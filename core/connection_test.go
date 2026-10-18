package core

import (
	common "common"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder collects a real Client's events.
type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) add(ev Event) { r.mu.Lock(); r.events = append(r.events, ev); r.mu.Unlock() }

// waitFor waits for an event matching ok that arrived after the first `after`
// events, and returns how many events there were then.
func (r *recorder) waitFor(t *testing.T, what string, after int, ok func(Event) bool) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for i := after; i < len(r.events); i++ {
			if ok(r.events[i]) {
				n := len(r.events)
				r.mu.Unlock()
				return n
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("never saw %s", what)
	return 0
}

func (r *recorder) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.events) }

func isState(s ConnState) func(Event) bool {
	return func(ev Event) bool { return ev.Kind == EventConnection && ev.State == s }
}

// signedInClient makes a real Client in its own data directory and registers it.
func signedInClient(t *testing.T, addr, name string) (*Client, *recorder) {
	t.Helper()
	serverPinsMu.Lock()
	pin := serverPins[addr]
	serverPinsMu.Unlock()
	rec := &recorder{}
	cl, err := New(Config{DataDir: t.TempDir(), OnEvent: rec.add})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cl.Close)
	if err := cl.CheckServer(addr, func(fp string) bool { return fp == pin }); err != nil {
		t.Fatal(err)
	}
	if err := cl.Register(addr, name, testPassword); err != nil {
		t.Fatal(err)
	}
	return cl, rec
}

func fastReconnect(t *testing.T, d time.Duration) {
	saved := reconnectMin
	reconnectMin = d
	t.Cleanup(func() { reconnectMin = saved })
}

func keptText(cl *Client, conv [16]byte, text string) func() bool {
	return func() bool {
		msgs, _ := cl.HistoryMessages(cl.UserID(), conv, 0, 100)
		for _, m := range msgs {
			if m.Text == text {
				return true
			}
		}
		return false
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

func TestReconnectsAfterTheServerRestarts(t *testing.T) {
	fastReconnect(t, 100*time.Millisecond)
	srv := startServerProc(t)
	cl, rec := signedInClient(t, srv.addr, "alice")
	bob := dialParty(t, srv.addr, "bob")

	dm := bob.openDM("alice")
	bob.sendDM(dm, "before the restart")
	eventually(t, "the first message kept", keptText(cl, dm, "before the restart"))
	gid := genID()
	sc := common.SignChange(bob.sm.identity.SigningSeed, common.GroupChange{
		GroupID: gid, Version: 1, Action: common.ActionCreate, Actor: bob.id, Timestamp: time.Now().Unix(),
		Targets: []common.MemberKey{keyOf(bob), {ID: cl.UserID(), IdentityKey: cl.idMgr.PublicKey, SigningKey: cl.idMgr.SigningKey}},
	})
	body := (&common.GroupChangeBody{Name: "team", Change: sc}).Encode()
	bob.send(&common.Packet{Header: common.Header{MsgType: common.CtrlGroupCreate, BodyLen: uint32(len(body))}, Body: body})
	bob.follow(5 * time.Second)
	eventually(t, "the group", func() bool { return cl.IsGroup(gid) })

	n := rec.count()
	srv.stop()
	n = rec.waitFor(t, "the client noticing", n, isState(StateConnecting))

	// Offline, a send is refused before anything is encrypted.
	before, _ := cl.sessionMgr.GetSession(dm)
	before.mu.Lock()
	sent := before.st.Send.N
	before.mu.Unlock()
	if err := cl.SendText(dm, "while the server is down"); !errors.Is(err, ErrOffline) {
		t.Fatalf("a send while offline: %v", err)
	}
	after, _ := cl.sessionMgr.GetSession(dm)
	after.mu.Lock()
	if after.st.Send.N != sent {
		t.Fatal("a refused send advanced the ratchet")
	}
	after.mu.Unlock()

	srv.start()
	rec.waitFor(t, "the client coming back", n, isState(StateOnline))

	bob = reloginParty(t, srv.addr, bob)
	bob.sendDM(dm, "after the restart")
	eventually(t, "a message after the restart", keptText(cl, dm, "after the restart"))
	if err := cl.SendText(dm, "and a reply"); err != nil {
		t.Fatal(err)
	}
	if got := bob.readDM(5 * time.Second); got != "and a reply" {
		t.Fatalf("bob read %q", got)
	}
	bob.sendGroupText(gid, "the group after the restart")
	eventually(t, "a group message after the restart", keptText(cl, gid, "the group after the restart"))
}

// A device whose account moved while it was offline learns so when it
// reconnects, and signs out.
func TestReconnectingToAMovedAccountSignsOut(t *testing.T) {
	fastReconnect(t, 2*time.Second)
	srv := startServerProc(t)
	cl, rec := signedInClient(t, srv.addr, "alice")

	n := rec.count()
	srv.stop()
	n = rec.waitFor(t, "the client noticing", n, isState(StateConnecting))
	srv.start()
	loginParty(t, srv.addr, "alice") // the account moves before the client is back

	rec.waitFor(t, "the sign-out", n, func(ev Event) bool { return ev.Kind == EventSignedOut })
	if _, err := cl.secrets().Get(vaultAccountKey); !errors.Is(err, ErrNotInVault) {
		t.Fatal("the replaced device kept its keys")
	}
}

func TestNoReconnectAfterClose(t *testing.T) {
	fastReconnect(t, 100*time.Millisecond)
	srv := startServerProc(t)
	cl, rec := signedInClient(t, srv.addr, "alice")

	srv.stop()
	rec.waitFor(t, "the client noticing", 0, isState(StateConnecting))
	cl.Close()
	n := rec.count()
	srv.start()
	time.Sleep(time.Second)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, ev := range rec.events[n:] {
		if ev.Kind == EventConnection && ev.State == StateOnline {
			t.Fatal("a closed client reconnected")
		}
	}
}

// A device whose server is down at launch still starts: its chats are there,
// sends are refused, and it comes online by itself once the server is back.
func TestResumeWithTheServerDownStartsOffline(t *testing.T) {
	fastReconnect(t, 100*time.Millisecond)
	srv := startServerProc(t)
	cl, _ := signedInClient(t, srv.addr, "alice")
	bob := dialParty(t, srv.addr, "bob")
	dm := bob.openDM("alice")
	bob.sendDM(dm, "kept for later")
	eventually(t, "the message kept", keptText(cl, dm, "kept for later"))
	dir := cl.dataDir
	cl.Close()
	srv.stop()

	rec := &recorder{}
	again, err := New(Config{DataDir: dir, OnEvent: rec.add})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(again.Close)
	if err := again.Resume(); err != nil {
		t.Fatalf("resuming with the server down: %v", err)
	}
	rec.waitFor(t, "the connecting state", 0, isState(StateConnecting))
	if again.UserID() != cl.UserID() {
		t.Fatal("started as another account")
	}
	if !keptText(again, dm, "kept for later")() {
		t.Fatal("the history is not readable offline")
	}
	if len(again.Conversations()) != 1 {
		t.Fatalf("conversations offline: %+v", again.Conversations())
	}
	if err := again.SendText(dm, "too early"); !errors.Is(err, ErrOffline) {
		t.Fatalf("a send while offline: %v", err)
	}

	n := rec.count()
	srv.start()
	rec.waitFor(t, "coming online", n, isState(StateOnline))
	bob = reloginParty(t, srv.addr, bob)
	if err := again.SendText(dm, "back again"); err != nil {
		t.Fatal(err)
	}
	if got := bob.readDM(5 * time.Second); got != "back again" {
		t.Fatalf("bob read %q", got)
	}
}

// A device in a group whose server is down at launch starts too. It used to
// crash asking for the group's log over a connection it did not have yet; the
// ask waits for the login instead, and the group works once the server is back.
func TestResumeInAGroupWithTheServerDownStartsOffline(t *testing.T) {
	fastReconnect(t, 100*time.Millisecond)
	srv := startServerProc(t)
	cl, _ := signedInClient(t, srv.addr, "alice")
	bob, _ := signedInClient(t, srv.addr, "bob")
	gid, err := cl.CreateGroup("pair", []string{"bob"})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob in the group", func() bool { return bob.IsGroup(gid) })
	if err := bob.SendText(gid, "before"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the group message kept", keptText(cl, gid, "before"))
	dir := cl.dataDir
	cl.Close()
	srv.stop()

	rec := &recorder{}
	again, err := New(Config{DataDir: dir, OnEvent: rec.add})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(again.Close)
	if err := again.Resume(); err != nil {
		t.Fatalf("resuming with the server down: %v", err)
	}
	rec.waitFor(t, "the connecting state", 0, isState(StateConnecting))
	if !again.IsGroup(gid) || !keptText(again, gid, "before")() {
		t.Fatal("the group is not there offline")
	}

	n := rec.count()
	srv.start()
	rec.waitFor(t, "coming online", n, isState(StateOnline))
	eventually(t, "bob back online", func() bool { return bob.SendText(gid, "after") == nil })
	eventually(t, "the group message after the outage", keptText(again, gid, "after"))
}

// Nothing is pinned until the host says so, and then exactly the fingerprint
// it showed.
func TestServerTrustIsPinnedOnlyWhenConfirmed(t *testing.T) {
	srv := startServerProc(t)
	serverPinsMu.Lock()
	want := serverPins[srv.addr]
	serverPinsMu.Unlock()
	cl, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	fp, pinned, err := cl.ServerFingerprint(srv.addr)
	if err != nil || pinned || fp != want {
		t.Fatalf("first look: %q %v %v", fp, pinned, err)
	}
	if err := cl.Register(srv.addr, "alice", testPassword); !errors.Is(err, ErrUntrustedServer) {
		t.Fatalf("registering with an unpinned server: %v", err)
	}
	other := strings.Repeat("ab", 32)
	if err := cl.TrustServer(srv.addr, other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cl.ServerFingerprint(srv.addr); !errors.Is(err, common.ErrPinMismatch) {
		t.Fatalf("a server not matching its pin: %v", err)
	}
	if err := cl.Register(srv.addr, "alice", testPassword); !errors.Is(err, common.ErrPinMismatch) {
		t.Fatalf("registering with a server not matching its pin: %v", err)
	}
	if err := cl.TrustServer(srv.addr, want); !errors.Is(err, common.ErrPinMismatch) {
		t.Fatalf("a pin was replaced without forgetting it first: %v", err)
	}
	if err := cl.ForgetServer(srv.addr); err != nil {
		t.Fatal(err)
	}
	if err := cl.TrustServer(srv.addr, common.FormatFingerprint(want)); err != nil {
		t.Fatal(err)
	}
	if fp, pinned, err := cl.ServerFingerprint(srv.addr); err != nil || !pinned || fp != want {
		t.Fatalf("after trusting: %q %v %v", fp, pinned, err)
	}
	if err := cl.Register(srv.addr, "alice", testPassword); err != nil {
		t.Fatal(err)
	}
}

// Coming to the foreground does not wait out the backoff.
func TestReconnectNowSkipsTheBackoff(t *testing.T) {
	fastReconnect(t, time.Minute)
	srv := startServerProc(t)
	cl, rec := signedInClient(t, srv.addr, "alice")
	n := rec.count()
	srv.stop()
	n = rec.waitFor(t, "the client noticing", n, isState(StateConnecting))
	srv.start()
	cl.ReconnectNow()
	rec.waitFor(t, "coming back without waiting a minute", n, isState(StateOnline))
}

// Close returns promptly even while a reconnect is dialing, and no loop
// outlives it.
func TestCloseEndsTheLoops(t *testing.T) {
	fastReconnect(t, 50*time.Millisecond)
	srv := startServerProc(t)
	cl, rec := signedInClient(t, srv.addr, "alice")
	srv.stop()
	rec.waitFor(t, "the client noticing", 0, isState(StateConnecting))
	time.Sleep(200 * time.Millisecond) // a few attempts in
	start := time.Now()
	cl.Close()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %v", d)
	}
	done := make(chan struct{})
	go func() { cl.loops.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a loop outlived Close")
	}
}
