package main

import (
	common "common"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// restart stops a server cleanly, closes its store, and starts a new one on the
// same database.
func restart(t *testing.T, srv *Server, dir string) (*Server, string) {
	t.Helper()
	srv.Close()
	if err := srv.store.Close(); err != nil {
		t.Fatal(err)
	}
	return startServerAt(t, dir)
}

func queueRows(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM queue`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// waitGone waits until the server has noticed a user's connection close, so a
// test does not race it by sending while it still counts them as connected.
func waitGone(t *testing.T, srv *Server, id [16]byte) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.RLock()
		_, on := srv.clients[id]
		srv.mu.RUnlock()
		if !on {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the server still counts the user as connected")
}

// relogin signs u in again with its current keys: the same device.
func relogin(t *testing.T, addr string, u *user) {
	t.Helper()
	c, reply := authAttempt(t, addr, common.CtrlLogin, u.name, testPassword, testBundle(u.key), testSeed(u.key))
	ackOf(t, reply)
	u.conn = c
}

func TestConversationsAndGroupsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	srv, addr := startServerAt(t, dir)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	carol := newUser(t, addr, "carol", 3)
	dmID, _ := openDM(t, bob.conn, "alice")
	g := createGroup(t, carol, "book club", alice, bob)
	readChange(t, alice)
	readChange(t, bob)

	sc := g.change(carol, common.ActionPromote, alice)
	sendChange(t, carol, common.CtrlGroupChange, "", sc)
	g.advance(readChange(t, bob).Change)

	// alice moves and rekeys, so the stored log holds two sets of keys for her.
	moveTo(t, addr, alice, 5)
	sc = g.change(alice, common.ActionRekey, alice)
	sendChange(t, alice, common.CtrlGroupChange, "", sc)
	g.advance(readChange(t, bob).Change)
	for _, u := range []*user{alice, bob, carol} {
		acknowledge(t, srv, u)
	}

	srv, addr = restart(t, srv, dir)

	srv.mu.RLock()
	dm, okDM := srv.convs[dmID]
	group, okG := srv.convs[g.id]
	srv.mu.RUnlock()
	if !okDM || len(dm.Members) != 2 || !dm.HasMember(alice.id) || !dm.HasMember(bob.id) {
		t.Fatal("the direct chat did not survive the restart")
	}
	if !okG || group.Name != "book club" || len(group.Log) != 3 || group.Membership.Version != 3 {
		t.Fatalf("the group did not survive the restart: %+v", group)
	}
	if k, _ := group.Membership.Key(alice.id); k.IdentityKey != testBundle(5).IdentityKey || !group.Membership.IsAdmin(alice.id) {
		t.Fatal("after the restart the group does not hold alice's new keys and role")
	}

	// Work carries on where it stopped: a change on the stored head is accepted...
	for _, u := range []*user{alice, bob, carol} {
		relogin(t, addr, u)
	}
	sc = g.change(alice, common.ActionDemote, carol)
	sendChange(t, alice, common.CtrlGroupChange, "", sc)
	if got := readChange(t, bob); got.Change.Change.Version != 4 {
		t.Fatalf("the change after the restart landed at version %d", got.Change.Change.Version)
	}
	// ...and the direct chat still routes.
	sendText(t, bob.conn, dmID, "still here")
	if got := readUntil(t, alice.conn, common.MsgText, 3*time.Second); string(got.Body) != "still here" {
		t.Fatalf("alice read %q", got.Body)
	}
}

// A pairwise conversation made for a group is a direct chat, and stays one after
// the people in it leave the group and the server restarts.
func TestAPairwiseChatOutlivesTheGroupThatMadeIt(t *testing.T) {
	dir := t.TempDir()
	srv, addr := startServerAt(t, dir)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	g := createGroup(t, alice, "pair", bob)
	readChange(t, bob)
	sc := g.change(alice, common.ActionRemove, bob)
	sendChange(t, alice, common.CtrlGroupChange, "", sc)
	readChange(t, bob)

	srv, addr = restart(t, srv, dir)
	pair := common.HashIDs(alice.id, bob.id)
	srv.mu.RLock()
	_, ok := srv.convs[pair]
	srv.mu.RUnlock()
	if !ok {
		t.Fatal("the pairwise chat was lost with the group")
	}
}

func TestQueuedPacketsSurviveARestartAndArriveOnce(t *testing.T) {
	dir := t.TempDir()
	srv, addr := startServerAt(t, dir)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")
	bob.conn.Close()
	waitGone(t, srv, bob.id)

	for _, m := range []string{"one", "two", "three"} {
		sendText(t, alice.conn, convID, m)
	}
	time.Sleep(100 * time.Millisecond)
	if n := queueRows(t, srv.store); n != 3 {
		t.Fatalf("%d packets in the store, want 3", n)
	}

	srv, addr = restart(t, srv, dir)
	relogin(t, addr, bob)
	for _, want := range []string{"one", "two", "three"} {
		if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != want {
			t.Fatalf("bob read %q, want %q", got.Body, want)
		}
	}

	// Acknowledged means gone: nothing comes again after another restart.
	acknowledge(t, srv, bob)
	srv, addr = restart(t, srv, dir)
	// Alice, who never read hers, still has the three delivery receipts waiting.
	srv.mu.RLock()
	bobDevice := srv.users[bob.id].Device.ID
	srv.mu.RUnlock()
	var n int
	if err := srv.store.db.QueryRow(`SELECT COUNT(*) FROM queue WHERE device_id = ?`, bobDevice[:]).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d delivered packets are still stored for bob, %v", n, err)
	}
	relogin(t, addr, bob)
	expectNo(t, bob.conn, common.MsgText, 300*time.Millisecond)
}

// A clean shutdown puts what a connected client had not been sent into the
// store, so it arrives after the restart.
func TestShutdownKeepsWhatAConnectionHadNotSent(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "gomesh.db"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(store)
	if err != nil {
		t.Fatal(err)
	}
	u, dev := testUser(srv, "bob")
	if err := store.CreateUser(userRecord{ID: u.ID, Username: "bob", PasswordHash: "x", Bundle: *testBundle(2), DeviceID: dev.ID, DeviceName: "mac"}, newToken(), time.Now()); err != nil {
		t.Fatal(err)
	}

	// A connection nobody reads: the first write blocks, the rest wait in its channel.
	near, far := net.Pipe()
	defer far.Close()
	c := &Client{Conn: near, UserID: u.ID, DeviceID: dev.ID, Username: "bob",
		send: make(chan common.Packet, sendBufferSize), done: make(chan struct{})}
	if !srv.addConnection(near, c) {
		t.Fatal("not admitted")
	}
	go srv.writeLoop(c)
	go func() { srv.readLoop(c); srv.loops.Done() }()
	for _, m := range []string{"one", "two", "three", "four"} {
		c.enqueue(textPacket(m))
	}
	time.Sleep(50 * time.Millisecond)

	srv.Close()
	q, err := store.LoadQueue(dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, item := range q {
		got = append(got, string(item.pkt.Body))
	}
	if len(got) != 4 || got[0] != "one" || got[3] != "four" {
		t.Fatalf("stored after shutdown: %q", got)
	}
	store.Close()
}

// Packets that were taken for a connection that then failed go back with the
// rows they already have, never as new ones.
func TestPuttingPacketsBackAddsNoRows(t *testing.T) {
	srv := newTestServer(t)
	u, dev := testUser(srv, "bob")
	for _, m := range []string{"one", "two", "three"} {
		srv.queueForUser(u.ID, textPacket(m))
	}
	if n := queueRows(t, srv.store); n != 3 {
		t.Fatalf("setup: %d rows", n)
	}
	broken := &Client{Conn: closedConn(), UserID: u.ID, DeviceID: dev.ID,
		send: make(chan common.Packet, 1), done: make(chan struct{})}
	if srv.drainQueue(broken) {
		t.Fatal("a drain over a dead connection reported success")
	}
	srv.mu.RLock()
	inMemory := len(dev.Queue)
	srv.mu.RUnlock()
	if n := queueRows(t, srv.store); n != 3 || inMemory != 3 {
		t.Fatalf("after a failed drain: %d rows, %d in memory; want 3 and 3", n, inMemory)
	}

	near, far := net.Pipe()
	defer far.Close()
	ok := &Client{Conn: near, UserID: u.ID, DeviceID: dev.ID,
		send: make(chan common.Packet, 1), done: make(chan struct{})}
	got := make(chan string, 3)
	go func() {
		for i := 0; i < 3; i++ {
			p, err := common.Decode(far)
			if err != nil {
				return
			}
			got <- string(p.Body)
		}
	}()
	if !srv.drainQueue(ok) {
		t.Fatal("the second drain failed")
	}
	for _, want := range []string{"one", "two", "three"} {
		if g := <-got; g != want {
			t.Fatalf("read %q, want %q", g, want)
		}
	}
	if n := queueRows(t, srv.store); n != 3 {
		t.Fatalf("%d rows before the acknowledgement, want 3", n)
	}
	srv.acknowledge(ok, common.DeliveredPacket(3).Body)
	if n := queueRows(t, srv.store); n != 0 {
		t.Fatalf("%d rows left after delivery", n)
	}
}

func TestDequeueDeletesOnlyTheNamedRows(t *testing.T) {
	st, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	dev := genID()
	var seqs []int64
	for i := 0; i < 3; i++ {
		seq, err := st.Enqueue(dev, encodePacket(textPacket("x")))
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, seq)
	}
	if err := st.Dequeue([]int64{seqs[2]}); err != nil {
		t.Fatal(err)
	}
	q, _ := st.LoadQueue(dev)
	if len(q) != 2 || q[0].seq != seqs[0] || q[1].seq != seqs[1] {
		t.Fatalf("left %+v", q)
	}
}

func TestTheQueueIsBoundedInBytes(t *testing.T) {
	savedN, savedB := maxOfflineQueue, maxQueueBytes
	defer func() { maxOfflineQueue, maxQueueBytes = savedN, savedB }()
	maxQueueBytes = 3 * (common.HeaderSize + 1000)

	srv := newTestServer(t)
	u, dev := testUser(srv, "bob")
	body := make([]byte, 1000)
	for i := byte(0); i < 5; i++ {
		body[0] = i
		srv.queueForUser(u.ID, textPacket(string(body)))
	}
	srv.mu.RLock()
	n, size, first := len(dev.Queue), dev.QueueBytes, dev.Queue[0].pkt.Body[0]
	srv.mu.RUnlock()
	if n != 3 || size > maxQueueBytes || first != 2 {
		t.Fatalf("queue holds %d packets, %d bytes, oldest #%d; want the newest 3", n, size, first)
	}
	if rows := queueRows(t, srv.store); rows != 3 {
		t.Fatalf("%d rows stored, want 3", rows)
	}
}

// What was queued for a device the account has left is never delivered, not
// even after a restart.
func TestAMoveThenARestartDeliversNothingOld(t *testing.T) {
	dir := t.TempDir()
	srv, addr := startServerAt(t, dir)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, bob.conn, "alice")
	alice.conn.Close()
	waitGone(t, srv, alice.id)
	sendText(t, bob.conn, convID, "for the old device")
	time.Sleep(100 * time.Millisecond)

	moveTo(t, addr, alice, 5)
	alice.conn.Close()
	readUntil(t, bob.conn, common.CtrlKeyChange, 3*time.Second)
	acknowledge(t, srv, bob)
	srv, addr = restart(t, srv, dir)
	if n := queueRows(t, srv.store); n != 0 {
		t.Fatalf("%d packets for the old device survived the move", n)
	}
	relogin(t, addr, alice)
	expectNo(t, alice.conn, common.MsgText, 300*time.Millisecond)
}

// A shutdown that arrives while the server is still starting must not leave it
// listening forever.
func TestCloseBeforeStartStopsTheServer(t *testing.T) {
	srv := newTestServer(t)
	srv.tls, _ = serverTLS(t)
	srv.Close()
	done := make(chan error, 1)
	go func() { done <- srv.Start("127.0.0.1:0") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start kept serving after Close")
	}
}
