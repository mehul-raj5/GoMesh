package main

import (
	common "common"
	"net"
	"testing"
	"time"
)

// user is a logged-in test account. Its signing seed is testSeed(key), so a test
// can sign changes as it.
type user struct {
	name string
	key  byte
	id   [16]byte
	conn net.Conn
}

func newUser(t *testing.T, addr, name string, key byte) *user {
	t.Helper()
	c, id := login(t, addr, name, key)
	t.Cleanup(func() { c.Close() })
	return &user{name: name, key: key, id: id, conn: c}
}

func (u *user) memberKey() common.MemberKey {
	b := testBundle(u.key)
	return common.MemberKey{ID: u.id, IdentityKey: b.IdentityKey, SigningKey: b.SigningKey}
}

// groupLog tracks the head of a group so tests can build the next change.
type groupLog struct {
	id      [16]byte
	version uint32
	head    [32]byte
}

func (g *groupLog) change(actor *user, action common.GroupAction, targets ...*user) common.SignedChange {
	ch := common.GroupChange{
		GroupID: g.id, Version: g.version + 1, PrevHash: g.head, Action: action,
		Actor: actor.id, Timestamp: time.Now().Unix(),
	}
	for _, t := range targets {
		ch.Targets = append(ch.Targets, t.memberKey())
	}
	return common.SignChange(testSeed(actor.key), ch)
}

func (g *groupLog) advance(sc common.SignedChange) {
	g.version = sc.Change.Version
	g.head = sc.Hash()
}

func sendChange(t *testing.T, u *user, msgType uint8, name string, sc common.SignedChange) {
	t.Helper()
	body := (&common.GroupChangeBody{Name: name, Change: sc}).Encode()
	pkt := common.Packet{Header: common.Header{MsgType: msgType, BodyLen: uint32(len(body))}, Body: body}
	if err := pkt.Encode(u.conn); err != nil {
		t.Fatalf("send %#x: %v", msgType, err)
	}
}

// createGroup has creator create a group of creator plus others and waits for
// the creator to hear the accepted change back.
func createGroup(t *testing.T, creator *user, name string, others ...*user) *groupLog {
	t.Helper()
	g := &groupLog{id: [16]byte{0xC0, others[0].id[0], others[len(others)-1].id[1]}}
	copy(g.id[3:], creator.id[:])
	sc := g.change(creator, common.ActionCreate, append([]*user{creator}, others...)...)
	sendChange(t, creator, common.CtrlGroupCreate, name, sc)
	p := readUntil(t, creator.conn, common.CtrlGroupChange, 3*time.Second)
	body, err := common.DecodeGroupChangeBody(p.Body)
	if err != nil {
		t.Fatalf("decode create broadcast: %v", err)
	}
	g.advance(body.Change)
	return g
}

func members(srv *Server, groupID [16]byte) map[[16]byte]bool {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	out := map[[16]byte]bool{}
	if conv, ok := srv.convs[groupID]; ok {
		for _, m := range conv.Members {
			out[m] = true
		}
	}
	return out
}

func readChange(t *testing.T, u *user) common.GroupChangeBody {
	t.Helper()
	p := readUntil(t, u.conn, common.CtrlGroupChange, 3*time.Second)
	body, err := common.DecodeGroupChangeBody(p.Body)
	if err != nil {
		t.Fatalf("decode change: %v", err)
	}
	return body
}

func readReject(t *testing.T, u *user) common.GroupChangeReject {
	t.Helper()
	p := readUntil(t, u.conn, common.CtrlGroupChangeReject, 3*time.Second)
	rej, err := common.DecodeGroupChangeReject(p.Body)
	if err != nil {
		t.Fatalf("decode reject: %v", err)
	}
	return rej
}

func TestCreateBroadcastsTheSignedChangeToEveryMember(t *testing.T) {
	srv, addr := startServer(t)
	alice, bob, carol := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3)

	g := createGroup(t, alice, "team", bob, carol)

	for _, u := range []*user{bob, carol} {
		body := readChange(t, u)
		if body.Name != "team" || body.Change.Change.Action != common.ActionCreate {
			t.Fatalf("%s got %+v", u.name, body)
		}
		if !body.Change.Verify(testBundle(1).SigningKey) {
			t.Fatalf("%s was sent a change that does not verify", u.name)
		}
		if len(body.Hints) != 3 {
			t.Fatalf("%s got %d hints, want 3", u.name, len(body.Hints))
		}
	}
	if got := members(srv, g.id); len(got) != 3 {
		t.Fatalf("server holds %d members", len(got))
	}
}

func TestChangesAreRefusedFromNonAdminsAndForgedActors(t *testing.T) {
	srv, addr := startServer(t)
	alice, bob, carol, dave := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3), newUser(t, addr, "dave", 4)
	g := createGroup(t, alice, "g", bob, carol)

	// A member who is not an admin cannot add.
	sendChange(t, bob, common.CtrlGroupChange, "", g.change(bob, common.ActionAdd, dave))
	readReject(t, bob)

	// Nor remove.
	sendChange(t, bob, common.CtrlGroupChange, "", g.change(bob, common.ActionRemove, carol))
	readReject(t, bob)

	// Bob cannot pass off a change as alice's: the server stamps who sent it, and
	// the actor must be that user.
	sendChange(t, bob, common.CtrlGroupChange, "", g.change(alice, common.ActionAdd, dave))
	readReject(t, bob)

	// A change signed with a key that is not the actor's fails, however well formed.
	forged := g.change(alice, common.ActionAdd, dave)
	forged = common.SignChange(testSeed(2), forged.Change) // bob's key, alice named as actor
	sendChange(t, alice, common.CtrlGroupChange, "", forged)
	readReject(t, alice)

	if got := members(srv, g.id); len(got) != 3 || got[dave.id] {
		t.Fatalf("a refused change altered the membership: %v", got)
	}
}

func TestOneOfTwoConcurrentChangesIsRefusedAndCanBeResubmitted(t *testing.T) {
	srv, addr := startServer(t)
	alice, bob, carol := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3)
	dave, erin := newUser(t, addr, "dave", 4), newUser(t, addr, "erin", 5)
	g := createGroup(t, alice, "g", bob, carol)

	// Make bob an admin so two admins can race.
	promote := g.change(alice, common.ActionPromote, bob)
	sendChange(t, alice, common.CtrlGroupChange, "", promote)
	readChange(t, alice)
	g.advance(promote)

	// Both build version 3 on the same head.
	addDave := g.change(alice, common.ActionAdd, dave)
	addErin := g.change(bob, common.ActionAdd, erin)
	sendChange(t, alice, common.CtrlGroupChange, "", addDave)
	// Wait for alice's to be applied so the order is deterministic.
	readChange(t, alice)
	sendChange(t, bob, common.CtrlGroupChange, "", addErin)

	rej := readReject(t, bob)
	if rej.ChangeHash != addErin.Hash() || rej.HeadVersion != 3 {
		t.Fatalf("reject names %x at head %d, want the second change at head 3", rej.ChangeHash[:4], rej.HeadVersion)
	}
	if got := members(srv, g.id); !got[dave.id] || got[erin.id] {
		t.Fatalf("expected exactly one of the two to land: %v", got)
	}

	// Rebuilt on top of the new head, it is accepted.
	g.advance(addDave)
	retry := g.change(bob, common.ActionAdd, erin)
	sendChange(t, bob, common.CtrlGroupChange, "", retry)
	for readChange(t, bob).Change.Change.Version < 4 {
	}
	if got := members(srv, g.id); !got[erin.id] {
		t.Fatal("the resubmitted change was not applied")
	}
}

func TestRemovedMemberHearsOfItAndStopsReceiving(t *testing.T) {
	srv, addr := startServer(t)
	alice, bob, carol := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3)
	g := createGroup(t, alice, "g", bob, carol)
	readChange(t, bob)
	readChange(t, carol)

	remove := g.change(alice, common.ActionRemove, carol)
	sendChange(t, alice, common.CtrlGroupChange, "", remove)

	// Carol is told, so she can drop the group.
	if got := readChange(t, carol); got.Change.Change.Action != common.ActionRemove {
		t.Fatalf("carol was told %v", got.Change.Change.Action)
	}
	readChange(t, bob)
	if members(srv, g.id)[carol.id] {
		t.Fatal("carol is still a member server-side")
	}

	// Group traffic now reaches bob and not carol.
	data := common.Packet{
		Header: common.Header{MsgType: common.MsgText, ConversationID: g.id, BodyLen: 3},
		Body:   []byte("hey"),
	}
	if err := data.Encode(alice.conn); err != nil {
		t.Fatal(err)
	}
	readUntil(t, bob.conn, common.MsgText, 3*time.Second)
	expectSilence(t, carol.conn, 500*time.Millisecond)

	// And she cannot read the log or send into the group.
	req := common.Packet{Header: common.Header{MsgType: common.CtrlGroupLogRq}, Body: (&common.GroupLogRequest{GroupID: g.id}).Encode()}
	req.Header.BodyLen = uint32(len(req.Body))
	req.Encode(carol.conn)
	expectSilence(t, carol.conn, 500*time.Millisecond)
}

func TestTheLastAdminMustPromoteBeforeLeaving(t *testing.T) {
	srv, addr := startServer(t)
	alice, bob, carol := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3)
	g := createGroup(t, alice, "g", bob, carol)

	// The bare leave is refused.
	sendChange(t, alice, common.CtrlGroupChange, "", g.change(alice, common.ActionLeave, alice))
	readReject(t, alice)
	if !members(srv, g.id)[alice.id] {
		t.Fatal("the sole admin left without promoting a successor")
	}

	// Promote bob, then the leave goes through.
	promote := g.change(alice, common.ActionPromote, bob)
	sendChange(t, alice, common.CtrlGroupChange, "", promote)
	readChange(t, alice)
	g.advance(promote)

	sendChange(t, alice, common.CtrlGroupChange, "", g.change(alice, common.ActionLeave, alice))
	readChange(t, alice)
	if got := members(srv, g.id); got[alice.id] || len(got) != 2 {
		t.Fatalf("unexpected members after the leave: %v", got)
	}
}

func TestLogRequestReturnsTheChangesAfterAVersion(t *testing.T) {
	_, addr := startServer(t)
	alice, bob, carol := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3)
	g := createGroup(t, alice, "g", bob)

	add := g.change(alice, common.ActionAdd, carol)
	sendChange(t, alice, common.CtrlGroupChange, "", add)
	readChange(t, alice)

	// Carol joined at version 2 and asks for everything.
	req := common.Packet{Header: common.Header{MsgType: common.CtrlGroupLogRq}, Body: (&common.GroupLogRequest{GroupID: g.id}).Encode()}
	req.Header.BodyLen = uint32(len(req.Body))
	if err := req.Encode(carol.conn); err != nil {
		t.Fatal(err)
	}
	first := readChange(t, carol) // the add she was sent when it happened, or the replayed create
	_ = first
	var versions []uint32
	deadline := time.Now().Add(3 * time.Second)
	for len(versions) < 3 && time.Now().Before(deadline) {
		carol.conn.SetReadDeadline(deadline)
		p, err := decode(carol.conn)
		if err != nil {
			t.Fatal(err)
		}
		if p.Header.MsgType == common.CtrlGroupChange {
			b, _ := common.DecodeGroupChangeBody(p.Body)
			versions = append(versions, b.Change.Change.Version)
		}
		if p.Header.MsgType == common.CtrlGroupHints {
			id, hints, err := common.DecodeGroupHints(p.Body)
			if err != nil || id != g.id || len(hints) != 3 {
				t.Fatalf("hints: %v %d", err, len(hints))
			}
			break
		}
	}
	seen := map[uint32]bool{}
	for _, v := range versions {
		seen[v] = true
	}
	if !seen[1] || !seen[2] {
		t.Fatalf("log reply covered versions %v, want 1 and 2", versions)
	}

	// Asking from version 1 returns only the add.
	req.Body = (&common.GroupLogRequest{GroupID: g.id, FromVersion: 1}).Encode()
	if err := req.Encode(bob.conn); err != nil {
		t.Fatal(err)
	}
	for {
		p := readUntil(t, bob.conn, common.CtrlGroupChange, 3*time.Second)
		b, _ := common.DecodeGroupChangeBody(p.Body)
		if b.Change.Change.Version == 1 {
			continue // the create bob was sent when the group was made
		}
		if b.Change.Change.Version != 2 {
			t.Fatalf("got version %d", b.Change.Change.Version)
		}
		break
	}
}

func TestUserLookupReturnsAVerifiableBundle(t *testing.T) {
	_, addr := startServer(t)
	alice, bob := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2)

	req := common.Packet{Header: common.Header{MsgType: common.CtrlUserLookupRq, BodyLen: 3}, Body: []byte("bob")}
	if err := req.Encode(alice.conn); err != nil {
		t.Fatal(err)
	}
	ack := readUntil(t, alice.conn, common.CtrlUserLookupAck, 3*time.Second)
	got, err := common.DecodeUserLookup(ack.Body)
	if err != nil || got.ID != bob.id || got.Name != "bob" || !got.Bundle.Verify() {
		t.Fatalf("lookup: %+v %v", got, err)
	}

	req.Body, req.Header.BodyLen = []byte("nobody"), 6
	req.Encode(alice.conn)
	if ack := readUntil(t, alice.conn, common.CtrlUserLookupAck, 3*time.Second); len(ack.Body) != 0 {
		t.Fatal("an unknown name was answered")
	}
}

func TestAChangeCannotIntroduceKeysTheDirectoryDoesNotHold(t *testing.T) {
	srv, addr := startServer(t)
	alice, bob, dave := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "dave", 4)
	g := createGroup(t, alice, "g", bob)

	sc := g.change(alice, common.ActionAdd, dave)
	sc.Change.Targets[0].SigningKey = testBundle(9).SigningKey // not dave's
	sc = common.SignChange(testSeed(1), sc.Change)
	sendChange(t, alice, common.CtrlGroupChange, "", sc)
	readReject(t, alice)
	if members(srv, g.id)[dave.id] {
		t.Fatal("a member was added under keys that are not on file")
	}
}
