package main

import (
	common "common"
	"testing"
	"time"
)

// moveTo signs u in on a new device with keys newKey: the right password, new
// keys. u is updated to the new device's connection and keys.
func moveTo(t *testing.T, addr string, u *user, newKey byte) {
	t.Helper()
	c, reply := authAttempt(t, addr, common.CtrlLogin, u.name, testPassword, testBundle(newKey), testSeed(newKey))
	ackOf(t, reply)
	u.conn, u.key = c, newKey
}

func readKeyChange(t *testing.T, u *user) common.UserLookup {
	t.Helper()
	p := readUntil(t, u.conn, common.CtrlKeyChange, 3*time.Second)
	kc, err := common.DecodeUserLookup(p.Body)
	if err != nil {
		t.Fatal(err)
	}
	return kc
}

func TestKeyChangeReachesEveryContactAndNobodyElse(t *testing.T) {
	_, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	carol := newUser(t, addr, "carol", 3)
	dave := newUser(t, addr, "dave", 4)
	openDM(t, bob.conn, "alice")
	createGroup(t, carol, "book club", alice)

	moveTo(t, addr, alice, 5)

	for _, u := range []*user{bob, carol} {
		kc := readKeyChange(t, u)
		if kc.ID != alice.id || kc.Name != "alice" || kc.Bundle != *testBundle(5) {
			t.Fatalf("%s was told %+v, want alice's new bundle", u.name, kc)
		}
	}
	expectNo(t, dave.conn, common.CtrlKeyChange, 300*time.Millisecond)
	expectNo(t, alice.conn, common.CtrlKeyChange, 300*time.Millisecond)
}

func TestSignInWithTheSameKeysIsNotAKeyChange(t *testing.T) {
	_, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	openDM(t, bob.conn, "alice")
	alice.conn.Close()

	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(1))
	ackOf(t, reply)
	expectNo(t, bob.conn, common.CtrlKeyChange, 300*time.Millisecond)
}

func TestMyGroupsIsSentAtLogin(t *testing.T) {
	_, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	g := createGroup(t, bob, "book club", alice)

	c, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(1))
	ackOf(t, reply)
	p := readUntil(t, c, common.CtrlMyGroups, 3*time.Second)
	groups, err := common.DecodeMyGroups(p.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].ID != g.id || groups[0].Name != "book club" {
		t.Fatalf("MyGroups = %+v", groups)
	}
}

func TestTheMoverRekeysAndStaysAdmin(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	g := createGroup(t, alice, "book club", bob)
	readChange(t, bob)

	moveTo(t, addr, alice, 5)
	readKeyChange(t, bob)

	sc := g.change(alice, common.ActionRekey, alice)
	sendChange(t, alice, common.CtrlGroupChange, "", sc)
	body := readChange(t, bob)
	if body.Change.Change.Action != common.ActionRekey {
		t.Fatalf("bob was sent a %v", body.Change.Change.Action)
	}
	if len(body.Hints) != 1 || body.Hints[0].ID != alice.id || body.Hints[0].Bundle != *testBundle(5) {
		t.Fatalf("the rekey came without alice's new bundle: %+v", body.Hints)
	}
	g.advance(body.Change)

	srv.mu.RLock()
	conv := srv.convs[g.id]
	k, _ := conv.Membership.Key(alice.id)
	admin := conv.Membership.IsAdmin(alice.id)
	srv.mu.RUnlock()
	if k.IdentityKey != testBundle(5).IdentityKey || !admin {
		t.Fatal("after the rekey alice does not hold her new keys as an admin")
	}

	// And she manages the group with the new key.
	sc = g.change(alice, common.ActionPromote, bob)
	sendChange(t, alice, common.CtrlGroupChange, "", sc)
	if got := readChange(t, bob); got.Change.Change.Action != common.ActionPromote {
		t.Fatal("alice could not manage the group after moving")
	}
}

func TestARekeyMustMatchTheDirectory(t *testing.T) {
	_, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	g := createGroup(t, alice, "book club", bob)
	readChange(t, bob)

	// Keys alice never registered: signed correctly, but the directory disagrees.
	alice.key = 7
	sc := g.change(alice, common.ActionRekey, alice)
	sendChange(t, alice, common.CtrlGroupChange, "", sc)
	readReject(t, alice)

	// Nor can bob rekey alice, even to the keys the directory now holds.
	moveTo(t, addr, alice, 5)
	sc = g.change(bob, common.ActionRekey, alice)
	sendChange(t, bob, common.CtrlGroupChange, "", sc)
	readReject(t, bob)
}

func TestSessionResetIsRelayedOnlyOneToOne(t *testing.T) {
	_, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, bob.conn, "alice")
	g := createGroup(t, bob, "book club", alice)
	readChange(t, alice)

	reset := func(conv [16]byte) {
		(&common.Packet{Header: common.Header{MsgType: common.CtrlSessionReset, ConversationID: conv}}).Encode(bob.conn)
	}
	reset(convID)
	p := readUntil(t, alice.conn, common.CtrlSessionReset, 3*time.Second)
	if p.Header.SenderID != bob.id || p.Header.ConversationID != convID {
		t.Fatal("the reset did not arrive stamped with its sender")
	}

	reset(g.id)
	expectNo(t, alice.conn, common.CtrlSessionReset, 300*time.Millisecond)
}
