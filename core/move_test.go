package core

import (
	common "common"
	"errors"
	"slices"
	"testing"
)

// Moving an account to a new device, in the in-process group network. The
// network plays the server: it orders changes and fans messages out by user ID.
// The old device is kept and fed a copy of everything addressed to the account,
// as a stolen device working with a malicious server could be, to show it reads
// nothing sent after the move.

// move gives p's account a new device: same user ID, new keys, no state. The
// network delivers to the new device from here on; the old one is returned.
func (n *gnet) move(p peer) (newDev, oldDev peer) {
	n.t.Helper()
	fresh := newPeer(n.t, p.id[0])
	n.add(fresh)
	return fresh, p
}

// notice is what a member does with the server's key-change notice: replace
// the direct session with one on the new bundle, and note the directory's key.
func (n *gnet) notice(at, moved peer) [][16]byte {
	n.t.Helper()
	convID := common.HashIDs(at.id, moved.id)
	if _, ok := at.sm.GetSession(convID); ok {
		if _, err := at.sm.OpenDirectSession(convID, moved.id, "moved", moved.im.Bundle(), false); err != nil {
			n.t.Fatal(err)
		}
	}
	return at.sm.NoteDirectoryKey(moved.id, moved.im.PublicKey)
}

// rekey has the new device catch up on the log and sign itself in.
func (n *gnet) rekey(newDev peer) {
	n.t.Helper()
	n.catchUp(newDev)
	n.do(newDev, common.ActionRekey, newDev)
}

// oldReads feeds the old device a copy of a send, sender keys included, and
// returns what it could read.
func oldReads(t *testing.T, old peer, msg common.Packet, pre []common.Packet) []string {
	t.Helper()
	for _, sk := range pre {
		if sk.Header.ConversationID != common.HashIDs(sk.Header.SenderID, old.id) {
			continue
		}
		sk = clonePacket(sk)
		if err := old.sm.DecryptPacket(&sk); err == nil {
			old.sm.ReceiveSenderKey(&sk)
		}
	}
	m := clonePacket(msg)
	if err := old.sm.DecryptGroupPacket(&m); err != nil {
		return nil
	}
	return []string{string(m.Body)}
}

func sentTo(pre []common.Packet, from, to peer) bool {
	return slices.ContainsFunc(pre, func(p common.Packet) bool {
		return p.Header.ConversationID == common.HashIDs(from.id, to.id)
	})
}

// The whole move, with the group's only admin moving: the group keeps working
// throughout, the old device reads nothing sent after the notice, and the admin
// manages the group from the new device.
func TestMoveKeepsTheGroupWorking(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	for _, p := range []peer{a, b, c} {
		n.send(p, "hello from "+string(rune('a'+p.id[0]/0x11-1)))
	}
	for _, p := range []peer{a, b, c} {
		n.pump(p)
		noErrors(t, n, p)
	}

	a2, oldA := n.move(a)

	// b and c hear the server's notice. Each replaces its own key, which the old
	// device held, and leaves a out until a's rekey.
	for _, p := range []peer{b, c} {
		if got := n.notice(p, a2); len(got) != 1 || got[0] != n.gid {
			t.Fatalf("%x: notice affected %v", p.id[0], got)
		}
		if st := gstate(t, p, n.gid); !st.Own.MustRotate || !st.isMoving(a.id) {
			t.Fatalf("%x after the notice: rotate=%v moving=%v", p.id[0], st.Own.MustRotate, st.Moving)
		}
	}

	// Between the notice and the rekey the others keep talking, and nothing of it
	// reaches either of a's devices.
	msg, pre := n.send(b, "b during the move")
	if sentTo(pre, b, a) {
		t.Fatal("b gave its sender key to a while a was moving")
	}
	if got := oldReads(t, oldA, msg, pre); len(got) > 0 {
		t.Fatalf("the old device read %q", got)
	}
	expectMsgs(t, "c", n.pump(c), "b during the move")
	noErrors(t, n, c)

	// The new device cannot send until its rekey is in the log.
	n.catchUp(a2)
	pkt := common.Packet{Header: common.Header{MsgType: common.MsgText, ConversationID: n.gid, SenderID: a2.id}, Body: []byte("too early")}
	if _, err := a2.sm.EncryptGroupPacket(&pkt); !errors.Is(err, ErrAwaitingRekey) {
		t.Fatalf("sending before the rekey: %v", err)
	}

	n.do(a2, common.ActionRekey, a2)
	for _, p := range []peer{b, c} {
		st := gstate(t, p, n.gid)
		if st.isMoving(a.id) || st.peerKeys(a.id) != nil {
			t.Fatalf("%x still treats a as moving, or kept the old device's key", p.id[0])
		}
		if k, _ := st.Membership.Key(a.id); k.IdentityKey != a2.im.PublicKey || !st.Membership.IsAdmin(a.id) {
			t.Fatalf("%x: a is not an admin on the new keys", p.id[0])
		}
	}

	// Now a's new device talks to everyone, and everyone to it.
	msg, pre = n.send(a2, "a from the new device")
	if got := oldReads(t, oldA, msg, pre); len(got) > 0 {
		t.Fatalf("the old device read %q", got)
	}
	expectMsgs(t, "b", n.pump(b), "a from the new device")
	expectMsgs(t, "c", n.pump(c), "a from the new device")

	msg, pre = n.send(c, "c after the move")
	if !sentTo(pre, c, a2) {
		t.Fatal("c did not give the new device its key")
	}
	if got := oldReads(t, oldA, msg, pre); len(got) > 0 {
		t.Fatalf("the old device read %q", got)
	}
	expectMsgs(t, "a2", n.pump(a2), "c after the move")
	expectMsgs(t, "b", n.pump(b), "c after the move")

	// The only admin manages the group from the new device.
	n.do(a2, common.ActionPromote, b)
	for _, p := range []peer{a2, b, c} {
		noErrors(t, n, p)
	}
}

// A member who learns the new keys only from a roster, with no notice and no
// session, still leaves the mover out and keeps sending.
func TestARosterAloneMarksTheMemberAsMoving(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	n.send(b, "first")
	n.pump(a)
	n.pump(c)

	a2, _ := n.move(a)
	// The roster path: the old session was dropped as a mismatch, and the
	// directory's key was noted. No session is opened to anyone.
	b.sm.mu.Lock()
	delete(b.sm.sessions, common.HashIDs(b.id, a.id))
	b.sm.mu.Unlock()
	b.sm.NoteDirectoryKey(a.id, a2.im.PublicKey)

	msg, pre := n.send(b, "while a moves")
	if sentTo(pre, b, a) {
		t.Fatal("a session was opened to one of a's devices from a stale bundle")
	}
	if _, ok := b.sm.GetSession(common.HashIDs(b.id, a.id)); ok {
		t.Fatal("group code opened a session to the moving member")
	}
	_ = msg
	expectMsgs(t, "c", n.pump(c), "while a moves")
}

// A sender key that arrives over a session with keys the log does not name yet
// is held, not installed, and installed once the rekey lands.
func TestSenderKeyOverAnUnsettledSessionWaitsForTheRekey(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)
	a2, _ := n.move(a)
	n.notice(b, a2)

	d := common.SenderKeyDist{GroupID: n.gid, KeyID: 1, ChainKey: [32]byte{1}, SignPub: a2.im.SigningKey, MembershipVersion: 1}
	upd, err := openSKDM(t, b, skdmPacket(t, a2, b, d))
	if err != nil {
		t.Fatal(err)
	}
	if len(upd.Installed) != 0 || gstate(t, b, n.gid).peerKeys(a.id) != nil {
		t.Fatal("a sender key over an unsettled session was installed")
	}

	n.catchUp(a2)
	upd = n.deliverChange(b, n.signed(a2, common.ActionRekey, a2), n.hints(a2)...)
	n.commit(n.signed(a2, common.ActionRekey, a2))
	if !slices.Contains(upd.Installed, a.id) {
		t.Fatalf("the held key was not installed after the rekey: %+v", upd)
	}
}

// Moving clears when the log catches up with the directory.
func TestMovingClearsWhenTheLogAgrees(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)
	a2, _ := n.move(a)
	n.notice(b, a2)
	if !gstate(t, b, n.gid).isMoving(a.id) {
		t.Fatal("setup: a should be moving")
	}
	// The directory going back to the log's key clears it too.
	b.sm.NoteDirectoryKey(a.id, a.im.PublicKey)
	if gstate(t, b, n.gid).isMoving(a.id) {
		t.Fatal("a is still moving although the directory agrees with the log")
	}
	n.notice(b, a2)
	n.rekey(a2)
	if gstate(t, b, n.gid).isMoving(a.id) {
		t.Fatal("a is still moving after the rekey")
	}
}

// A member whose session disagrees with the log, and who is not moving, does
// not get our key, does not hold up the send, and is reported.
func TestAnUnsettledMemberIsLeftOutAndReported(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	stranger := newPeer(t, 0x22)
	// b's session with c is on keys the log does not name for c.
	if _, err := b.sm.OpenDirectSession(common.HashIDs(b.id, c.id), c.id, "c", stranger.im.Bundle(), false); err != nil {
		t.Fatal(err)
	}
	if got := b.sm.UnsettledMembers(n.gid); len(got) != 1 || got[0] != c.id {
		t.Fatalf("unsettled = %x", got)
	}
	_, pre := n.send(b, "hi")
	if sentTo(pre, b, c) {
		t.Fatal("b gave its key over a session the log does not vouch for")
	}
	expectMsgs(t, "a", n.pump(a), "hi")
}
