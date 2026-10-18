package core

import (
	common "common"
	"errors"
	"slices"
	"testing"
	"time"
)

// A sender key can reach a member before the membership change that admits its
// owner. The 1:1 message it came in is consumed, so it is held, not refused.
func TestSenderKeyAheadOfMembershipIsHeldThenInstalled(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33, 0x44)
	a, b, c, d := n.peer(0x11), n.peer(0x22), n.peer(0x33), n.peer(0x44)
	n.create(a, b, c)

	// a adds d. d and a hear of it; b has not yet.
	sc := n.signed(a, common.ActionAdd, d)
	n.commit(sc)
	n.deliverChange(a, sc, n.hints(d)...)
	n.catchUp(d)
	n.deliverChange(c, sc, n.hints(d)...)

	// d speaks at once. b gets d's key and message before it has heard of d.
	n.send(d, "d here")
	var gotKey, gotMsg bool
	for _, pkt := range n.inbox[b.id] {
		if pkt.Header.SenderID != d.id {
			continue
		}
		if pkt.Header.MsgType == common.CtrlSenderKey {
			gotKey = true
		} else {
			gotMsg = true
		}
	}
	if !gotKey || !gotMsg {
		t.Fatalf("setup: b should have been sent d's key and message (key=%v msg=%v)", gotKey, gotMsg)
	}

	if got := n.pump(b); len(got) != 0 {
		t.Fatalf("b read %q before it knew d was a member", got)
	}
	if len(n.errs[b.id]) != 0 {
		t.Fatalf("b refused something it should have held: %v", n.errs[b.id])
	}
	if len(gstate(t, b, n.gid).Held) != 1 {
		t.Fatal("d's sender key was not held")
	}

	// b hears of the add; the key is admitted and the message reads.
	upd := n.deliverChange(b, sc, n.hints(d)...)
	if !slices.Contains(upd.Installed, d.id) {
		t.Fatalf("the held key was not installed: %v", upd.Installed)
	}
	if got := n.drain(b); !slices.Equal(got, []string{"d here"}) {
		t.Fatalf("b read %q after learning of d", got)
	}
}

// drain returns what a member has opened since it last looked, without reading
// anything new from the network.
func (n *gnet) drain(p peer) []string {
	out := n.read[p.id]
	n.read[p.id] = nil
	return out
}

// A member who cannot be reached yet must not be left behind by messages sent
// before they could be: nothing is consumed until every member can be sent a key.
func TestSendWaitsForMembersItCannotYetReach(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)

	// a is told of the group with no directory hints for anyone.
	sc := n.signed(a, common.ActionCreate, a, b, c)
	n.commit(sc)
	n.deliverChange(a, sc)
	n.deliverChange(b, sc, n.hints(a, b, c)...)
	n.deliverChange(c, sc, n.hints(a, b, c)...)

	before := gstate(t, a, n.gid).Own
	pkt := common.Packet{Header: common.Header{MsgType: common.MsgText, ConversationID: n.gid, SenderID: a.id}, Body: []byte("hi")}
	_, err := a.sm.EncryptGroupPacket(&pkt)
	var need *NeedSessionsError
	if !errors.As(err, &need) || len(need.Peers) != 2 {
		t.Fatalf("got %v, want a NeedSessionsError naming both peers", err)
	}
	if after := gstate(t, a, n.gid).Own; after.Have != before.Have || after.N != before.N || after.KeyID != before.KeyID {
		t.Fatalf("a refused send consumed state: %+v -> %+v", before, after)
	}
	if string(pkt.Body) != "hi" {
		t.Fatal("a refused send altered the packet")
	}

	// Once the directory data arrives the same send goes through.
	a.sm.ApplyGroupHints(n.gid, n.hints(b, c))
	n.send(a, "now")
	expectMsgs(t, "b", n.pump(b), "now")
	expectMsgs(t, "c", n.pump(c), "now")
}

// Two members who have never exchanged a 1:1 message both speak first. Their
// sessions open crossed; the direct-chat tie-break settles it, and neither
// sender key is lost.
func TestCrossedFirstSendsBothArrive(t *testing.T) {
	n := newGnet(t, 0x11, 0x99)
	a, b := n.peer(0x11), n.peer(0x99)
	n.create(a, b)

	n.send(a, "from a")
	n.send(b, "from b")
	expectMsgs(t, "a", n.pump(a), "from b")
	expectMsgs(t, "b", n.pump(b), "from a")
	noErrors(t, n, a)
	noErrors(t, n, b)

	// Both are still able to talk afterwards.
	n.send(a, "again a")
	n.send(b, "again b")
	expectMsgs(t, "a", n.pump(a), "again b")
	expectMsgs(t, "b", n.pump(b), "again a")
	noErrors(t, n, a)
	noErrors(t, n, b)
}

// A peer whose device lost its state, but kept its identity key, lost everything
// it held of ours, and its key ids begin again. Their old entries are wiped so the
// fresh key is not mistaken for a stale one, and we give them ours again. (A
// device with new keys is a move, which a signed rekey handles; see move_test.go.)
func TestPeerStartingOverIsTreatedAsRemoveAndAdd(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)
	n.send(b, "b1")
	n.send(a, "a1")
	n.pump(a)
	n.pump(b)

	if gstate(t, a, n.gid).peerKeys(b.id) == nil || !slices.Contains(gstate(t, a, n.gid).Own.DeliveredTo, b.id) {
		t.Fatal("setup: a should hold b's key and have given b its own")
	}
	affected := a.sm.PeerKeysChanged(b.id)
	if len(affected) != 1 || affected[0] != n.gid {
		t.Fatalf("affected groups: %v", affected)
	}
	st := gstate(t, a, n.gid)
	if st.peerKeys(b.id) != nil || slices.Contains(st.Own.DeliveredTo, b.id) || !st.Own.MustRotate {
		t.Fatalf("a still trusts what it held about b: %+v", st.Own)
	}

	// b's next key starts over at id 1 and is accepted.
	fresh := peer{id: b.id, pub: b.pub, im: b.im, sm: NewSessionManager(b.im, b.id)}
	fresh.sm.store = nil
	fresh.sm.now = n.clock
	n.peers[b.id] = fresh
	n.catchUp(fresh)
	n.send(fresh, "b after starting over")
	expectMsgs(t, "a", n.pump(a), "b after starting over")
}

// A reader that restarts picks its chains up where it left them, and still knows
// who is in the group.
func TestReceiverStateSurvivesARestart(t *testing.T) {
	n := newGnet(t)
	a, b := n.add(newPersistentPeer(t, 0x11)), n.add(newPersistentPeer(t, 0x22))
	n.create(a, b)
	n.send(a, "one")
	n.send(a, "two")
	n.pump(b)
	in3, _ := n.send(a, "three")
	n.inbox[b.id] = nil

	b2 := n.add(restartWithGroups(t, b, n.clock))
	if info, ok := b2.sm.Group(n.gid); !ok || len(info.Members) != 2 || info.Version != 1 {
		t.Fatalf("membership after restart: %+v ok=%v", info, ok)
	}
	m := clonePacket(in3)
	if err := b2.sm.DecryptGroupPacket(&m); err != nil || string(m.Body) != "three" {
		t.Fatalf("after restart: %v %q", err, m.Body)
	}
	// What was read before the restart is still spent.
	again := clonePacket(in3)
	if err := b2.sm.DecryptGroupPacket(&again); err == nil {
		t.Fatal("a message read before the restart was accepted again")
	}
}

// The signed log, not the display state, decides who may be sent a key. A member
// the log removed must not be reachable by any route, including a stale hint.
func TestHintsThatContradictTheLogAreIgnored(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x66)
	a, b, mallory := n.peer(0x11), n.peer(0x22), n.peer(0x66)
	n.create(a, b)

	// A hint for someone the log does not name, and one whose bundle does not
	// match the keys the log vouches for.
	wrong := n.hints(b)
	wrong[0].Bundle = mallory.im.Bundle()
	a.sm.ApplyGroupHints(n.gid, append(n.hints(mallory), wrong...))

	st := gstate(t, a, n.gid)
	for _, h := range st.Hints {
		if h.ID == mallory.id {
			t.Fatal("a hint for a non-member was kept")
		}
		if h.ID == b.id && h.Bundle.IdentityKey != b.im.PublicKey {
			t.Fatal("a bundle contradicting the log was kept")
		}
	}
}

// A group message waits for its key far longer than a direct one does.
func TestGroupMessagesAreHeldForTheirOwnLifetime(t *testing.T) {
	q := newPendingQueue()
	conv, sender := groupID(0xAA), groupID(0x11)
	long := heldPacket(conv, sender, "group")
	short := heldPacket(conv, sender, "direct")
	q.ParkFor(conv, long, GroupPendingTTL)
	q.Park(conv, short)

	// Age both past the direct lifetime.
	q.mu.Lock()
	for i := range q.byConv[conv] {
		q.byConv[conv][i].parkedAt = time.Now().Add(-2 * pendingTTL)
	}
	q.mu.Unlock()

	got := q.Release(conv)
	if len(got) != 1 || string(got[0].Body) != "group" {
		t.Fatalf("released %d packets, want only the group message", len(got))
	}
}

// --- what the user's commands turn into ---

func intentFixture(t *testing.T, n *gnet, self peer) {
	t.Helper()
	tcl.mgr = NewClientManager(self.id, "self")
	tcl.idMgr = self.im
	tcl.sessionMgr = self.sm
}

func groupSnapshot(t *testing.T, n *gnet, p peer) (GroupInfo, [32]byte) {
	t.Helper()
	info, ok := p.sm.Group(n.gid)
	if !ok {
		t.Fatal("group not known")
	}
	head, _ := p.sm.GroupHead(n.gid)
	// Hints carry names: give them some so commands can be addressed by name.
	return info, head
}

func TestTheSoleAdminLeavingPromotesASuccessorFirst(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	intentFixture(t, n, a)

	info, head := groupSnapshot(t, n, a)
	sc, done, err := tcl.nextChange(info, head, &groupIntent{action: common.ActionLeave})
	if err != nil || done {
		t.Fatalf("err=%v done=%v", err, done)
	}
	if sc.Change.Action != common.ActionPromote || len(sc.Change.Targets) != 1 || sc.Change.Targets[0].ID == a.id {
		t.Fatalf("expected a promotion of someone else first, got %v of %d", sc.Change.Action, len(sc.Change.Targets))
	}
	if !sc.Verify(a.im.SigningKey) {
		t.Fatal("the promotion is not signed by the leaver")
	}

	// With a second admin it is a plain leave.
	n.do(a, common.ActionPromote, b)
	info, head = groupSnapshot(t, n, a)
	sc, _, err = tcl.nextChange(info, head, &groupIntent{action: common.ActionLeave})
	if err != nil || sc.Change.Action != common.ActionLeave {
		t.Fatalf("got %v, %v", sc.Change.Action, err)
	}

	// And a leave already done needs nothing.
	n.do(a, common.ActionLeave, a)
	if _, ok := a.sm.Group(n.gid); ok {
		t.Fatal("the group should be gone after leaving")
	}
}

func TestAddAndRemoveIntentsAreIdempotentAndCheckAuthority(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b)
	intentFixture(t, n, a)
	info, head := groupSnapshot(t, n, a)

	// Adding who is already in is nothing to do; adding someone new is a change.
	if _, done, err := tcl.nextChange(info, head, &groupIntent{action: common.ActionAdd, targets: []common.MemberKey{memberKeyOf(b)}}); !done || err != nil {
		t.Fatalf("adding an existing member: done=%v err=%v", done, err)
	}
	sc, done, err := tcl.nextChange(info, head, &groupIntent{action: common.ActionAdd, targets: []common.MemberKey{memberKeyOf(c)}})
	if done || err != nil || sc.Change.Action != common.ActionAdd || sc.Change.Version != info.Version+1 || sc.Change.PrevHash != head {
		t.Fatalf("add: done=%v err=%v %+v", done, err, sc.Change)
	}

	// Removing yourself is a leave; removing someone already gone is done.
	if _, _, err := tcl.nextChange(info, head, &groupIntent{action: common.ActionRemove, names: []string{info.Names[a.id]}}); err == nil {
		t.Fatal("an admin removing themselves should be pointed at /leave")
	}
	if _, done, _ := tcl.nextChange(info, head, &groupIntent{action: common.ActionRemove, names: []string{"nobody"}}); !done {
		t.Fatal("removing someone who is not a member should be a no-op")
	}

	// A member who is not an admin cannot ask for any of it.
	intentFixture(t, n, b)
	info, head = groupSnapshot(t, n, b)
	if _, _, err := tcl.nextChange(info, head, &groupIntent{action: common.ActionAdd, targets: []common.MemberKey{memberKeyOf(c)}}); err == nil {
		t.Fatal("a non-admin was allowed to build an add")
	}
}

// Everyone speaks first with no prior 1:1 sessions, so every pair opens crossed
// handshakes and the losing side of each fires the same reset the client runs when
// a session is replaced. Extra rotations are expected; lost messages are not.
func TestEveryoneSpeakingFirstLosesNothing(t *testing.T) {
	n := newGnet(t, 0x11, 0x55, 0x99)
	a, b, c := n.peer(0x11), n.peer(0x55), n.peer(0x99)
	n.create(a, b, c)

	n.send(a, "from a")
	n.send(b, "from b")
	n.send(c, "from c")
	expectMsgs(t, "a", n.pump(a), "from b", "from c")
	expectMsgs(t, "b", n.pump(b), "from a", "from c")
	expectMsgs(t, "c", n.pump(c), "from a", "from b")
	for _, p := range []peer{a, b, c} {
		noErrors(t, n, p)
	}

	for round := 0; round < 3; round++ {
		n.send(a, "a again")
		n.send(b, "b again")
		n.send(c, "c again")
		expectMsgs(t, "a", n.pump(a), "b again", "c again")
		expectMsgs(t, "b", n.pump(b), "a again", "c again")
		expectMsgs(t, "c", n.pump(c), "a again", "b again")
	}
	for _, p := range []peer{a, b, c} {
		noErrors(t, n, p)
	}
}

// --- bounds on what an outsider or a long history can make us keep ---

func randomGroup(i int) [16]byte {
	var id [16]byte
	id[0], id[1], id[2] = 0xF0, byte(i>>8), byte(i)
	return id
}

// createOn has creator make a group of creator and the others and delivers it to
// every member's session manager directly.
func createOn(t *testing.T, gid [16]byte, creator peer, others ...peer) common.SignedChange {
	t.Helper()
	return createFor(t, gid, creator, append([]peer{creator}, others...), others...)
}

// createFor is createOn, delivering only to the listed readers. A test about one
// client's limits need not also push every group onto the creator.
func createFor(t *testing.T, gid [16]byte, creator peer, readers []peer, others ...peer) common.SignedChange {
	t.Helper()
	keys := []common.MemberKey{memberKeyOf(creator)}
	for _, o := range others {
		keys = append(keys, memberKeyOf(o))
	}
	sc := common.SignChange(creator.im.SigningSeed, common.GroupChange{
		GroupID: gid, Version: 1, Action: common.ActionCreate, Actor: creator.id, Targets: keys,
	})
	for _, p := range readers {
		if _, err := p.sm.ApplyGroupChange(&common.GroupChangeBody{Name: "g", Change: sc}); err != nil {
			t.Fatalf("create %x on %x: %v", gid[:3], p.id[0], err)
		}
	}
	return sc
}

func countKinds(sm *SessionManager) (stubs, verified, tombs int) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.countLocked(kindStub), sm.countLocked(kindVerified), sm.countLocked(kindTombstone)
}

func TestAnOutsiderSprayingSenderKeysCannotBlockRealGroups(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x77)
	a, b, outsider := n.peer(0x11), n.peer(0x22), n.peer(0x77)

	_, pub, _ := common.GenerateSigningKeys()
	for i := 0; i < 300; i++ {
		d := common.SenderKeyDist{GroupID: randomGroup(i), KeyID: 1, ChainKey: [32]byte{9}, SignPub: pub, MembershipVersion: 1}
		if _, err := openSKDM(t, b, skdmPacket(t, outsider, b, d)); err != nil {
			t.Fatalf("a key for an unknown group should be held, got %v", err)
		}
	}
	if stubs, _, _ := countKinds(b.sm); stubs > maxStubRecords {
		t.Fatalf("%d stub records kept, past the bound of %d", stubs, maxStubRecords)
	}

	// A real group still forms, and what it needs works.
	n.create(a, b)
	n.send(a, "still works")
	expectMsgs(t, "b", n.pump(b), "still works")
	if _, verified, _ := countKinds(b.sm); verified != 1 {
		t.Fatalf("%d verified groups, want 1", verified)
	}
}

func TestLeavingManyGroupsDoesNotUseUpTheLimit(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)

	total := maxTombstones + 20
	for i := 0; i < total; i++ {
		gid := randomGroup(i)
		createFor(t, gid, a, []peer{b}, b)
		leave := common.SignChange(b.im.SigningSeed, common.GroupChange{
			GroupID: gid, Version: 2, PrevHash: gstate(t, b, gid).Membership.Head,
			Action: common.ActionLeave, Actor: b.id, Targets: []common.MemberKey{memberKeyOf(b)},
		})
		upd, err := b.sm.ApplyGroupChange(&common.GroupChangeBody{Change: leave})
		if err != nil || !upd.Left {
			t.Fatalf("leave %d: left=%v err=%v", i, upd.Left, err)
		}
	}
	if _, verified, tombs := countKinds(b.sm); verified != 0 || tombs > maxTombstones {
		t.Fatalf("after %d leaves: %d verified, %d tombstones (bound %d)", total, verified, tombs, maxTombstones)
	}

	// There is still room to join a new group.
	n.create(a, b)
	n.send(a, "welcome")
	expectMsgs(t, "b", n.pump(b), "welcome")
}

func TestOnlyVerifiedGroupsCountAgainstTheMembershipLimit(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)

	for i := 0; i < maxVerifiedGroups; i++ {
		createOn(t, randomGroup(i), a, b)
	}
	sc := common.SignChange(a.im.SigningSeed, common.GroupChange{
		GroupID: randomGroup(9999), Version: 1, Action: common.ActionCreate, Actor: a.id,
		Targets: []common.MemberKey{memberKeyOf(a), memberKeyOf(b)},
	})
	if _, err := b.sm.ApplyGroupChange(&common.GroupChangeBody{Change: sc}); err == nil {
		t.Fatalf("a client joined group %d", maxVerifiedGroups+1)
	}
	if _, verified, _ := countKinds(b.sm); verified != maxVerifiedGroups {
		t.Fatalf("%d verified groups", verified)
	}

	// Leaving one frees a slot, and the refused group can now be joined.
	gid := randomGroup(0)
	leave := common.SignChange(b.im.SigningSeed, common.GroupChange{
		GroupID: gid, Version: 2, PrevHash: gstate(t, b, gid).Membership.Head,
		Action: common.ActionLeave, Actor: b.id, Targets: []common.MemberKey{memberKeyOf(b)},
	})
	if _, err := b.sm.ApplyGroupChange(&common.GroupChangeBody{Change: leave}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.sm.ApplyGroupChange(&common.GroupChangeBody{Change: sc}); err != nil {
		t.Fatalf("after leaving one: %v", err)
	}
}

func TestStaleStubsExpire(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x77)
	b, outsider := n.peer(0x22), n.peer(0x77)

	_, pub, _ := common.GenerateSigningKeys()
	d := common.SenderKeyDist{GroupID: randomGroup(1), KeyID: 1, ChainKey: [32]byte{9}, SignPub: pub, MembershipVersion: 1}
	if _, err := openSKDM(t, b, skdmPacket(t, outsider, b, d)); err != nil {
		t.Fatal(err)
	}
	n.advance(GroupPendingTTL + time.Hour)
	d.GroupID = randomGroup(2)
	if _, err := openSKDM(t, b, skdmPacket(t, outsider, b, d)); err != nil {
		t.Fatal(err)
	}
	if b.sm.lookupGroup(randomGroup(1)) != nil {
		t.Fatal("a stub older than the hold lifetime was kept")
	}
}

// Deletion does not wait for a message to arrive: a quiet group still drops an
// expired previous key and stale skipped keys the next time it is touched.
func TestExpiredKeysAreDeletedEvenInAQuietGroup(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)
	n.send(a, "m0")
	n.send(a, "m1")
	n.send(a, "m2")
	// b reads m2 only, so it holds skipped keys for m0 and m1.
	q := n.inbox[b.id]
	n.inbox[b.id] = []common.Packet{q[0], q[3]}
	n.pump(b)
	a.sm.lookupGroup(n.gid).st.Own.MustRotate = true
	n.send(a, "m3")
	n.pump(b)

	st := gstate(t, b, n.gid).peerKeys(a.id)
	if st.Previous == nil || len(st.Previous.Skipped) == 0 {
		t.Fatalf("setup: expected a previous key holding skipped keys, got %+v", st.Previous)
	}

	n.advance(SkippedKeyTTL + time.Hour)
	// b speaks, touching the group without receiving anything.
	n.send(b, "b speaks")
	if gstate(t, b, n.gid).peerKeys(a.id).Previous != nil {
		t.Fatal("an expired previous key survived being touched")
	}
}
