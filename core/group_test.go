package core

import (
	common "common"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"
)

func groupID(b byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = b
	}
	return id
}

// gnet is a group of in-process members and the network between them. It plays
// the server's part, which is only to order membership changes and to fan
// messages out to whoever the log says is a member, so every check the client
// makes is exercised for real.
type gnet struct {
	t      *testing.T
	gid    [16]byte
	peers  map[[16]byte]peer
	shadow common.Membership // the server's view of the log
	log    []common.SignedChange
	inbox  map[[16]byte][]common.Packet // delivered by the server, not yet read
	held   map[[16]byte][]common.Packet // read but waiting on a key or membership
	read   map[[16]byte][]string        // opened, not yet collected by pump
	errs   map[[16]byte][]error         // permanent failures, per reader
	now    time.Time
}

func newGnet(t *testing.T, ids ...byte) *gnet {
	t.Helper()
	n := &gnet{
		t: t, gid: groupID(0xA0),
		peers: map[[16]byte]peer{},
		inbox: map[[16]byte][]common.Packet{},
		held:  map[[16]byte][]common.Packet{},
		read:  map[[16]byte][]string{},
		errs:  map[[16]byte][]error{},
		now:   time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
	}
	n.shadow.GroupID = n.gid
	for _, b := range ids {
		n.add(newPeer(t, b))
	}
	return n
}

func (n *gnet) add(p peer) peer {
	p.sm.now = n.clock
	// The same reaction the client has when a 1:1 session is replaced: the peer
	// started over, or the two sides opened crossed handshakes, and what was held
	// of each other's group keys is reset.
	p.sm.OnReplaced = func(convID [16]byte) {
		if sess, ok := p.sm.GetSession(convID); ok {
			sess.mu.Lock()
			peerID := sess.st.PeerID
			sess.mu.Unlock()
			p.sm.PeerKeysChanged(peerID)
		}
	}
	n.peers[p.id] = p
	return p
}

func (n *gnet) clock() time.Time { return n.now }

func (n *gnet) advance(d time.Duration) { n.now = n.now.Add(d) }

func (n *gnet) peer(b byte) peer {
	p, ok := n.peers[groupID(b)]
	if !ok {
		n.t.Fatalf("no peer %#x", b)
	}
	return p
}

func memberKeyOf(p peer) common.MemberKey {
	return common.MemberKey{ID: p.id, IdentityKey: p.im.PublicKey, SigningKey: p.im.SigningKey}
}

func (n *gnet) hints(ps ...peer) []common.GroupHint {
	var hs []common.GroupHint
	for _, p := range ps {
		hs = append(hs, common.GroupHint{ID: p.id, Name: fmt.Sprintf("p%x", p.id[0]), Bundle: p.im.Bundle()})
	}
	return hs
}

// signed builds the next change on the server's head, signed by actor.
func (n *gnet) signed(actor peer, action common.GroupAction, targets ...peer) common.SignedChange {
	ch := common.GroupChange{
		GroupID: n.gid, Version: n.shadow.Version + 1, PrevHash: n.shadow.Head,
		Action: action, Actor: actor.id, Timestamp: n.now.Unix(),
	}
	for _, t := range targets {
		ch.Targets = append(ch.Targets, memberKeyOf(t))
	}
	return common.SignChange(actor.im.SigningSeed, ch)
}

func (n *gnet) commit(sc common.SignedChange) common.ChangeEffect {
	n.t.Helper()
	eff, err := n.shadow.Apply(&sc, nil)
	if err != nil {
		n.t.Fatalf("the server refused %v: %v", sc.Change.Action, err)
	}
	n.log = append(n.log, sc)
	return eff
}

// deliverChange hands a change to one member, as the server's broadcast would.
func (n *gnet) deliverChange(to peer, sc common.SignedChange, hints ...common.GroupHint) GroupUpdate {
	n.t.Helper()
	upd, err := to.sm.ApplyGroupChange(&common.GroupChangeBody{Name: "g", Change: sc, Hints: hints})
	if err != nil {
		n.t.Fatalf("%x applying %v: %v", to.id[0], sc.Change.Action, err)
	}
	n.retryHeld(to)
	return upd
}

func (n *gnet) memberPeers() []peer {
	var ps []peer
	for _, id := range n.shadow.MemberIDs() {
		ps = append(ps, n.peers[id])
	}
	return ps
}

// do makes one change and delivers it to everyone who should hear of it: those
// who were members before, including whoever is removed, and those it adds.
func (n *gnet) do(actor peer, action common.GroupAction, targets ...peer) common.SignedChange {
	n.t.Helper()
	before := n.memberPeers()
	sc := n.signed(actor, action, targets...)
	eff := n.commit(sc)

	recipients := slices.Clone(before)
	for _, a := range eff.Added {
		if !slices.ContainsFunc(recipients, func(p peer) bool { return p.id == a.ID }) {
			recipients = append(recipients, n.peers[a.ID])
		}
	}
	for _, r := range recipients {
		isNew := slices.ContainsFunc(eff.Added, func(k common.MemberKey) bool { return k.ID == r.id }) &&
			!slices.ContainsFunc(before, func(p peer) bool { return p.id == r.id })
		if isNew && action != common.ActionCreate {
			n.catchUp(r)
			continue
		}
		n.deliverChange(r, sc, n.hints(targets...)...)
	}
	return sc
}

// catchUp gives a member the whole log, as a LogRq reply would, with directory
// hints for everyone in the group.
func (n *gnet) catchUp(p peer) {
	n.t.Helper()
	for i, sc := range n.log {
		var hs []common.GroupHint
		if i == len(n.log)-1 {
			hs = n.hints(n.memberPeers()...)
		}
		n.deliverChange(p, sc, hs...)
	}
}

// create makes the group and tells every member.
func (n *gnet) create(creator peer, others ...peer) {
	n.t.Helper()
	all := append([]peer{creator}, others...)
	sc := n.signed(creator, common.ActionCreate, all...)
	n.commit(sc)
	for _, p := range all {
		n.deliverChange(p, sc, n.hints(all...)...)
	}
}

// send seals a group message from a member and has the server queue what it
// produces: each sender key for its one recipient, the message for all members.
func (n *gnet) send(from peer, text string) (msg common.Packet, pre []common.Packet) {
	n.t.Helper()
	pkt := common.Packet{
		Header: common.Header{MsgType: common.MsgText, ConversationID: n.gid, SenderID: from.id, BodyLen: uint32(len(text))},
		Body:   []byte(text),
	}
	pre, err := from.sm.EncryptGroupPacket(&pkt)
	if err != nil {
		n.t.Fatalf("%x sending %q: %v", from.id[0], text, err)
	}
	for _, sk := range pre {
		for _, p := range n.peers {
			if p.id != from.id && sk.Header.ConversationID == common.HashIDs(from.id, p.id) {
				n.inbox[p.id] = append(n.inbox[p.id], sk)
			}
		}
	}
	for _, id := range n.shadow.MemberIDs() {
		if id != from.id {
			n.inbox[id] = append(n.inbox[id], clonePacket(pkt))
		}
	}
	return pkt, pre
}

func clonePacket(p common.Packet) common.Packet {
	p.Body = append([]byte(nil), p.Body...)
	return p
}

// pump reads everything waiting for a member and returns the messages it could
// open, including any held ones that a key in this batch released. What cannot
// be opened yet is held and retried when a key arrives.
func (n *gnet) pump(p peer) []string {
	n.t.Helper()
	queue := n.inbox[p.id]
	n.inbox[p.id] = nil
	for _, pkt := range queue {
		n.process(p, pkt)
	}
	out := n.read[p.id]
	n.read[p.id] = nil
	return out
}

func (n *gnet) process(p peer, pkt common.Packet) {
	n.t.Helper()
	pkt = clonePacket(pkt)
	if pkt.Header.MsgType == common.CtrlSenderKey {
		if err := p.sm.DecryptPacket(&pkt); err != nil {
			n.errs[p.id] = append(n.errs[p.id], err)
			return
		}
		upd, err := p.sm.ReceiveSenderKey(&pkt)
		if err != nil {
			n.errs[p.id] = append(n.errs[p.id], err)
			return
		}
		if len(upd.Installed) > 0 {
			n.retryHeld(p)
		}
		return
	}
	err := p.sm.DecryptGroupPacket(&pkt)
	switch {
	case err == nil:
		n.read[p.id] = append(n.read[p.id], string(pkt.Body))
	case Recoverable(err):
		n.held[p.id] = append(n.held[p.id], clonePacket(pkt))
	default:
		n.errs[p.id] = append(n.errs[p.id], err)
	}
}

// retryHeld offers a member what it set aside, as the client does when a key or a
// membership change arrives.
func (n *gnet) retryHeld(p peer) {
	held := n.held[p.id]
	n.held[p.id] = nil
	for _, pkt := range held {
		n.process(p, pkt)
	}
}

// --- inspection ---

func cloneGroupState(st groupState) groupState {
	st.Own = st.Own.clone()
	peers := make([]peerKeys, len(st.Peers))
	for i, p := range st.Peers {
		peers[i] = peerKeys{Owner: p.Owner, Current: p.Current.clone(), Previous: p.Previous.clone()}
	}
	st.Peers = peers
	st.Held = slices.Clone(st.Held)
	st.Hints = slices.Clone(st.Hints)
	st.Membership = st.Membership.Clone()
	return st
}

func gstate(t *testing.T, p peer, gid [16]byte) groupState {
	t.Helper()
	rec := p.sm.lookupGroup(gid)
	if rec == nil {
		return groupState{}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return cloneGroupState(rec.st)
}

func (st groupState) peerKeys(owner [16]byte) *peerKeys {
	for i := range st.Peers {
		if st.Peers[i].Owner == owner {
			return &st.Peers[i]
		}
	}
	return nil
}

func wireOf(t *testing.T, pkt common.Packet) common.GroupWire {
	t.Helper()
	w, err := common.DecodeGroupWire(pkt.Body)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func expectMsgs(t *testing.T, who string, got []string, want ...string) {
	t.Helper()
	g, w := slices.Clone(got), slices.Clone(want)
	slices.Sort(g)
	slices.Sort(w)
	if !slices.Equal(g, w) {
		t.Fatalf("%s read %q, want %q", who, got, want)
	}
}

func noErrors(t *testing.T, n *gnet, p peer) {
	t.Helper()
	if len(n.errs[p.id]) > 0 {
		t.Fatalf("%x hit errors: %v", p.id[0], n.errs[p.id])
	}
}

// --- Spec test 1 ---

func TestThreeMembersExchangeAndSignaturesVerify(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)

	msgA, preA := n.send(a, "from a")
	n.send(b, "from b")
	n.send(c, "from c")

	// Each member's first send gave the key to the two others.
	if len(preA) != 2 {
		t.Fatalf("a's first send carried %d sender keys, want 2", len(preA))
	}
	expectMsgs(t, "a", n.pump(a), "from b", "from c")
	expectMsgs(t, "b", n.pump(b), "from a", "from c")
	expectMsgs(t, "c", n.pump(c), "from a", "from b")
	for _, p := range []peer{a, b, c} {
		noErrors(t, n, p)
	}

	// The signature is a real one under a's sender key, which the others hold.
	w := wireOf(t, msgA)
	pk := gstate(t, b, n.gid).peerKeys(a.id)
	if pk == nil || !common.VerifyGroupMessage(pk.Current.SignPub, w.Header.Encode(), w.Ciphertext, w.Signature) {
		t.Fatal("the message does not verify under the sender key a gave b")
	}
	if w.Header.SenderID != a.id {
		t.Fatal("header does not name its sender")
	}
}

func TestTheServerFansOutOneCiphertextToEveryMember(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	msg, _ := n.send(a, "once")

	for _, p := range []peer{b, c} {
		var found bool
		for _, pkt := range n.inbox[p.id] {
			if pkt.Header.MsgType == common.MsgText {
				found = true
				if string(pkt.Body) != string(msg.Body) {
					t.Fatalf("%x was sent different bytes than the others", p.id[0])
				}
			}
		}
		if !found {
			t.Fatalf("%x was sent no message", p.id[0])
		}
	}
}

// --- Spec test 2 ---

func TestMemberOfflineForADayCatchesUp(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)

	// c never reads anything while a and b talk. Their keys and messages queue.
	n.send(a, "a1")
	n.send(b, "b1")
	n.send(a, "a2")
	n.advance(6 * time.Hour)
	n.send(b, "b2")
	n.advance(18 * time.Hour)
	n.send(a, "a3")

	n.pump(a)
	n.pump(b)
	got := n.pump(c)
	expectMsgs(t, "c", got, "a1", "b1", "a2", "b2", "a3")
	noErrors(t, n, c)

	// And c can now speak to them.
	n.send(c, "c1")
	expectMsgs(t, "a", n.pump(a), "c1")
}

// --- Spec test 3 ---

func TestMessageBeforeItsKeyIsHeldThenRead(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)

	n.send(a, "early")
	// The message overtakes its key on the way to b.
	q := n.inbox[b.id]
	if len(q) != 2 || q[0].Header.MsgType != common.CtrlSenderKey {
		t.Fatalf("unexpected queue shape: %d packets", len(q))
	}
	n.inbox[b.id] = []common.Packet{q[1], q[0]}

	for _, pkt := range n.inbox[b.id] {
		if pkt.Header.MsgType != common.CtrlSenderKey {
			err := b.sm.DecryptGroupPacket(&pkt)
			if !errors.Is(err, ErrNoSenderKey) || !Recoverable(err) {
				t.Fatalf("a message with no key: got %v, want a recoverable ErrNoSenderKey", err)
			}
		}
	}
	expectMsgs(t, "b", n.pump(b), "early")
	noErrors(t, n, b)
	if len(n.held[b.id]) != 0 {
		t.Fatal("the message was still held after its key arrived")
	}
}

// --- Spec test 4 ---

func TestOutOfOrderMessagesWithinOneKey(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)

	for i := 0; i < 6; i++ {
		n.send(a, fmt.Sprintf("m%d", i))
	}
	q := n.inbox[b.id] // [key, m0..m5]
	order := []int{0, 6, 1, 4, 2, 5, 3}
	var reordered []common.Packet
	for _, i := range order {
		reordered = append(reordered, q[i])
	}
	n.inbox[b.id] = reordered

	expectMsgs(t, "b", n.pump(b), "m0", "m1", "m2", "m3", "m4", "m5")
	noErrors(t, n, b)
	if st := gstate(t, b, n.gid).peerKeys(a.id); len(st.Current.Skipped) != 0 || st.Current.N != 6 {
		t.Fatalf("skipped keys left over: %d, at %d", len(st.Current.Skipped), st.Current.N)
	}
}

// --- Spec test 5 ---

func TestPreviousKeyReadableOnlyWithinTheGracePeriod(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)

	n.send(a, "first")
	n.pump(b)

	// Two messages on the first key are still in flight when a rotates.
	n.send(a, "late 1")
	n.send(a, "late 2")
	late := slices.Clone(n.inbox[b.id])
	n.inbox[b.id] = nil

	a.sm.lookupGroup(n.gid).st.Own.MustRotate = true
	n.send(a, "on the new key")
	expectMsgs(t, "b", n.pump(b), "on the new key")
	if st := gstate(t, b, n.gid); st.peerKeys(a.id).Previous == nil {
		t.Fatal("the previous key was not kept for in-flight messages")
	}

	// One arrives inside the grace period and is read.
	n.advance(OldKeyGrace - time.Hour)
	n.inbox[b.id] = late[:1]
	expectMsgs(t, "b", n.pump(b), "late 1")

	// The other arrives after the key expired and is not.
	n.advance(2 * time.Hour)
	n.inbox[b.id] = late[1:]
	if got := n.pump(b); len(got) != 0 {
		t.Fatalf("read %q on an expired key", got)
	}
	if len(n.errs[b.id]) != 1 {
		t.Fatalf("expected one refusal, got %v", n.errs[b.id])
	}
	if gstate(t, b, n.gid).peerKeys(a.id).Previous != nil {
		t.Fatal("the expired key was not deleted")
	}
}

// --- Spec test 6 ---

func TestRemovalSendsNewKeysOnlyToRemainingMembers(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	n.send(a, "a before")
	n.send(b, "b before")
	n.pump(a)
	n.pump(b)
	n.pump(c)
	oldKeyA := gstate(t, a, n.gid).Own.KeyID

	n.do(a, common.ActionRemove, c)

	// Everyone who stays rotates before they next send, and forgets c.
	for _, p := range []peer{a, b} {
		st := gstate(t, p, n.gid)
		if !st.Own.MustRotate {
			t.Fatalf("%x did not mark its key for rotation", p.id[0])
		}
		if st.Own.DeliveredTo != nil && slices.Contains(st.Own.DeliveredTo, c.id) {
			t.Fatalf("%x still counts c as holding its key", p.id[0])
		}
		if st.peerKeys(c.id) != nil {
			t.Fatalf("%x kept c's sender key", p.id[0])
		}
	}

	msgA, preA := n.send(a, "a after")
	msgB, preB := n.send(b, "b after")
	for _, tc := range []struct {
		name string
		pre  []common.Packet
		peer peer
		to   peer
	}{{"a", preA, a, b}, {"b", preB, b, a}} {
		if len(tc.pre) != 1 || tc.pre[0].Header.ConversationID != common.HashIDs(tc.peer.id, tc.to.id) {
			t.Fatalf("%s distributed its new key to %d recipients, want only %x", tc.name, len(tc.pre), tc.to.id[0])
		}
	}
	if w := wireOf(t, msgA); w.Header.KeyID <= oldKeyA {
		t.Fatalf("a kept its old key %d after the removal", w.Header.KeyID)
	}
	expectMsgs(t, "b", n.pump(b), "a after")
	expectMsgs(t, "a", n.pump(a), "b after")

	// c was told, dropped the group, and cannot read what came after.
	if len(n.inbox[c.id]) != 0 {
		t.Fatal("the server fanned a message out to the removed member")
	}
	for _, m := range []common.Packet{msgA, msgB} {
		m := clonePacket(m)
		if err := c.sm.DecryptGroupPacket(&m); err == nil {
			t.Fatal("the removed member decrypted a later message")
		}
	}
	if st := gstate(t, c, n.gid); !st.Left || st.Own.Have || len(st.Peers) != 0 {
		t.Fatalf("the removed member kept keys: %+v", st)
	}
}

func TestMemberWhoMissedTheRemovalStillCannotRead(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	n.send(a, "before")
	n.pump(c)

	// c is offline for the removal and never hears of it.
	sc := n.signed(a, common.ActionRemove, c)
	n.commit(sc)
	n.deliverChange(a, sc)
	n.deliverChange(b, sc)

	msg, pre := n.send(a, "after")
	for _, p := range pre {
		if p.Header.ConversationID == common.HashIDs(a.id, c.id) {
			t.Fatal("a sent its new key to the member it removed")
		}
	}
	// Even handed the message directly, c cannot read it: it names a membership
	// version c has not verified, and c never received the key.
	m := clonePacket(msg)
	if err := c.sm.DecryptGroupPacket(&m); !errors.Is(err, ErrMembershipBehind) {
		t.Fatalf("got %v, want ErrMembershipBehind", err)
	}
	// Once c does hear of the removal there is nothing left to read it with.
	n.deliverChange(c, sc)
	m = clonePacket(msg)
	if err := c.sm.DecryptGroupPacket(&m); !errors.Is(err, ErrNotInGroup) {
		t.Fatalf("after learning of the removal: got %v, want ErrNotInGroup", err)
	}
}

// --- Spec test 7 ---

func TestAddedMemberReadsNewMessagesButNotOldOnes(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33, 0x44)
	a, b, c, d := n.peer(0x11), n.peer(0x22), n.peer(0x33), n.peer(0x44)
	n.create(a, b, c)
	oldA, _ := n.send(a, "before d")
	n.send(b, "b before d")
	n.pump(a)
	n.pump(b)
	n.pump(c)

	n.do(a, common.ActionAdd, d)

	// No rotation is needed, and d is simply not yet in anyone's delivered set.
	if gstate(t, a, n.gid).Own.MustRotate {
		t.Fatal("an add forced a rotation")
	}
	if slices.Contains(gstate(t, a, n.gid).Own.DeliveredTo, d.id) {
		t.Fatal("a already counts d as holding its key")
	}

	// Before a speaks again d holds nothing of a's.
	old := clonePacket(oldA)
	if err := d.sm.DecryptGroupPacket(&old); !errors.Is(err, ErrNoSenderKey) {
		t.Fatalf("d with no key: got %v", err)
	}

	n.send(a, "after d")
	n.send(b, "b after d")
	n.send(c, "c after d")
	expectMsgs(t, "d", n.pump(d), "after d", "b after d", "c after d")
	noErrors(t, n, d)

	// Holding a's key from this point on does not open what came before it.
	old = clonePacket(oldA)
	if err := d.sm.DecryptGroupPacket(&old); err == nil {
		t.Fatal("d read a message sent before it joined")
	}
	// And the others read d.
	n.send(d, "hello from d")
	expectMsgs(t, "a", n.pump(a), "hello from d", "b after d", "c after d")
}

// --- Spec test 8 ---

func TestRotationAfterOneHundredMessages(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)

	var keyIDs []uint32
	for i := 0; i < GroupRotateEvery+1; i++ {
		msg, _ := n.send(a, fmt.Sprintf("m%d", i))
		keyIDs = append(keyIDs, wireOf(t, msg).Header.KeyID)
	}
	for i, id := range keyIDs {
		want := uint32(1)
		if i >= GroupRotateEvery {
			want = 2
		}
		if id != want {
			t.Fatalf("message %d used key %d, want %d", i, id, want)
		}
	}
	if got := n.pump(b); len(got) != GroupRotateEvery+1 {
		t.Fatalf("b read %d of %d", len(got), GroupRotateEvery+1)
	}
	noErrors(t, n, b)
}

func TestRotationAfterSevenDays(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)

	m1, _ := n.send(a, "day 0")
	n.advance(GroupRotateMaxAge - time.Hour)
	m2, _ := n.send(a, "just under a week")
	n.advance(2 * time.Hour)
	m3, _ := n.send(a, "over a week")

	if k1, k2, k3 := wireOf(t, m1).Header.KeyID, wireOf(t, m2).Header.KeyID, wireOf(t, m3).Header.KeyID; k1 != k2 || k3 != k2+1 {
		t.Fatalf("key ids %d, %d, %d: want the first two equal and the third new", k1, k2, k3)
	}
	expectMsgs(t, "b", n.pump(b), "day 0", "just under a week", "over a week")
}

// --- Spec test 9 ---

func TestAMemberCannotForgeAnotherMembersMessage(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	n.send(a, "genuine")
	n.send(b, "b speaks")
	n.pump(b)
	n.pump(c)

	// b holds a's chain key, so it can encrypt something that opens under a's
	// key. What it cannot do is sign as a.
	aKey := gstate(t, b, n.gid).peerKeys(a.id).Current
	bOwn := gstate(t, b, n.gid).Own
	header := common.GroupHeader{
		Version: common.GroupMsgVersion, GroupID: n.gid, SenderID: a.id,
		KeyID: aKey.KeyID, N: aKey.N, MembershipVersion: n.shadow.Version, MsgType: common.MsgText,
	}
	hb := header.Encode()
	mk, _ := common.RatchetStep(aKey.Chain)
	ct, err := common.Encrypt(mk, []byte("a says pay b"), hb)
	if err != nil {
		t.Fatal(err)
	}
	wire := common.GroupWire{Header: header, Ciphertext: ct, Signature: common.SignGroupMessage(bOwn.SignSeed, hb, ct)}
	forged := common.Packet{
		Header: common.Header{MsgType: common.MsgText, ConversationID: n.gid, SenderID: a.id, Flags: common.FlagEncrypted},
		Body:   wire.Encode(),
	}
	forged.Header.BodyLen = uint32(len(forged.Body))

	before := gstate(t, c, n.gid)
	if err := c.sm.DecryptGroupPacket(&forged); err == nil {
		t.Fatal("c accepted a message b signed as a")
	}
	if !reflect.DeepEqual(before.Peers, gstate(t, c, n.gid).Peers) {
		t.Fatal("a forged message moved a chain")
	}

	// Naming itself in the header but a as the packet's sender fails too: the
	// server stamps the real sender on the packet.
	own := common.GroupHeader{Version: common.GroupMsgVersion, GroupID: n.gid, SenderID: b.id, KeyID: bOwn.KeyID, N: bOwn.N, MsgType: common.MsgText}
	hb = own.Encode()
	ct, _ = common.Encrypt([32]byte{1}, []byte("x"), hb)
	mismatch := common.GroupWire{Header: own, Ciphertext: ct, Signature: common.SignGroupMessage(bOwn.SignSeed, hb, ct)}
	pkt := common.Packet{
		Header: common.Header{MsgType: common.MsgText, ConversationID: n.gid, SenderID: a.id, Flags: common.FlagEncrypted},
		Body:   mismatch.Encode(),
	}
	if err := c.sm.DecryptGroupPacket(&pkt); err == nil {
		t.Fatal("a header naming b was accepted on a packet from a")
	}
}

// --- Spec test 10 ---

func TestTamperedMessageFailsAndLeavesStateUnchanged(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)
	msg, pre := n.send(a, "intact")
	n.inbox[b.id] = nil
	for _, sk := range pre {
		pkt := clonePacket(sk)
		if err := b.sm.DecryptPacket(&pkt); err != nil {
			t.Fatal(err)
		}
		if _, err := b.sm.ReceiveSenderKey(&pkt); err != nil {
			t.Fatal(err)
		}
	}

	before := gstate(t, b, n.gid)
	nOffset := 1 + 16 + 16 + 4 // the header's message number
	for name, at := range map[string]int{
		"key id":       1 + 16 + 16,
		"message no.":  nOffset,
		"membership":   nOffset + 4,
		"signature":    common.GroupHeaderLen + 3,
		"ciphertext":   common.GroupHeaderLen + common.SignatureSize + common.NonceSize + 1,
		"last byte":    len(msg.Body) - 1,
		"nonce":        common.GroupHeaderLen + common.SignatureSize,
		"message type": common.GroupHeaderLen - 1,
	} {
		bad := clonePacket(msg)
		bad.Body[at] ^= 0x01
		if err := b.sm.DecryptGroupPacket(&bad); err == nil {
			t.Fatalf("a message with its %s altered was accepted", name)
		}
		if !reflect.DeepEqual(before.Peers, gstate(t, b, n.gid).Peers) {
			t.Fatalf("altering the %s moved state", name)
		}
	}

	good := clonePacket(msg)
	if err := b.sm.DecryptGroupPacket(&good); err != nil || string(good.Body) != "intact" {
		t.Fatalf("the genuine message no longer opens: %v", err)
	}
}

// --- Spec test 11 ---

func TestReplayedMessageIsRefused(t *testing.T) {
	n := newGnet(t, 0x11, 0x22)
	a, b := n.peer(0x11), n.peer(0x22)
	n.create(a, b)
	m0, _ := n.send(a, "m0")
	m1, _ := n.send(a, "m1")
	m2, _ := n.send(a, "m2")
	n.pump(b)
	n.errs[b.id] = nil

	for name, m := range map[string]common.Packet{"m0": m0, "m1": m1, "m2": m2} {
		r := clonePacket(m)
		if err := b.sm.DecryptGroupPacket(&r); err == nil {
			t.Fatalf("a replayed %s was accepted", name)
		}
	}

	// A skipped key is spent once it is used, too.
	m3, _ := n.send(a, "m3")
	m4, _ := n.send(a, "m4")
	first := clonePacket(m4)
	if err := b.sm.DecryptGroupPacket(&first); err != nil {
		t.Fatal(err)
	}
	late := clonePacket(m3)
	if err := b.sm.DecryptGroupPacket(&late); err != nil {
		t.Fatal(err)
	}
	again := clonePacket(m3)
	if err := b.sm.DecryptGroupPacket(&again); err == nil {
		t.Fatal("a skipped key was usable twice")
	}
}

// --- Spec test 12 ---

func TestForgedMembershipChangesFromTheServerAreRefused(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33, 0x66)
	a, b, c, mallory := n.peer(0x11), n.peer(0x22), n.peer(0x33), n.peer(0x66)
	n.create(a, b, c)
	n.send(a, "x")

	// What the server (or anyone relaying for it) might try. Each is built on the
	// real head, so only authenticity and authority stand in the way.
	asA := n.signed(a, common.ActionAdd, mallory)
	unsigned := common.SignedChange{Change: asA.Change}
	signedByServer := common.SignChange(mallory.im.SigningSeed, asA.Change)
	byNonAdmin := n.signed(b, common.ActionAdd, mallory)
	removeAdmin := n.signed(b, common.ActionRemove, a)
	promoteSelf := n.signed(b, common.ActionPromote, b)
	byOutsider := n.signed(mallory, common.ActionAdd, mallory)

	before := gstate(t, c, n.gid).Membership
	for name, sc := range map[string]common.SignedChange{
		"unsigned":             unsigned,
		"signed by the server": signedByServer,
		"by a non-admin":       byNonAdmin,
		"removing an admin":    removeAdmin,
		"self-promotion":       promoteSelf,
		"by a non-member":      byOutsider,
	} {
		_, err := c.sm.ApplyGroupChange(&common.GroupChangeBody{Name: "g", Change: sc})
		if !errors.Is(err, common.ErrBadChange) {
			t.Fatalf("%s: got %v, want a refusal", name, err)
		}
		if got := gstate(t, c, n.gid).Membership; !reflect.DeepEqual(got, before) {
			t.Fatalf("%s: the membership changed", name)
		}
	}
	// And the member who was never added gets no key.
	if m := gstate(t, a, n.gid).Membership; m.IsMember(mallory.id) {
		t.Fatal("mallory became a member")
	}
}

// --- Spec test 13 ---

func TestConcurrentAdminChangesEndInTheSameState(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33, 0x44, 0x55)
	a, b, c, d, e := n.peer(0x11), n.peer(0x22), n.peer(0x33), n.peer(0x44), n.peer(0x55)
	n.create(a, b, c)
	n.do(a, common.ActionPromote, b)

	// Both admins build version 3 on the same head. The server takes the first
	// and refuses the second, which is rebuilt on top.
	addD := n.signed(a, common.ActionAdd, d)
	addE := n.signed(b, common.ActionAdd, e)
	n.commit(addD)
	if _, err := n.shadow.Apply(&addE, nil); !errors.Is(err, common.ErrChangeStale) {
		t.Fatalf("the second concurrent change: got %v, want it refused as stale", err)
	}
	addE = n.signed(b, common.ActionAdd, e)
	n.commit(addE)

	// c hears of them in the wrong order; a and b in the right one.
	for _, p := range []peer{a, b} {
		n.deliverChange(p, addD, n.hints(d)...)
		n.deliverChange(p, addE, n.hints(e)...)
	}
	upd := n.deliverChange(c, addE, n.hints(e)...)
	if !upd.Behind {
		t.Fatal("a change ahead of the log was not reported as a gap")
	}
	if c.sm.GroupVersion(n.gid) != 2 {
		t.Fatalf("c applied a change out of order: version %d", c.sm.GroupVersion(n.gid))
	}
	n.deliverChange(c, addD, n.hints(d)...)

	// Everyone, d and e included once they catch up, holds the same log.
	n.catchUp(d)
	n.catchUp(e)
	want := gstate(t, a, n.gid).Membership
	for _, p := range []peer{b, c, d, e} {
		got := gstate(t, p, n.gid).Membership
		if got.Version != 4 || got.Head != want.Head || !slices.Equal(got.MemberIDs(), want.MemberIDs()) {
			t.Fatalf("%x ended at version %d with %d members, want the same as a", p.id[0], got.Version, len(got.Members))
		}
	}
	if len(want.Members) != 5 {
		t.Fatalf("expected 5 members, got %d", len(want.Members))
	}
}

// --- Spec test 14 ---

// skdmPacket seals a sender key distribution from one peer to another over their
// 1:1 session, opening the session if there is none.
func skdmPacket(t *testing.T, from, to peer, d common.SenderKeyDist) common.Packet {
	t.Helper()
	convID := common.HashIDs(from.id, to.id)
	if _, ok := from.sm.GetSession(convID); !ok {
		if _, err := from.sm.OpenDirectSession(convID, to.id, "peer", to.im.Bundle(), false); err != nil {
			t.Fatal(err)
		}
	}
	payload := d.Encode()
	pkt := common.Packet{
		Header: common.Header{
			ConversationID: convID, SenderID: from.id, MsgType: common.CtrlSenderKey,
			BodyLen: uint32(len(payload)),
		},
		Body: payload,
	}
	if err := from.sm.EncryptPacket(&pkt); err != nil {
		t.Fatal(err)
	}
	return pkt
}

func openSKDM(t *testing.T, to peer, pkt common.Packet) (GroupUpdate, error) {
	t.Helper()
	if err := to.sm.DecryptPacket(&pkt); err != nil {
		t.Fatal(err)
	}
	return to.sm.ReceiveSenderKey(&pkt)
}

func TestSenderKeyFromANonMemberIsRefused(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x77)
	a, b, outsider := n.peer(0x11), n.peer(0x22), n.peer(0x77)
	n.create(a, b)

	_, pub, _ := common.GenerateSigningKeys()
	d := common.SenderKeyDist{GroupID: n.gid, KeyID: 1, ChainKey: [32]byte{9}, SignPub: pub, MembershipVersion: 1}
	upd, err := openSKDM(t, b, skdmPacket(t, outsider, b, d))
	if !errors.Is(err, ErrNotInGroup) || len(upd.Installed) != 0 {
		t.Fatalf("got %v, installed %v; want ErrNotInGroup", err, upd.Installed)
	}
	if gstate(t, b, n.gid).peerKeys(outsider.id) != nil {
		t.Fatal("a non-member's key was stored")
	}
}

func TestSenderKeyForAGroupTheReceiverLeftIsRefused(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)
	n.do(c, common.ActionLeave, c)
	left := n.shadow.Version

	_, pub, _ := common.GenerateSigningKeys()
	d := common.SenderKeyDist{GroupID: n.gid, KeyID: 1, ChainKey: [32]byte{9}, SignPub: pub, MembershipVersion: left}
	if _, err := openSKDM(t, c, skdmPacket(t, a, c, d)); !errors.Is(err, ErrNotInGroup) {
		t.Fatalf("a key for a group c left: got %v", err)
	}
	if gstate(t, c, n.gid).peerKeys(a.id) != nil {
		t.Fatal("a key was stored for a group c is not in")
	}

	// A group nobody has heard of is held rather than refused, in case the group's
	// log is still on its way.
	d.GroupID = groupID(0xEE)
	upd, err := openSKDM(t, b, skdmPacket(t, a, b, d))
	if err != nil || len(upd.Installed) != 0 || !upd.Behind {
		t.Fatalf("a key for an unknown group: err=%v installed=%v behind=%v", err, upd.Installed, upd.Behind)
	}
}

func TestSenderKeyOwnerIsTheSessionPeerNotThePayload(t *testing.T) {
	n := newGnet(t, 0x11, 0x22, 0x33)
	a, b, c := n.peer(0x11), n.peer(0x22), n.peer(0x33)
	n.create(a, b, c)

	// A packet that arrived on a's session with b but is stamped as c's would let
	// a hand b a key in c's name.
	_, pub, _ := common.GenerateSigningKeys()
	d := common.SenderKeyDist{GroupID: n.gid, KeyID: 1, ChainKey: [32]byte{9}, SignPub: pub, MembershipVersion: 1}
	pkt := skdmPacket(t, a, b, d)
	if err := b.sm.DecryptPacket(&pkt); err != nil {
		t.Fatal(err)
	}
	pkt.Header.SenderID = c.id
	if _, err := b.sm.ReceiveSenderKey(&pkt); err == nil {
		t.Fatal("a key was installed for an owner other than the session's peer")
	}
	if gstate(t, b, n.gid).peerKeys(c.id) != nil {
		t.Fatal("c's entry was written from a's session")
	}
}

// --- Spec test 15 ---

func restartWithGroups(t *testing.T, p peer, clock func() time.Time) peer {
	t.Helper()
	q := restart(t, p, storeDir(p))
	if _, err := q.sm.LoadGroups(); err != nil {
		t.Fatalf("load groups: %v", err)
	}
	q.sm.now = clock
	return q
}

func TestCrashAfterEncryptNeverReusesAChainPosition(t *testing.T) {
	n := newGnet(t)
	a, b := n.add(newPersistentPeer(t, 0x11)), n.add(newPersistentPeer(t, 0x22))
	n.create(a, b)

	sent, _ := n.send(a, "sent just before the crash")
	hSent := wireOf(t, sent).Header

	// The process dies. Whatever was in memory is gone; only the disk remains.
	a2 := n.add(restartWithGroups(t, a, n.clock))
	next, _ := n.send(a2, "first after the crash")
	hNext := wireOf(t, next).Header

	if hNext.KeyID == hSent.KeyID && hNext.N <= hSent.N {
		t.Fatalf("position went from %d back to %d: a message key would be reused", hSent.N, hNext.N)
	}
	// b reads both: the restart lost nothing it was owed.
	got := n.pump(b)
	expectMsgs(t, "b", got, "sent just before the crash", "first after the crash")
	noErrors(t, n, b)
}

func TestUnsavableGroupStateMeansNothingIsSent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not bind root")
	}
	n := newGnet(t)
	a, b := n.add(newPersistentPeer(t, 0x11)), n.add(newPersistentPeer(t, 0x22))
	n.create(a, b)
	n.send(a, "one")
	n.pump(b)
	before := gstate(t, a, n.gid).Own

	dir := storeDir(a)
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)

	pkt := common.Packet{Header: common.Header{MsgType: common.MsgText, ConversationID: n.gid, SenderID: a.id}, Body: []byte("two")}
	if _, err := a.sm.EncryptGroupPacket(&pkt); err == nil {
		t.Fatal("a message was released although its state could not be saved")
	}
	if string(pkt.Body) != "two" || pkt.Header.Flags&common.FlagEncrypted != 0 {
		t.Fatal("the packet was altered although nothing was sent")
	}
	if after := gstate(t, a, n.gid).Own; after.N != before.N || after.Chain != before.Chain {
		t.Fatal("the chain moved although the state was not saved")
	}

	os.Chmod(dir, 0o700)
	a2 := n.add(restartWithGroups(t, a, n.clock))
	n.send(a2, "after the failure")
	expectMsgs(t, "b", n.pump(b), "after the failure")
}
