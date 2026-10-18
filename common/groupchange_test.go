package common

import (
	"errors"
	"testing"
)

// member is a test identity: an ID and the keys a change vouches for.
type member struct {
	key  MemberKey
	seed [32]byte
}

func newMember(t *testing.T, tag byte) member {
	t.Helper()
	seed, pub, err := GenerateSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, ik, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	var id [IDSize]byte
	id[0] = tag
	return member{key: MemberKey{ID: id, IdentityKey: ik, SigningKey: pub}, seed: seed}
}

// chainer builds the next change on a membership, signed by an actor.
type chainer struct {
	t       *testing.T
	groupID [IDSize]byte
	m       *Membership
}

func (c *chainer) next(actor member, action GroupAction, targets ...MemberKey) SignedChange {
	c.t.Helper()
	ch := GroupChange{
		GroupID: c.groupID, Version: c.m.Version + 1, PrevHash: c.m.Head,
		Action: action, Actor: actor.key.ID, Timestamp: 1, Targets: targets,
	}
	return SignChange(actor.seed, ch)
}

func (c *chainer) apply(actor member, action GroupAction, targets ...MemberKey) ChangeEffect {
	c.t.Helper()
	sc := c.next(actor, action, targets...)
	eff, err := c.m.Apply(&sc, nil)
	if err != nil {
		c.t.Fatalf("%v by %x: %v", action, actor.key.ID[:1], err)
	}
	return eff
}

func newGroup(t *testing.T, creator member, others ...member) (*chainer, *Membership) {
	t.Helper()
	m := &Membership{}
	c := &chainer{t: t, groupID: [IDSize]byte{0xAA}, m: m}
	keys := []MemberKey{creator.key}
	for _, o := range others {
		keys = append(keys, o.key)
	}
	c.apply(creator, ActionCreate, keys...)
	return c, m
}

func TestChangeRoundTripAndHash(t *testing.T) {
	a, b := newMember(t, 1), newMember(t, 2)
	c, _ := newGroup(t, a, b)
	sc := c.next(a, ActionRemove, b.key)

	got, n, err := DecodeSignedChange(sc.Encode())
	if err != nil || n != len(sc.Encode()) {
		t.Fatalf("decode: %v (%d)", err, n)
	}
	if got.Hash() != sc.Hash() || !got.Verify(a.key.SigningKey) {
		t.Fatal("round trip changed the change or its signature")
	}
	for cut := 0; cut < len(sc.Encode()); cut++ {
		if _, _, err := DecodeSignedChange(sc.Encode()[:cut]); err == nil {
			t.Fatalf("a change truncated to %d bytes decoded", cut)
		}
	}
}

func TestCreateMakesTheCreatorTheFirstAdmin(t *testing.T) {
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	_, m := newGroup(t, a, b, c)
	if m.Version != 1 || len(m.Members) != 3 || len(m.Admins) != 1 || !m.IsAdmin(a.key.ID) {
		t.Fatalf("unexpected state after create: %+v", m)
	}
}

func TestOnlyAnAdminMayAddRemovePromoteOrDemote(t *testing.T) {
	a, b, c, d := newMember(t, 1), newMember(t, 2), newMember(t, 3), newMember(t, 4)
	ch, m := newGroup(t, a, b, c)

	for _, tc := range []struct {
		name   string
		action GroupAction
		target MemberKey
	}{
		{"add", ActionAdd, d.key},
		{"remove", ActionRemove, c.key},
		{"promote", ActionPromote, c.key},
		{"demote", ActionDemote, a.key},
	} {
		sc := ch.next(b, tc.action, tc.target) // b is a member, not an admin
		before := m.Clone()
		if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
			t.Errorf("%s by a non-admin: got %v, want ErrBadChange", tc.name, err)
		}
		if m.Version != before.Version || m.Head != before.Head || len(m.Members) != len(before.Members) {
			t.Errorf("%s by a non-admin changed the membership", tc.name)
		}
	}
}

func TestChangeMustBeSignedByItsActor(t *testing.T) {
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	ch, m := newGroup(t, a, b)

	// The server cannot add c by signing as a with some other key.
	forged := ch.next(a, ActionAdd, c.key)
	other := newMember(t, 9)
	forged = SignChange(other.seed, forged.Change)
	if _, err := m.Apply(&forged, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a change signed with the wrong key: got %v", err)
	}

	// Nor can it alter a genuine change after the fact.
	genuine := ch.next(a, ActionAdd, c.key)
	genuine.Change.Targets = []MemberKey{newMember(t, 7).key}
	if _, err := m.Apply(&genuine, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a tampered change: got %v", err)
	}

	// A change with no signature at all.
	unsigned := SignedChange{Change: ch.next(a, ActionAdd, c.key).Change}
	if _, err := m.Apply(&unsigned, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("an unsigned change: got %v", err)
	}
	if m.Version != 1 || m.IsMember(c.key.ID) {
		t.Fatal("a rejected change altered the membership")
	}
}

func TestChangesApplyStrictlyInOrder(t *testing.T) {
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	ch, m := newGroup(t, a, b)

	// Build v2 and v3 against a scratch copy, then offer them out of order.
	scratch := &chainer{t: t, groupID: ch.groupID, m: func() *Membership { x := m.Clone(); return &x }()}
	v2 := scratch.next(a, ActionAdd, c.key)
	if _, err := scratch.m.Apply(&v2, nil); err != nil {
		t.Fatal(err)
	}
	v3 := scratch.next(a, ActionPromote, c.key)

	if _, err := m.Apply(&v3, nil); !errors.Is(err, ErrChangeGap) {
		t.Fatalf("v3 before v2: got %v, want ErrChangeGap", err)
	}
	if _, err := m.Apply(&v2, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(&v3, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(&v2, nil); !errors.Is(err, ErrChangeStale) {
		t.Fatalf("v2 again: got %v, want ErrChangeStale", err)
	}
}

func TestAForkedChangeIsRefused(t *testing.T) {
	a, b, c, d := newMember(t, 1), newMember(t, 2), newMember(t, 3), newMember(t, 4)
	ch, m := newGroup(t, a, b)

	// Two admins would both build version 2 on the same head. Once one is
	// applied the other is simply stale; and one built on a head that never
	// existed does not follow the log.
	first := ch.next(a, ActionAdd, c.key)
	second := ch.next(a, ActionAdd, d.key)
	if _, err := m.Apply(&first, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(&second, nil); !errors.Is(err, ErrChangeStale) {
		t.Fatalf("losing side of a fork: got %v, want ErrChangeStale", err)
	}

	phantom := ch.next(a, ActionAdd, d.key)
	phantom.Change.PrevHash = [32]byte{9}
	phantom = SignChange(a.seed, phantom.Change)
	if _, err := m.Apply(&phantom, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a change on the wrong head: got %v", err)
	}
}

func TestLeaveRules(t *testing.T) {
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	ch, m := newGroup(t, a, b, c)

	// The only admin may not simply leave a group that has other members.
	sc := ch.next(a, ActionLeave, a.key)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("the sole admin leaving: got %v", err)
	}
	// A member may not make someone else leave.
	sc = ch.next(b, ActionLeave, c.key)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("leave naming someone else: got %v", err)
	}

	// Once someone else is an admin, the leave is valid.
	ch.apply(a, ActionPromote, b.key)
	eff := ch.apply(a, ActionLeave, a.key)
	if len(eff.Removed) != 1 || eff.Removed[0] != a.key.ID || m.IsMember(a.key.ID) || m.IsAdmin(a.key.ID) {
		t.Fatalf("leave did not remove the member: %+v", eff)
	}
	if !m.IsAdmin(b.key.ID) {
		t.Fatal("the successor lost admin")
	}
}

func TestDemoteCannotLeaveTheGroupWithoutAnAdmin(t *testing.T) {
	a, b := newMember(t, 1), newMember(t, 2)
	ch, m := newGroup(t, a, b)
	sc := ch.next(a, ActionDemote, a.key)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("demoting the last admin: got %v", err)
	}
}

func TestAdminCannotRemoveThemselvesOrANonMember(t *testing.T) {
	a, b, z := newMember(t, 1), newMember(t, 2), newMember(t, 9)
	ch, m := newGroup(t, a, b)
	for _, target := range []MemberKey{a.key, z.key} {
		sc := ch.next(a, ActionRemove, target)
		if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
			t.Fatalf("removing %x: got %v", target.ID[:1], err)
		}
	}
}

func TestAddRejectsExistingMembersAndMissingKeys(t *testing.T) {
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	ch, m := newGroup(t, a, b)

	sc := ch.next(a, ActionAdd, b.key)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("adding an existing member: got %v", err)
	}
	keyless := c.key
	keyless.SigningKey = [32]byte{}
	sc = ch.next(a, ActionAdd, keyless)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("adding a member with no signing key: got %v", err)
	}
}

func TestCreateMustIncludeTheCreator(t *testing.T) {
	a, b := newMember(t, 1), newMember(t, 2)
	m := &Membership{}
	ch := GroupChange{GroupID: [IDSize]byte{1}, Version: 1, Action: ActionCreate, Actor: a.key.ID, Targets: []MemberKey{b.key}}
	sc := SignChange(a.seed, ch)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a create that omits its creator: got %v", err)
	}
}

func TestDirectoryPinOverridesAClaimedSigningKey(t *testing.T) {
	a, b := newMember(t, 1), newMember(t, 2)
	m := &Membership{}
	ch := GroupChange{
		GroupID: [IDSize]byte{1}, Version: 1, Action: ActionCreate, Actor: a.key.ID,
		Targets: []MemberKey{a.key, b.key},
	}
	sc := SignChange(a.seed, ch)

	pinTo := func(id [IDSize]byte, key [32]byte) KeyPin {
		return func(got [IDSize]byte) ([32]byte, bool) { return key, got == id }
	}
	if _, err := m.Apply(&sc, pinTo(b.key.ID, [32]byte{0xEE})); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a target whose key contradicts the directory: got %v", err)
	}
	if _, err := m.Apply(&sc, pinTo(a.key.ID, [32]byte{0xEE})); !errors.Is(err, ErrBadChange) {
		t.Fatalf("an actor whose key contradicts the directory: got %v", err)
	}
	if _, err := m.Apply(&sc, pinTo(a.key.ID, a.key.SigningKey)); err != nil {
		t.Fatalf("a matching pin: %v", err)
	}
}

func TestHintsAndBodiesRoundTrip(t *testing.T) {
	var b PreKeyBundle
	b.IdentityKey[0], b.SigningKey[0], b.SPK[0] = 1, 2, 3
	hints := []GroupHint{{ID: [IDSize]byte{1}, Name: "alice", Bundle: b}, {ID: [IDSize]byte{2}, Name: "bob", Bundle: b}}

	got, n, err := DecodeHints(EncodeHints(hints))
	if err != nil || n != len(EncodeHints(hints)) || len(got) != 2 || got[1].Name != "bob" || got[0].Bundle != b {
		t.Fatalf("hints round trip: %+v %v", got, err)
	}

	a := newMember(t, 1)
	body := GroupChangeBody{
		Name:   "team",
		Change: SignChange(a.seed, GroupChange{GroupID: [IDSize]byte{1}, Version: 1, Action: ActionCreate, Actor: a.key.ID, Targets: []MemberKey{a.key}}),
		Hints:  hints,
	}
	back, err := DecodeGroupChangeBody(body.Encode())
	if err != nil || back.Name != "team" || back.Change.Hash() != body.Change.Hash() || len(back.Hints) != 2 {
		t.Fatalf("change body round trip: %+v %v", back, err)
	}

	rej := GroupChangeReject{GroupID: [IDSize]byte{1}, ChangeHash: [32]byte{2}, HeadVersion: 5, Reason: "stale"}
	if got, err := DecodeGroupChangeReject(rej.Encode()); err != nil || got != rej {
		t.Fatalf("reject round trip: %+v %v", got, err)
	}
}

func TestGroupWireRoundTripAndSignature(t *testing.T) {
	seed, pub, err := GenerateSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	h := GroupHeader{Version: GroupMsgVersion, GroupID: [IDSize]byte{1}, SenderID: [IDSize]byte{2}, KeyID: 3, N: 4, MembershipVersion: 5, MsgType: MsgText}
	ct := make([]byte, NonceSize+20)
	w := GroupWire{Header: h, Ciphertext: ct, Signature: SignGroupMessage(seed, h.Encode(), ct)}

	got, err := DecodeGroupWire(w.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Header != h || !VerifyGroupMessage(pub, got.Header.Encode(), got.Ciphertext, got.Signature) {
		t.Fatal("round trip changed the message or broke its signature")
	}

	// Any change to the header or ciphertext breaks the signature.
	h2 := h
	h2.KeyID++
	if VerifyGroupMessage(pub, h2.Encode(), ct, w.Signature) {
		t.Fatal("a signature held for an altered header")
	}
	ct2 := append([]byte(nil), ct...)
	ct2[0] ^= 1
	if VerifyGroupMessage(pub, h.Encode(), ct2, w.Signature) {
		t.Fatal("a signature held for an altered ciphertext")
	}
}
