package common

import (
	"errors"
	"slices"
	"testing"
)

// moved is the same member on a new device: the ID stays, both keys are new.
func moved(t *testing.T, m member) member {
	t.Helper()
	n := newMember(t, m.key.ID[0])
	n.key.ID = m.key.ID
	return n
}

func TestRekeyMovesAMemberAndKeepsTheirRole(t *testing.T) {
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	ch, m := newGroup(t, a, b, c)
	ch.apply(a, ActionPromote, b.key)

	b2 := moved(t, b)
	eff := ch.apply(b2, ActionRekey, b2.key)

	got, _ := m.Key(b.key.ID)
	if got != b2.key {
		t.Fatal("the log does not hold b's new keys")
	}
	if !m.IsAdmin(b.key.ID) {
		t.Fatal("moving to a new device cost b the admin role")
	}
	if len(eff.Rekeyed) != 1 || eff.Rekeyed[0] != b2.key || len(eff.Added)+len(eff.Removed) != 0 {
		t.Fatalf("effect = %+v", eff)
	}
	if !slices.Equal(m.MemberIDs(), [][IDSize]byte{a.key.ID, b.key.ID, c.key.ID}) {
		t.Fatal("rekeying changed who is in the group, or their order")
	}

	// From here on b signs with the new key, and the old one is refused.
	ch.apply(b2, ActionDemote, a.key)
	sc := ch.next(b, ActionPromote, a.key)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a change signed by b's old key: got %v", err)
	}
}

// The group's only admin can move devices and stay its admin, which is what
// makes the move safe for groups nobody else can manage.
func TestTheOnlyAdminCanMove(t *testing.T) {
	a, b := newMember(t, 1), newMember(t, 2)
	ch, m := newGroup(t, a, b)
	a2 := moved(t, a)
	ch.apply(a2, ActionRekey, a2.key)
	if !m.IsAdmin(a.key.ID) || len(m.Admins) != 1 {
		t.Fatal("the only admin lost the role by moving")
	}
	ch.apply(a2, ActionRemove, b.key)
}

func TestRekeyRefusals(t *testing.T) {
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	outsider := newMember(t, 9)
	ch, m := newGroup(t, a, b, c)
	b2, c2 := moved(t, b), moved(t, c)

	sameKeys := b
	halfNew := b2
	halfNew.key.IdentityKey = b.key.IdentityKey
	outsider2 := moved(t, outsider)

	cases := []struct {
		name    string
		actor   member
		targets []MemberKey
	}{
		{"for someone else", b2, []MemberKey{c2.key}},
		{"for the actor and someone else", b2, []MemberKey{b2.key, c2.key}},
		{"with no target", b2, nil},
		{"by a non-member", outsider2, []MemberKey{outsider2.key}},
		{"with the current keys", sameKeys, []MemberKey{b.key}},
		{"with only one new key", halfNew, []MemberKey{halfNew.key}},
	}
	for _, tc := range cases {
		sc := ch.next(tc.actor, ActionRekey, tc.targets...)
		before := m.Clone()
		if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
			t.Errorf("a rekey %s: got %v, want a refusal", tc.name, err)
		}
		if m.Version != before.Version || m.Head != before.Head {
			t.Fatalf("a refused rekey %s changed the log", tc.name)
		}
	}

	// Signed by the old key: whoever holds only the old device cannot move it.
	ch2 := GroupChange{GroupID: ch.groupID, Version: m.Version + 1, PrevHash: m.Head,
		Action: ActionRekey, Actor: b.key.ID, Timestamp: 1, Targets: []MemberKey{b2.key}}
	sc := SignChange(b.seed, ch2)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a rekey signed by the old key: got %v", err)
	}
	// Signed by another member.
	sc = SignChange(c.seed, ch2)
	if _, err := m.Apply(&sc, nil); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a rekey signed by another member: got %v", err)
	}
}

// The server pins the actor's directory key, and for a rekey that is the new key.
func TestRekeyIsCheckedAgainstTheDirectory(t *testing.T) {
	a, b := newMember(t, 1), newMember(t, 2)
	ch, m := newGroup(t, a, b)
	b2 := moved(t, b)
	sc := ch.next(b2, ActionRekey, b2.key)

	stale := func(id [IDSize]byte) ([32]byte, bool) { return b.key.SigningKey, id == b.key.ID }
	if _, err := m.Apply(&sc, stale); !errors.Is(err, ErrBadChange) {
		t.Fatalf("a rekey to keys the directory does not hold: got %v", err)
	}
	current := func(id [IDSize]byte) ([32]byte, bool) { return b2.key.SigningKey, id == b.key.ID }
	if _, err := m.Apply(&sc, current); err != nil {
		t.Fatalf("a rekey to the directory's keys: %v", err)
	}
}

// A log that rekeys someone replays from the start for anyone who joins later.
func TestALogWithARekeyReplaysFromTheStart(t *testing.T) {
	a, b, c := newMember(t, 1), newMember(t, 2), newMember(t, 3)
	ch, _ := newGroup(t, a, b)
	var log []SignedChange
	record := func(actor member, action GroupAction, targets ...MemberKey) {
		sc := ch.next(actor, action, targets...)
		if _, err := ch.m.Apply(&sc, nil); err != nil {
			t.Fatal(err)
		}
		log = append(log, sc)
	}
	a2 := moved(t, a)
	record(a2, ActionRekey, a2.key)
	record(a2, ActionAdd, c.key)

	// c replays it all, starting from the create.
	fresh := &Membership{}
	create := SignChange(a.seed, GroupChange{GroupID: ch.groupID, Version: 1, Action: ActionCreate,
		Actor: a.key.ID, Timestamp: 1, Targets: []MemberKey{a.key, b.key}})
	if _, err := fresh.Apply(&create, nil); err != nil {
		t.Fatal(err)
	}
	for _, sc := range log {
		if _, err := fresh.Apply(&sc, nil); err != nil {
			t.Fatalf("replaying %v: %v", sc.Change.Action, err)
		}
	}
	if k, _ := fresh.Key(a.key.ID); k != a2.key || !fresh.IsMember(c.key.ID) {
		t.Fatal("the replay did not end where the log did")
	}
}

func TestMyGroupsRoundTrip(t *testing.T) {
	in := []GroupRef{{ID: [IDSize]byte{1}, Name: "family"}, {ID: [IDSize]byte{2}, Name: ""}}
	out, err := DecodeMyGroups(EncodeMyGroups(in))
	if err != nil || !slices.Equal(in, out) {
		t.Fatalf("round trip: %+v %v", out, err)
	}
	if got, err := DecodeMyGroups(EncodeMyGroups(nil)); err != nil || len(got) != 0 {
		t.Fatal("an empty list did not round trip")
	}
	body := EncodeMyGroups(in)
	for n := 0; n < len(body); n++ {
		if _, err := DecodeMyGroups(body[:n]); err == nil {
			t.Fatalf("a list truncated to %d bytes was accepted", n)
		}
	}
	if _, err := DecodeMyGroups(append(body, 0)); err == nil {
		t.Fatal("trailing bytes were accepted")
	}
}
