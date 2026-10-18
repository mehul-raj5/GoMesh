package common

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randID(t *testing.T) [IDSize]byte {
	t.Helper()
	var id [IDSize]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return id
}

func randKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestSenderKeyDistRoundTrip(t *testing.T) {
	want := SenderKeyDist{
		GroupID:           randID(t),
		KeyID:             7,
		ChainKey:          randKey(t),
		N:                 12,
		SignPub:           randKey(t),
		MembershipVersion: 3,
	}

	got, err := DecodeSenderKeyDist(want.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != want {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestSenderKeyDistRejectsShortBody(t *testing.T) {
	full := (&SenderKeyDist{GroupID: randID(t), KeyID: 1, ChainKey: randKey(t)}).Encode()
	for _, n := range []int{0, 1, IDSize, len(full) - 1} {
		if _, err := DecodeSenderKeyDist(full[:n]); err == nil {
			t.Errorf("expected error decoding %d of %d bytes", n, len(full))
		}
	}
}

func TestConvInfoRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		info ConvInfo
	}{
		{
			name: "direct",
			info: ConvInfo{
				ConvID:  randID(t),
				IsGroup: false,
				Members: []ConvMember{
					{UserID: randID(t), PubKey: randKey(t), Name: "alice"},
					{UserID: randID(t), PubKey: randKey(t), Name: "bob"},
				},
			},
		},
		{
			name: "group",
			info: ConvInfo{
				ConvID:  randID(t),
				IsGroup: true,
				Name:    "the group",
				Members: []ConvMember{
					{UserID: randID(t), PubKey: randKey(t), Name: "alice"},
					{UserID: randID(t), PubKey: randKey(t), Name: "bob"},
					{UserID: randID(t), PubKey: randKey(t), Name: "carol"},
				},
			},
		},
		{
			name: "empty name",
			info: ConvInfo{
				ConvID:  randID(t),
				Members: []ConvMember{{UserID: randID(t), PubKey: randKey(t), Name: ""}},
			},
		},
		{
			name: "no members",
			info: ConvInfo{ConvID: randID(t), IsGroup: true, Name: "empty group"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeConvInfo(tc.info.Encode())
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.ConvID != tc.info.ConvID {
				t.Errorf("convID: got %x want %x", got.ConvID, tc.info.ConvID)
			}
			if got.IsGroup != tc.info.IsGroup {
				t.Errorf("isGroup: got %v want %v", got.IsGroup, tc.info.IsGroup)
			}
			if got.Name != tc.info.Name {
				t.Errorf("name: got %q want %q", got.Name, tc.info.Name)
			}
			if len(got.Members) != len(tc.info.Members) {
				t.Fatalf("member count: got %d want %d", len(got.Members), len(tc.info.Members))
			}
			for i, m := range tc.info.Members {
				if got.Members[i] != m {
					t.Errorf("member %d:\n got %+v\nwant %+v", i, got.Members[i], m)
				}
			}
		})
	}
}

func TestConvInfoRejectsTruncated(t *testing.T) {
	full := (&ConvInfo{
		ConvID:  randID(t),
		IsGroup: true,
		Name:    "g",
		Members: []ConvMember{{UserID: randID(t), PubKey: randKey(t), Name: "alice"}},
	}).Encode()

	for n := 0; n < len(full); n++ {
		if _, err := DecodeConvInfo(full[:n]); err == nil {
			t.Errorf("expected error decoding %d of %d bytes", n, len(full))
		}
	}
}

// A malformed member count must be rejected against the body that actually
// arrived, not trusted far enough to preallocate for.
func TestConvInfoRejectsImpossibleMemberCount(t *testing.T) {
	// convID(16) || isGroup(1) || nameLen(2) || memberCount(2), with an empty name.
	body := (&ConvInfo{ConvID: randID(t), Members: nil}).Encode()
	body[IDSize+3] = 0xFF
	body[IDSize+4] = 0xFF

	if _, err := DecodeConvInfo(body); err == nil {
		t.Fatal("expected error for a member count the body cannot hold")
	}
}

// legacyHashIDs is HashIDs as it was written before LowerID was extracted.
// HashIDs feeds every direct conversation ID in the system, so the refactor has
// to be provably output-identical.
func legacyHashIDs(id1, id2 [16]byte) ([16]byte, [16]byte) {
	first, second := id1, id2
	for i := 0; i < 16; i++ {
		if id1[i] < id2[i] {
			break
		} else if id1[i] > id2[i] {
			first, second = id2, id1
			break
		}
	}
	return first, second
}

func TestLowerIDMatchesLegacyOrdering(t *testing.T) {
	var lowFirst, highFirst, equal [16]byte
	highFirst[0] = 1
	lowLast, highLast := [16]byte{}, [16]byte{}
	highLast[15] = 1

	cases := [][2][16]byte{
		{lowFirst, highFirst},
		{highFirst, lowFirst},
		{equal, equal},
		{lowLast, highLast},
		{highLast, lowLast},
	}
	for i := 0; i < 200; i++ {
		cases = append(cases, [2][16]byte{randID(t), randID(t)})
	}

	for _, c := range cases {
		wantFirst, wantSecond := legacyHashIDs(c[0], c[1])

		gotFirst, gotSecond := c[0], c[1]
		if !LowerID(c[0], c[1]) {
			gotFirst, gotSecond = c[1], c[0]
		}

		if gotFirst != wantFirst || gotSecond != wantSecond {
			t.Fatalf("ordering diverged for %x / %x:\n got %x %x\nwant %x %x",
				c[0], c[1], gotFirst, gotSecond, wantFirst, wantSecond)
		}
	}
}

func TestHashIDsIsSymmetric(t *testing.T) {
	for i := 0; i < 200; i++ {
		a, b := randID(t), randID(t)
		if HashIDs(a, b) != HashIDs(b, a) {
			t.Fatalf("HashIDs not symmetric for %x / %x", a, b)
		}
	}
}

// Exactly one peer must take the sending root, or both ends encrypt with the
// same chain and neither can read the other.
func TestLowerIDAssignsOppositeRoles(t *testing.T) {
	for i := 0; i < 200; i++ {
		a, b := randID(t), randID(t)
		if bytes.Equal(a[:], b[:]) {
			continue
		}
		if LowerID(a, b) == LowerID(b, a) {
			t.Fatalf("both peers took the same role for %x / %x", a, b)
		}
	}
}
