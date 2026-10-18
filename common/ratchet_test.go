package common

import (
	"bytes"
	"testing"
)

func mustKeys(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	priv, pub, err := GenerateIdentityKeys()
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestHandshakeSecretsAgree(t *testing.T) {
	ikA, ikAPub := mustKeys(t)
	ikB, ikBPub := mustKeys(t)
	spkB, spkBPub := mustKeys(t)
	ekA, ekAPub := mustKeys(t)

	skA, err := InitiatorSecret(ikA, ekA, ikBPub, spkBPub)
	if err != nil {
		t.Fatal(err)
	}
	skB, err := ResponderSecret(ikB, spkB, ikAPub, ekAPub)
	if err != nil {
		t.Fatal(err)
	}
	if skA != skB {
		t.Fatal("initiator and responder derived different secrets")
	}

	lhA, hlA, _ := DeriveDirectionRoots(skA)
	lhB, hlB, _ := DeriveDirectionRoots(skB)
	if lhA != lhB || hlA != hlB {
		t.Fatal("direction roots differ")
	}
	if lhA == hlA {
		t.Fatal("the two directions share a root")
	}
}

func TestHandshakeSecretDependsOnEphemeral(t *testing.T) {
	ikA, _ := mustKeys(t)
	_, ikBPub := mustKeys(t)
	_, spkBPub := mustKeys(t)
	ek1, _ := mustKeys(t)
	ek2, _ := mustKeys(t)

	s1, _ := InitiatorSecret(ikA, ek1, ikBPub, spkBPub)
	s2, _ := InitiatorSecret(ikA, ek2, ikBPub, spkBPub)
	if s1 == s2 {
		t.Fatal("a fresh ephemeral key did not change the secret")
	}
}

func TestSendDirectionIsOppositeForThePair(t *testing.T) {
	var lo, hi [16]byte
	hi[0] = 1
	if SendDirection(lo, hi) != LowToHigh || SendDirection(hi, lo) != HighToLow {
		t.Fatal("directions not assigned by ID order")
	}
	if SendDirection(lo, hi).Opposite() != SendDirection(hi, lo) {
		t.Fatal("Opposite disagrees with the peer's own direction")
	}
}

func TestKDFRootKeyChainsOnThePreviousRoot(t *testing.T) {
	rk, _ := mustKeys(t)
	dh, _ := mustKeys(t)

	rk1, ck1, err := KDFRootKey(rk, dh, LowToHigh.RatchetInfo())
	if err != nil {
		t.Fatal(err)
	}
	rk2, _, _ := KDFRootKey(rk1, dh, LowToHigh.RatchetInfo())
	if rk1 == rk || rk2 == rk1 || rk1 == ck1 {
		t.Fatal("root key did not advance, or equals its own chain key")
	}
	_, ckOther, _ := KDFRootKey(rk, dh, HighToLow.RatchetInfo())
	if ckOther == ck1 {
		t.Fatal("direction label does not separate outputs")
	}
}

func TestPreKeySignature(t *testing.T) {
	seed, pub, err := GenerateSigningKeys()
	if err != nil {
		t.Fatal(err)
	}
	_, spk := mustKeys(t)
	sig := SignPreKey(seed, 7, spk)

	if !VerifyPreKey(pub, 7, spk, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifyPreKey(pub, 8, spk, sig) {
		t.Fatal("signature accepted under a different prekey ID")
	}
	_, other := mustKeys(t)
	if VerifyPreKey(pub, 7, other, sig) {
		t.Fatal("signature accepted for a different prekey")
	}
	sig[0] ^= 1
	if VerifyPreKey(pub, 7, spk, sig) {
		t.Fatal("tampered signature accepted")
	}
}

func testBundle(t *testing.T) PreKeyBundle {
	t.Helper()
	_, ik := mustKeys(t)
	seed, sign, _ := GenerateSigningKeys()
	_, spk := mustKeys(t)
	return PreKeyBundle{IdentityKey: ik, SigningKey: sign, SPKID: 3, SPK: spk, SPKSig: SignPreKey(seed, 3, spk)}
}

func TestBundleRoundTripAndVerify(t *testing.T) {
	b := testBundle(t)
	got, err := DecodePreKeyBundle(b.Encode())
	if err != nil || got != b {
		t.Fatalf("round trip failed: %v", err)
	}
	if !got.Verify() {
		t.Fatal("genuine bundle failed verification")
	}
	got.SPK[0] ^= 1
	if got.Verify() {
		t.Fatal("bundle with a swapped prekey verified")
	}
	if _, err := DecodePreKeyBundle(b.Encode()[:PreKeyBundleSize-1]); err == nil {
		t.Fatal("truncated bundle accepted")
	}
}

func TestRatchetHeaderRoundTrip(t *testing.T) {
	_, pub := mustKeys(t)
	_, ik := mustKeys(t)
	_, ek := mustKeys(t)

	for _, init := range []*RatchetInit{nil, {IdentityKey: ik, Ephemeral: ek, SPKID: 9}} {
		h := RatchetHeader{SenderEpoch: 4, UsedPeerEpoch: 2, N: 17, PrevLen: 50, RatchetPub: pub, Init: init}
		enc := append(h.Encode(), []byte("ciphertext")...)

		got, n, err := DecodeRatchetHeader(enc)
		if err != nil {
			t.Fatal(err)
		}
		if n != h.Len() || !bytes.Equal(enc[n:], []byte("ciphertext")) {
			t.Fatalf("consumed %d bytes, want %d", n, h.Len())
		}
		if got.SenderEpoch != 4 || got.UsedPeerEpoch != 2 || got.N != 17 || got.PrevLen != 50 || got.RatchetPub != pub {
			t.Fatalf("fields changed: %+v", got)
		}
		if (got.Init == nil) != (init == nil) || (init != nil && *got.Init != *init) {
			t.Fatalf("init fields changed: %+v", got.Init)
		}
	}
}

func TestRatchetHeaderRejectsBadInput(t *testing.T) {
	h := RatchetHeader{Init: &RatchetInit{}}
	enc := h.Encode()

	if _, _, err := DecodeRatchetHeader(enc[:len(enc)-1]); err == nil {
		t.Fatal("truncated init fields accepted")
	}
	if _, _, err := DecodeRatchetHeader(enc[:10]); err == nil {
		t.Fatal("truncated header accepted")
	}
	bad := append([]byte{}, enc...)
	bad[0] = RatchetVersion + 1
	if _, _, err := DecodeRatchetHeader(bad); err == nil {
		t.Fatal("unknown version accepted")
	}
	bad = append([]byte{}, enc...)
	bad[1] |= 0x80
	if _, _, err := DecodeRatchetHeader(bad); err == nil {
		t.Fatal("unknown flag bits accepted")
	}
}

func TestSafetyNumberIsSymmetricAndKeySensitive(t *testing.T) {
	_, ikA := mustKeys(t)
	_, sA := mustKeys(t)
	_, ikB := mustKeys(t)
	_, sB := mustKeys(t)

	n1 := SafetyNumber(ikA, sA, ikB, sB)
	if n1 != SafetyNumber(ikB, sB, ikA, sA) {
		t.Fatal("the two sides computed different safety numbers")
	}
	if len(n1) != 12*5+11 {
		t.Fatalf("unexpected shape %q", n1)
	}
	_, ikC := mustKeys(t)
	if n1 == SafetyNumber(ikA, sA, ikC, sB) {
		t.Fatal("a substituted identity key did not change the number")
	}
	if n1 == SafetyNumber(ikA, sA, ikB, ikC) {
		t.Fatal("a substituted signing key did not change the number")
	}
}
