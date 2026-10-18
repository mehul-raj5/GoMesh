package core

import (
	common "common"
	"errors"
	"reflect"
	"testing"
	"time"
)

type peer struct {
	id  [16]byte
	pub [32]byte
	im  *IdentityManager
	sm  *SessionManager
}

// newPeer builds a client with a real identity, signed prekey and session
// manager. Its user ID is idByte repeated, so tests can choose who sorts lower.
func newPeer(t *testing.T, idByte byte) peer {
	t.Helper()
	im := newTestIdentity(t)
	var id [16]byte
	for i := range id {
		id[i] = idByte
	}
	sm := NewSessionManager(im, id)
	sm.store = nil // saving to disk on every message makes tests slow; those that need it ask
	return peer{id: id, pub: im.PublicKey, im: im, sm: sm}
}

// newPersistentPeer is newPeer with sessions saved to its state store, for the
// tests that restart a client.
func newPersistentPeer(t *testing.T, idByte byte) peer {
	t.Helper()
	p := newPeer(t, idByte)
	p.sm.store = p.im.store
	return p
}

// freezeRotation stops a peer's DH rotation by making it look as if the other
// side stopped answering, so a single chain can run as long as a test needs.
func freezeRotation(p peer, convID [16]byte) {
	sess, _ := p.sm.GetSession(convID)
	sess.mu.Lock()
	sess.st.MyEpoch = sess.st.PeerAcked + MaxUnackedEpochs
	sess.mu.Unlock()
}

// start has a open a chat with b, as the CtrlDirectAck would: a holds b's
// bundle and nothing has been sent. b is told nothing.
func start(t *testing.T, a, b peer) [16]byte {
	t.Helper()
	convID := common.HashIDs(a.id, b.id)
	if _, err := a.sm.OpenDirectSession(convID, b.id, "peer", b.im.Bundle(), false); err != nil {
		t.Fatalf("open: %v", err)
	}
	return convID
}

// link opens a chat from a to b and exchanges one message each way, leaving
// both sides with an established session.
func link(t *testing.T, a, b peer) [16]byte {
	t.Helper()
	convID := start(t, a, b)
	open(t, b, seal(t, a, convID, "hello"), "hello")
	open(t, a, seal(t, b, convID, "hi"), "hi")
	return convID
}

func seal(t *testing.T, from peer, convID [16]byte, text string) common.Packet {
	t.Helper()
	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.MsgText,
			ConversationID: convID,
			SenderID:       from.id,
			BodyLen:        uint32(len(text)),
		},
		Body: []byte(text),
	}
	if err := from.sm.EncryptPacket(&pkt); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return pkt
}

func open(t *testing.T, to peer, pkt common.Packet, want string) {
	t.Helper()
	if err := to.sm.DecryptPacket(&pkt); err != nil {
		t.Fatalf("decrypt %q: %v", want, err)
	}
	if got := string(pkt.Body); got != want {
		t.Fatalf("plaintext: got %q want %q", got, want)
	}
}

// stateOf returns a private copy of a peer's session state.
func stateOf(p peer, convID [16]byte) sessionState {
	sess, ok := p.sm.GetSession(convID)
	if !ok {
		return sessionState{}
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return *sess.st.clone()
}

// headerOf reads the ratchet header a sealed packet carries.
func headerOf(t *testing.T, pkt common.Packet) (common.RatchetHeader, int) {
	t.Helper()
	h, n, err := common.DecodeRatchetHeader(pkt.Body)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	return h, n
}

// mutated returns a copy of pkt with one body byte flipped.
func mutated(pkt common.Packet, at int) common.Packet {
	pkt.Body = append([]byte(nil), pkt.Body...)
	pkt.Body[at] ^= 0x01
	return pkt
}

func decryptErr(p peer, pkt common.Packet) error {
	return p.sm.DecryptPacket(&pkt)
}

// --- handshake ---

// The responder is told nothing: the handshake rides in the first message, and
// the session it builds mirrors the initiator's.
func TestFirstMessageBuildsTheResponderSession(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)

	if _, ok := bob.sm.GetSession(convID); ok {
		t.Fatal("bob has a session before hearing anything")
	}
	open(t, bob, seal(t, alice, convID, "out of nowhere"), "out of nowhere")

	st := stateOf(bob, convID)
	if st.PeerID != alice.id || st.PeerIK != alice.pub || st.Initiator {
		t.Fatalf("responder session wrong: %+v", st)
	}
	if !st.Unverified {
		t.Fatal("a key learned from a header should be unverified until the roster agrees")
	}

	open(t, alice, seal(t, bob, convID, "reply"), "reply")
	open(t, bob, seal(t, alice, convID, "and back"), "and back")
}

// Either user ID order must work, since each side picks its direction from the
// IDs alone.
func TestEitherSideMayInitiate(t *testing.T) {
	for _, tc := range []struct {
		name         string
		initiatorID  byte
		responderID  byte
		initiatorLow bool
	}{
		{"initiator has the lower ID", 0x11, 0x99, true},
		{"initiator has the higher ID", 0x99, 0x11, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newPeer(t, tc.initiatorID), newPeer(t, tc.responderID)
			convID := link(t, a, b)
			if stateOf(a, convID).DirSend == stateOf(b, convID).DirSend {
				t.Fatal("both sides own the same direction")
			}
			if (stateOf(a, convID).DirSend == common.LowToHigh) != tc.initiatorLow {
				t.Fatal("direction does not follow ID order")
			}
			open(t, b, seal(t, a, convID, "again"), "again")
		})
	}
}

// A bundle whose prekey was not signed by its own signing key is refused before
// any key is generated (spec test 13).
func TestInvalidPrekeySignatureAbortsSetup(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := common.HashIDs(alice.id, bob.id)

	b := bob.im.Bundle()
	b.SPKSig[0] ^= 1
	if _, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", b, false); err == nil {
		t.Fatal("a bundle with a bad signature was accepted")
	}

	b = bob.im.Bundle()
	b.SPK[3] ^= 1 // a substituted prekey under the original signature
	if _, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", b, false); err == nil {
		t.Fatal("a bundle with a swapped prekey was accepted")
	}

	if _, ok := alice.sm.GetSession(convID); ok {
		t.Fatal("a session was created from a bundle that failed verification")
	}
}

func TestOpeningAgainWithoutForceKeepsTheExistingSession(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	before := stateOf(alice, convID)

	res, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", bob.im.Bundle(), false)
	if err != nil || res.Replaced {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	after := stateOf(alice, convID)
	after.PeerName, before.PeerName = "", ""
	if !reflect.DeepEqual(before, after) {
		t.Fatal("re-opening a chat disturbed a working ratchet")
	}
	open(t, bob, seal(t, alice, convID, "still works"), "still works")
}

func TestPeerWithANewIdentityKeyReplacesTheSessionAndSaysSo(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	impostor := newPeer(t, 0x99)
	res, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", impostor.im.Bundle(), false)
	if err != nil || !res.Replaced || !res.IdentityChanged {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if stateOf(alice, convID).PeerIK != impostor.pub {
		t.Fatal("the session was not rebuilt for the new key")
	}
}

func TestMessageForAnUnknownConversationIsHeldNotDropped(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	later := seal(t, alice, convID, "no handshake fields on this one")

	stranger := newPeer(t, 0x99)
	err := decryptErr(stranger, later)
	if !errors.Is(err, ErrNoSession) || !Recoverable(err) {
		t.Fatalf("expected a recoverable ErrNoSession, got %v", err)
	}
}

// --- the roster's check on a key learned from a header ---

func TestRosterAgreeingClearsTheUnverifiedFlag(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)
	open(t, bob, seal(t, alice, convID, "hi"), "hi")

	if err := bob.sm.NotePeerKeys(convID, alice.id, "alice", alice.pub, alice.im.SigningKey); err != nil {
		t.Fatal(err)
	}
	if stateOf(bob, convID).Unverified {
		t.Fatal("still unverified after the roster agreed")
	}
	n, err := bob.sm.SafetyNumber(convID)
	if err != nil {
		t.Fatal(err)
	}
	an, _ := alice.sm.SafetyNumber(convID)
	if n != an {
		t.Fatalf("the two sides show different safety numbers:\n%s\n%s", n, an)
	}
}

// If the server's directory names a different key than the first message did,
// the session is thrown away.
func TestRosterContradictingTheHeaderClosesTheSession(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)
	open(t, bob, seal(t, alice, convID, "hi"), "hi")

	other := newPeer(t, 0x11)
	err := bob.sm.NotePeerKeys(convID, alice.id, "alice", other.pub, other.im.SigningKey)
	if !errors.Is(err, ErrPeerKeyMismatch) {
		t.Fatalf("expected ErrPeerKeyMismatch, got %v", err)
	}
	if _, ok := bob.sm.GetSession(convID); ok {
		t.Fatal("the session survived a directory mismatch")
	}
}

// When the directory is already known, a first message claiming a different key
// never builds a session at all.
func TestFirstMessageContradictingTheDirectoryIsRefused(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	other := newPeer(t, 0x11)
	bob.sm.KnownKey = func(id [16]byte) ([32]byte, bool) { return other.pub, id == alice.id }

	convID := start(t, alice, bob)
	err := decryptErr(bob, seal(t, alice, convID, "hi"))
	if !errors.Is(err, ErrPeerKeyMismatch) {
		t.Fatalf("expected ErrPeerKeyMismatch, got %v", err)
	}
	if _, ok := bob.sm.GetSession(convID); ok {
		t.Fatal("a session was built on a key the directory contradicts")
	}
}

func TestPacketFromTheWrongSenderIsRefused(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	pkt := seal(t, alice, convID, "from someone else")
	pkt.Header.SenderID = [16]byte{0x42}
	if err := decryptErr(bob, pkt); err == nil {
		t.Fatal("a packet stamped with another sender was read")
	}
}

// --- order, replay and forgery within an epoch ---

func TestOutOfOrderAndLateDelivery(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	m0 := seal(t, alice, convID, "zero")
	m1 := seal(t, alice, convID, "one")
	m2 := seal(t, alice, convID, "two")

	open(t, bob, m2, "two")
	open(t, bob, m0, "zero")
	open(t, bob, m1, "one")

	if n := len(stateOf(bob, convID).Skipped); n != 0 {
		t.Fatalf("%d skipped keys left after every message arrived", n)
	}
}

func TestDuplicateIsRejected(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	m := seal(t, alice, convID, "once")
	open(t, bob, m, "once")
	if err := decryptErr(bob, m); err == nil {
		t.Fatal("a replayed message was accepted")
	}

	// A skipped key is spent by the message that uses it.
	m1, m2 := seal(t, alice, convID, "a"), seal(t, alice, convID, "b")
	open(t, bob, m2, "b")
	open(t, bob, m1, "a")
	if err := decryptErr(bob, m1); err == nil {
		t.Fatal("a late message was readable twice")
	}
}

func TestFailedDecryptDoesNotConsumeASkippedKey(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	m0, m1 := seal(t, alice, convID, "zero"), seal(t, alice, convID, "one")
	open(t, bob, m1, "one")

	// A forgery aimed at m0's slot: right header, damaged ciphertext.
	_, hlen := headerOf(t, m0)
	if err := decryptErr(bob, mutated(m0, hlen+common.NonceSize+1)); err == nil {
		t.Fatal("a damaged ciphertext was accepted")
	}
	open(t, bob, m0, "zero") // the real one still reads
}

// Spec test 7: a message altered anywhere in the header or the ciphertext fails
// and leaves the session exactly as it was.
func TestTamperingFailsAndLeavesStateUnchanged(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	m := seal(t, alice, convID, "authentic")
	_, hlen := headerOf(t, m)
	before := stateOf(bob, convID)

	for _, at := range []int{
		2,                           // sender epoch
		6,                           // used peer epoch
		10,                          // index
		14,                          // previous epoch length
		20,                          // ratchet public key
		hlen + 1,                    // nonce
		hlen + common.NonceSize + 2, // ciphertext
		len(m.Body) - 1,             // tag
	} {
		if err := decryptErr(bob, mutated(m, at)); err == nil {
			t.Errorf("flipping body byte %d was not detected", at)
		}
		if !reflect.DeepEqual(before, stateOf(bob, convID)) {
			t.Fatalf("flipping body byte %d changed the session", at)
		}
	}

	// The packet header is covered too.
	forged := m
	forged.Header.MessageID[0] ^= 1
	if err := decryptErr(bob, forged); err == nil {
		t.Error("an altered packet header went unnoticed")
	}
	if !reflect.DeepEqual(before, stateOf(bob, convID)) {
		t.Fatal("a forged packet header changed the session")
	}

	open(t, bob, m, "authentic") // the genuine one is unaffected
}

// Spec test 9. The index a message claims is attacker-chosen, so it must not
// buy an unbounded run of ratchet steps. Rotation is held off so that one chain
// can run past the limit.
func TestIndexBeyondTheSkipLimitIsRejectedWithoutMovingAnything(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	freezeRotation(alice, convID)

	var last common.Packet
	for i := 0; i <= MaxSkipDirect+1; i++ {
		last = seal(t, alice, convID, "x")
	}
	before := stateOf(bob, convID)
	if err := decryptErr(bob, last); err == nil {
		t.Fatal("a message skipping past the limit was accepted")
	}
	if !reflect.DeepEqual(before, stateOf(bob, convID)) {
		t.Fatal("a rejected skip still moved the chain")
	}
}

func TestExactlyTheSkipLimitIsAccepted(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	freezeRotation(alice, convID)

	var last common.Packet
	for i := 0; i <= MaxSkipDirect; i++ {
		last = seal(t, alice, convID, "edge")
	}
	open(t, bob, last, "edge")
	if n := len(stateOf(bob, convID).Skipped); n != MaxSkipDirect {
		t.Fatalf("held %d skipped keys, want %d", n, MaxSkipDirect)
	}
}

func TestSkippedKeysExpire(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	m0, m1, m2 := seal(t, alice, convID, "0"), seal(t, alice, convID, "1"), seal(t, alice, convID, "2")
	open(t, bob, m2, "2")
	if n := len(stateOf(bob, convID).Skipped); n != 2 {
		t.Fatalf("expected 2 skipped keys, got %d", n)
	}

	clock := bob.sm.now()
	bob.sm.now = func() time.Time { return clock.Add(SkippedKeyTTL + time.Hour) }
	if err := decryptErr(bob, m0); err == nil {
		t.Fatal("a key past its time to live was still used")
	}
	_ = m1
}
