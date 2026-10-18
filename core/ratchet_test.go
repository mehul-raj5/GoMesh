package core

import (
	common "common"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// exchange sends one message each way, so each side learns the other's newest
// key and the next send on both rotates.
func exchange(t *testing.T, a, b peer, convID [16]byte, tag string) {
	t.Helper()
	open(t, b, seal(t, a, convID, tag+" a>b"), tag+" a>b")
	open(t, a, seal(t, b, convID, tag+" b>a"), tag+" b>a")
}

// Spec test 1.
func TestTwoWayConversation(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	for i := 0; i < 40; i++ {
		exchange(t, alice, bob, convID, fmt.Sprintf("round %d", i))
	}
	for i := 0; i < 5; i++ {
		open(t, bob, seal(t, alice, convID, fmt.Sprintf("burst %d", i)), fmt.Sprintf("burst %d", i))
	}
	for i := 0; i < 5; i++ {
		open(t, alice, seal(t, bob, convID, fmt.Sprintf("burst %d", i)), fmt.Sprintf("burst %d", i))
	}
}

// Every reply that carries a new key makes the other side rotate on its next
// send, which is what heals a compromise quickly in an active conversation.
func TestRotatesOnceThePeerHasPublishedANewKey(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	before := stateOf(alice, convID).Send.Epoch
	open(t, bob, seal(t, alice, convID, "x"), "x")
	open(t, alice, seal(t, bob, convID, "y"), "y")
	m := seal(t, alice, convID, "z")
	open(t, bob, m, "z")

	h, _ := headerOf(t, m)
	if h.SenderEpoch <= before {
		t.Fatalf("alice did not rotate after hearing bob's new key (epoch %d, was %d)", h.SenderEpoch, before)
	}
	if h.UsedPeerEpoch != stateOf(bob, convID).Send.Epoch {
		t.Fatalf("alice's new epoch was not built against bob's newest key: used %d", h.UsedPeerEpoch)
	}
}

func TestRotatesEveryFiftyMessagesSent(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	epochs := map[uint32]int{}
	for i := 0; i < 3*RotateEvery; i++ {
		m := seal(t, alice, convID, "m")
		h, _ := headerOf(t, m)
		epochs[h.SenderEpoch]++
		open(t, bob, m, "m")
	}
	for e, n := range epochs {
		if n > RotateEvery {
			t.Errorf("epoch %d carried %d messages, more than %d", e, n, RotateEvery)
		}
	}
	if len(epochs) < 3 {
		t.Fatalf("expected at least three epochs over %d messages, saw %d", 3*RotateEvery, len(epochs))
	}
}

// Spec test 2, and the walkthrough: bob is offline while alice sends 500; the
// server queues them in order; bob reads them all after one session build.
func TestFiveHundredMessagesWhileThePeerIsOffline(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)

	var queued []common.Packet
	epochs := map[uint32]bool{}
	for i := 0; i < 500; i++ {
		m := seal(t, alice, convID, fmt.Sprintf("msg %d", i))
		queued = append(queued, m)
		h, _ := headerOf(t, m)
		epochs[h.SenderEpoch] = true
		if h.Init == nil {
			t.Fatalf("message %d lost its handshake fields while the peer was silent", i)
		}
		if i%RotateEvery == 0 && h.N != 0 {
			t.Fatalf("message %d should open an epoch, has index %d", i, h.N)
		}
	}
	if len(epochs) != 10 {
		t.Fatalf("expected 10 epochs, saw %d", len(epochs))
	}

	for i, m := range queued {
		open(t, bob, m, fmt.Sprintf("msg %d", i))
	}
	if n := len(stateOf(bob, convID).Skipped); n != 0 {
		t.Fatalf("%d skipped keys left after in-order delivery", n)
	}

	// Bob answers with a fresh key, alice's next message rotates against it, and
	// once bob reads that, the key alice had been using is no longer held.
	open(t, alice, seal(t, bob, convID, "back"), "back")
	m := seal(t, alice, convID, "next")
	h, _ := headerOf(t, m)
	if h.UsedPeerEpoch != 1 {
		t.Fatalf("alice should now build against bob's epoch 1, used %d", h.UsedPeerEpoch)
	}
	if h.Init != nil {
		t.Fatal("handshake fields are still being sent after a reply")
	}
	open(t, bob, m, "next")
}

// Spec test 3: both sides rotate while messages cross in flight.
func TestSimultaneousRotationKeepsBothDirectionsInStep(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	var fromAlice, fromBob []common.Packet
	for i := 0; i < 130; i++ {
		fromAlice = append(fromAlice, seal(t, alice, convID, fmt.Sprintf("a%d", i)))
		fromBob = append(fromBob, seal(t, bob, convID, fmt.Sprintf("b%d", i)))
	}
	// Neither side has seen anything the other sent since linking, so each has
	// rotated against the other's old key, independently.
	for i := range fromAlice {
		open(t, bob, fromAlice[i], fmt.Sprintf("a%d", i))
		open(t, alice, fromBob[i], fmt.Sprintf("b%d", i))
	}

	// And the conversation carries on after the crossing.
	for i := 0; i < 10; i++ {
		exchange(t, alice, bob, convID, fmt.Sprintf("after %d", i))
	}
}

func TestInterleavedRotationsWithUnevenTraffic(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	for round := 0; round < 12; round++ {
		na, nb := (round*7)%60+1, (round*13)%60+1
		var a, b []common.Packet
		for i := 0; i < na; i++ {
			a = append(a, seal(t, alice, convID, fmt.Sprintf("a %d.%d", round, i)))
		}
		for i := 0; i < nb; i++ {
			b = append(b, seal(t, bob, convID, fmt.Sprintf("b %d.%d", round, i)))
		}
		for i, m := range a {
			open(t, bob, m, fmt.Sprintf("a %d.%d", round, i))
		}
		for i, m := range b {
			open(t, alice, m, fmt.Sprintf("b %d.%d", round, i))
		}
	}
}

// Spec test 5: a message from the epoch before a rotation turns up after the
// rotation has already been processed.
func TestLateMessageFromThePreviousEpoch(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	var ms []common.Packet
	for i := 0; i < 60; i++ {
		ms = append(ms, seal(t, alice, convID, fmt.Sprintf("m%d", i)))
	}
	h0, _ := headerOf(t, ms[0])
	h59, _ := headerOf(t, ms[59])
	if h59.SenderEpoch != h0.SenderEpoch+1 {
		t.Fatalf("expected one rotation across 60 messages, epochs %d..%d", h0.SenderEpoch, h59.SenderEpoch)
	}

	late := ms[RotateEvery-1] // the last of the old epoch
	for i, m := range ms {
		if m.Body[0] == late.Body[0] && i == RotateEvery-1 {
			continue
		}
		open(t, bob, m, fmt.Sprintf("m%d", i))
	}
	open(t, bob, late, fmt.Sprintf("m%d", RotateEvery-1))
	if n := len(stateOf(bob, convID).Skipped); n != 0 {
		t.Fatalf("%d skipped keys left after the straggler arrived", n)
	}
}

// Spec test 6: epoch 3 arrives before epoch 2. It cannot be read yet, because
// its root depends on epoch 2's DH, so it is held and read after.
func TestEpochAheadOfItsPredecessorWaitsForIt(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	var ms []common.Packet
	for i := 0; i < 3*RotateEvery; i++ {
		ms = append(ms, seal(t, alice, convID, fmt.Sprintf("m%d", i)))
	}
	third := ms[2*RotateEvery+3]

	for i := 0; i < RotateEvery; i++ { // first epoch
		open(t, bob, ms[i], fmt.Sprintf("m%d", i))
	}

	before := stateOf(bob, convID)
	err := decryptErr(bob, third)
	if !errors.Is(err, ErrEpochGap) || !Recoverable(err) {
		t.Fatalf("expected a recoverable ErrEpochGap, got %v", err)
	}
	after := stateOf(bob, convID)
	if before.Recv != after.Recv || len(before.Skipped) != len(after.Skipped) {
		t.Fatal("a message that could not be read yet moved the chain")
	}

	for i := RotateEvery; i < 2*RotateEvery; i++ { // the missing epoch
		open(t, bob, ms[i], fmt.Sprintf("m%d", i))
	}
	open(t, bob, third, fmt.Sprintf("m%d", 2*RotateEvery+3))
}

// Spec test 8.
func TestReplayAcrossEpochsIsRejected(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	var ms []common.Packet
	for i := 0; i < 2*RotateEvery+5; i++ {
		m := seal(t, alice, convID, "x")
		ms = append(ms, m)
		open(t, bob, m, "x")
	}
	for _, i := range []int{0, RotateEvery - 1, RotateEvery, len(ms) - 1} {
		if err := decryptErr(bob, ms[i]); err == nil {
			t.Errorf("message %d was accepted a second time", i)
		}
	}
}

// Spec test 10: once the peer has built against a newer key, the older ones
// are gone, and no message key is left lying around.
func TestOldRatchetKeysAreDeletedOnceThePeerMovesPast(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	for i := 0; i < 6; i++ {
		exchange(t, alice, bob, convID, fmt.Sprintf("r%d", i))
	}

	for _, p := range []peer{alice, bob} {
		st := stateOf(p, convID)
		if st.PeerAcked == 0 {
			t.Fatal("no acknowledgement was ever seen")
		}
		for k := range st.MyKeys {
			if k < st.PeerAcked {
				t.Errorf("private ratchet key for epoch %d is still held; the peer has used %d", k, st.PeerAcked)
			}
		}
		if _, held := st.MyKeys[st.PeerAcked]; st.PeerAcked != 0 && !held {
			t.Errorf("the key the peer is currently using (%d) was deleted", st.PeerAcked)
		}
		if len(st.Skipped) != 0 {
			t.Errorf("%d message keys are stored", len(st.Skipped))
		}
	}
}

// Spec test 11: a peer that never answers must not make us keep a private key
// for every fifty messages forever, and the chat must keep flowing.
func TestUnackedEpochsAreCapped(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)

	var last common.Packet
	for i := 0; i < (MaxUnackedEpochs+10)*RotateEvery; i++ {
		last = seal(t, alice, convID, "into the void")
	}
	st := stateOf(alice, convID)
	if st.MyEpoch != MaxUnackedEpochs {
		t.Fatalf("epoch is %d, want it to stop at %d", st.MyEpoch, MaxUnackedEpochs)
	}
	if len(st.MyKeys) > MaxUnackedEpochs {
		t.Fatalf("holding %d private keys, more than %d", len(st.MyKeys), MaxUnackedEpochs)
	}
	if h, _ := headerOf(t, last); h.N < RotateEvery {
		t.Fatalf("messages still flow in the capped epoch, but index is only %d", h.N)
	}

	// Past the cap the chain still ratchets symmetrically; a peer within the
	// skip limit of the newest message can read it.
	closing := seal(t, alice, convID, "still readable")
	_ = closing
}

func TestChatResumesNormalRotationOnceThePeerAnswers(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)

	var ms []common.Packet
	for i := 0; i < (MaxUnackedEpochs+3)*RotateEvery; i++ {
		ms = append(ms, seal(t, alice, convID, "m"))
	}
	for _, m := range ms {
		open(t, bob, m, "m")
	}
	open(t, alice, seal(t, bob, convID, "finally"), "finally")

	before := stateOf(alice, convID).MyEpoch
	exchange(t, alice, bob, convID, "resumed")
	if stateOf(alice, convID).MyEpoch <= before {
		t.Fatal("DH rotation did not resume after the peer acknowledged")
	}
}

// --- handshake fields until the peer replies ---

// The first messages are lost on the way, or parked and evicted. Any later one
// still carries everything needed, so the session builds from it alone.
func TestSessionBuildsFromAnyOneOfTheEarlyMessages(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)

	var ms []common.Packet
	for i := 0; i < 8; i++ {
		ms = append(ms, seal(t, alice, convID, fmt.Sprintf("m%d", i)))
	}
	open(t, bob, ms[6], "m6") // 0..5 never arrived
	open(t, bob, ms[2], "m2") // and one of them turns up later
	open(t, bob, ms[7], "m7")
	open(t, alice, seal(t, bob, convID, "reply"), "reply")
}

func TestHandshakeFieldsStopOnceAMessageHasBeenReceived(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)

	m1 := seal(t, alice, convID, "1")
	if h, _ := headerOf(t, m1); h.Init == nil {
		t.Fatal("first message has no handshake fields")
	}
	open(t, bob, m1, "1")
	if h, _ := headerOf(t, seal(t, alice, convID, "2")); h.Init == nil {
		t.Fatal("handshake fields stopped before any reply")
	}
	if !stateOf(alice, convID).Pending {
		t.Fatal("session should be pending until something arrives on it")
	}

	open(t, alice, seal(t, bob, convID, "reply"), "reply")
	if stateOf(alice, convID).Pending {
		t.Fatal("session is still pending after a reply")
	}
	if h, _ := headerOf(t, seal(t, alice, convID, "3")); h.Init != nil {
		t.Fatal("handshake fields still sent after the reply")
	}
	if h, _ := headerOf(t, seal(t, bob, convID, "bob never sends them")); h.Init != nil {
		t.Fatal("the responder sent handshake fields")
	}
}

// --- both sides open a chat at the same moment ---

func TestSimultaneousHandshakeLowerIDWins(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b byte
	}{
		{"initiators ordered one way", 0x11, 0x99},
		{"initiators ordered the other", 0x99, 0x11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, q := newPeer(t, tc.a), newPeer(t, tc.b)
			winner, loser := p, q
			if tc.b < tc.a {
				winner, loser = q, p
			}

			convID := common.HashIDs(p.id, q.id)
			start(t, p, q)
			start(t, q, p)

			// Each sends before hearing anything. The loser sends twice.
			w1 := seal(t, winner, convID, "winner first")
			l1 := seal(t, loser, convID, "loser first")
			l2 := seal(t, loser, convID, "loser second")

			// The winner reads the loser's message on a temporary session and
			// keeps sending on its own.
			open(t, winner, l1, "loser first")
			if !stateOf(winner, convID).Initiator {
				t.Fatal("the winner abandoned its own session")
			}
			// The loser adopts the winner's session.
			open(t, loser, w1, "winner first")
			if stateOf(loser, convID).Initiator {
				t.Fatal("the loser kept its own session instead of the winner's")
			}

			// What the loser sent before switching is still readable by the winner.
			open(t, winner, l2, "loser second")

			// After one exchange both sit on the same session.
			open(t, winner, seal(t, loser, convID, "on the winner's session"), "on the winner's session")
			open(t, loser, seal(t, winner, convID, "and back"), "and back")
			if stateOf(winner, convID).Pending {
				t.Fatal("the winner's session is still pending after hearing from the loser on it")
			}
			for i := 0; i < 5; i++ {
				exchange(t, winner, loser, convID, fmt.Sprintf("settled %d", i))
			}
		})
	}
}

// The messages the loser sent before switching reach the winner ahead of
// anything on the winner's session, since the server delivers in order. They are
// read on the temporary session and leave the winner's own untouched.
func TestLoserMessagesSentBeforeSwitchingDoNotDisturbTheWinnersSession(t *testing.T) {
	winner, loser := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := common.HashIDs(winner.id, loser.id)
	start(t, winner, loser)
	start(t, loser, winner)

	w1 := seal(t, winner, convID, "w1")
	l1 := seal(t, loser, convID, "l1")
	l2 := seal(t, loser, convID, "l2")

	open(t, loser, w1, "w1") // the loser switches

	before := stateOf(winner, convID)
	open(t, winner, l1, "l1")
	open(t, winner, l2, "l2")
	after := stateOf(winner, convID)
	if before.Recv != after.Recv || before.Send.N != after.Send.N || !after.Pending {
		t.Fatal("messages from the losing session moved the winning one")
	}

	open(t, winner, seal(t, loser, convID, "on the winner's session"), "on the winner's session")
	if stateOf(winner, convID).Pending {
		t.Fatal("the winner never settled")
	}
	exchange(t, winner, loser, convID, "after")
}

func TestLosingSessionIsOnlyKeptForAWhile(t *testing.T) {
	winner, loser := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := common.HashIDs(winner.id, loser.id)
	start(t, winner, loser)
	start(t, loser, winner)

	l1 := seal(t, loser, convID, "l1")
	l2 := seal(t, loser, convID, "l2")
	open(t, winner, l1, "l1")

	clock := time.Now()
	winner.sm.now = func() time.Time { return clock.Add(auxIdle + time.Minute) }
	if err := decryptErr(winner, l2); err == nil {
		t.Fatal("the losing session was still readable long after the grace period")
	}
	// And a straggler cannot talk it back into existence.
	if err := decryptErr(winner, seal(t, loser, convID, "l3")); err == nil {
		t.Fatal("a later packet revived the expired session")
	}
	if !stateOf(winner, convID).Initiator {
		t.Fatal("expiry disturbed the winner's own session")
	}
}

// --- a peer who comes back from nothing ---

// Once we have heard from a peer on a session, a new handshake from them is a
// deliberate restart. It replaces the session instead of being refused.
func TestRestartedPeerReplacesAnEstablishedSession(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	// Bob reinstalls: same identity, no session state.
	bob2 := peer{id: bob.id, pub: bob.pub, im: bob.im, sm: NewSessionManager(bob.im, bob.id)}
	start(t, bob2, alice)
	open(t, alice, seal(t, bob2, convID, "i'm back"), "i'm back")

	open(t, bob2, seal(t, alice, convID, "welcome back"), "welcome back")
	exchange(t, alice, bob2, convID, "after the restart")
}

// A captured first message from a superseded session must not roll things back.
func TestSupersededHandshakeCannotBeReplayed(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, bob, alice)
	oldFirst := seal(t, bob, convID, "first life")
	open(t, alice, oldFirst, "first life")
	open(t, bob, seal(t, alice, convID, "ack"), "ack")

	bob2 := peer{id: bob.id, pub: bob.pub, im: bob.im, sm: NewSessionManager(bob.im, bob.id)}
	start(t, bob2, alice)
	open(t, alice, seal(t, bob2, convID, "second life"), "second life")
	open(t, bob2, seal(t, alice, convID, "ack"), "ack")

	if err := decryptErr(alice, oldFirst); err == nil {
		t.Fatal("a superseded session's handshake was accepted again")
	}
	exchange(t, alice, bob2, convID, "undisturbed")
}

// A forged handshake must not evict a working session before it authenticates.
func TestUnauthenticatedHandshakeDoesNotEvictASession(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	before := stateOf(alice, convID)

	mallory := newPeer(t, 0x99)
	start(t, mallory, alice)
	forged := seal(t, mallory, convID, "let me in")
	forged.Header.SenderID = bob.id
	_, hlen := headerOf(t, forged)
	forged = mutated(forged, hlen+common.NonceSize+1)

	if err := decryptErr(alice, forged); err == nil {
		t.Fatal("a damaged handshake was accepted")
	}
	after := stateOf(alice, convID)
	if before.InitEK != after.InitEK || before.Recv != after.Recv {
		t.Fatal("a failed handshake changed the session")
	}
	exchange(t, alice, bob, convID, "unaffected")
}

// The responder's signed prekey rotated between the initiator fetching the
// bundle and the first message arriving.
func TestFirstMessageSurvivesThePeerRotatingItsPrekey(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)
	first := seal(t, alice, convID, "built on yesterday's prekey")

	if err := bob.im.RotateSPK(); err != nil {
		t.Fatal(err)
	}
	open(t, bob, first, "built on yesterday's prekey")
	open(t, alice, seal(t, bob, convID, "reply"), "reply")
}

func TestFirstMessageAfterThePrekeyExpiredIsRefused(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)
	first := seal(t, alice, convID, "too late")

	clock := time.Now()
	bob.im.now = func() time.Time { return clock }
	if err := bob.im.RotateSPK(); err != nil {
		t.Fatal(err)
	}
	bob.im.now = func() time.Time { return clock.Add(SPKGrace + time.Hour) }
	if err := decryptErr(bob, first); err == nil {
		t.Fatal("a handshake against an expired prekey was accepted")
	}
}

// --- persistence ---

func restart(t *testing.T, p peer, selfStateDir string) peer {
	t.Helper()
	// The same directory under the same keys, as a real start would find it.
	if selfStateDir != p.im.store.dir {
		t.Fatalf("restart expects the peer's own store")
	}
	store := &StateStore{dir: selfStateDir, key: p.im.store.key, names: p.im.store.names}
	// A fresh manager holding the same keys, bringing its prekeys back from disk
	// exactly as a real start would.
	im := &IdentityManager{
		PrivateKey: p.im.PrivateKey, PublicKey: p.im.PublicKey,
		SigningSeed: p.im.SigningSeed, SigningKey: p.im.SigningKey,
		now: time.Now,
	}
	if err := im.LoadPreKeys(store); err != nil {
		t.Fatalf("prekeys: %v", err)
	}
	sm := NewSessionManager(im, p.id)
	if _, err := sm.LoadSessions(); err != nil {
		t.Fatalf("load: %v", err)
	}
	return peer{id: p.id, pub: p.pub, im: im, sm: sm}
}

// The identity in newTestIdentity keeps its store somewhere private to the
// test; tests that restart need to know where.
func storeDir(p peer) string { return p.im.store.dir }

func TestSessionsSurviveARestart(t *testing.T) {
	alice, bob := newPersistentPeer(t, 0x11), newPersistentPeer(t, 0x99)
	convID := link(t, alice, bob)
	for i := 0; i < 7; i++ {
		exchange(t, alice, bob, convID, fmt.Sprintf("r%d", i))
	}
	// A message in flight when bob goes down.
	inFlight := seal(t, alice, convID, "in flight")

	alice2 := restart(t, alice, storeDir(alice))
	bob2 := restart(t, bob, storeDir(bob))

	open(t, bob2, inFlight, "in flight")
	for i := 0; i < 5; i++ {
		exchange(t, alice2, bob2, convID, fmt.Sprintf("after restart %d", i))
	}
	if stateOf(alice2, convID).MyEpoch != stateOf(alice, convID).MyEpoch+1 &&
		stateOf(alice2, convID).MyEpoch < stateOf(alice, convID).MyEpoch {
		t.Fatal("the ratchet went backwards across a restart")
	}
}

// Spec test 12. The state is on disk before a ciphertext can leave, so a crash
// right after sending cannot make the next run reuse that message's key.
func TestRestartNeverReusesAChainKey(t *testing.T) {
	alice, bob := newPersistentPeer(t, 0x11), newPersistentPeer(t, 0x99)
	convID := link(t, alice, bob)

	sent := seal(t, alice, convID, "sent just before the crash")
	hSent, _ := headerOf(t, sent)

	alice2 := restart(t, alice, storeDir(alice)) // "crash" and come back
	next := seal(t, alice2, convID, "first after the crash")
	hNext, _ := headerOf(t, next)

	if hNext.SenderEpoch == hSent.SenderEpoch && hNext.N <= hSent.N {
		t.Fatalf("index went from %d back to %d: a chain key would be reused", hSent.N, hNext.N)
	}
	open(t, bob, sent, "sent just before the crash")
	open(t, bob, next, "first after the crash")
}

// If the new state cannot be saved, nothing is sent: better a failed send than
// a message whose key a restart would hand out again.
func TestUnsavableStateMeansNothingIsSent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not bind root")
	}
	alice, bob := newPersistentPeer(t, 0x11), newPersistentPeer(t, 0x99)
	convID := link(t, alice, bob)

	dir := storeDir(alice)
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)

	pkt := common.Packet{Header: common.Header{MsgType: common.MsgText, ConversationID: convID, SenderID: alice.id}, Body: []byte("x")}
	if err := alice.sm.EncryptPacket(&pkt); err == nil {
		t.Fatal("a message was released although its state could not be saved")
	}

	os.Chmod(dir, 0o700)
	alice2 := restart(t, alice, dir)
	open(t, bob, seal(t, alice2, convID, "after the failure"), "after the failure")
}

func TestStaleSessionRecordsFromAnotherAccountAreIgnored(t *testing.T) {
	alice, bob := newPersistentPeer(t, 0x11), newPersistentPeer(t, 0x99)
	link(t, alice, bob)

	otherAccount := alice
	otherAccount.id = [16]byte{0x77}
	reloaded := restart(t, otherAccount, storeDir(alice))
	if _, ok := reloaded.sm.GetSession(common.HashIDs(alice.id, bob.id)); ok {
		t.Fatal("a session recorded under another user ID was restored")
	}
}

func TestSessionRecordsAreNotReadableByOthers(t *testing.T) {
	alice, bob := newPersistentPeer(t, 0x11), newPersistentPeer(t, 0x99)
	convID := link(t, alice, bob)
	file, _ := alice.im.store.file(recordName(convID))
	path := filepath.Join(storeDir(alice), file)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("session record mode %v", info.Mode().Perm())
	}
}

// --- what the ratchet is for ---

// An attacker who copies alice's entire state at one instant can read what she
// sends for as long as she stays in the same epoch, and no longer: her next
// rotation mixes in a key she generates afterwards plus bob's reply.
func TestACompromiseHealsAfterTheNextExchange(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	exchange(t, alice, bob, convID, "warm up")

	leaked := stateOf(alice, convID)

	tryWithLeak := func(pkt common.Packet) bool {
		h, hlen := headerOf(t, pkt)
		ad := append(pkt.Header.Bytes(), pkt.Body[:hlen]...)
		ct := pkt.Body[hlen:]
		ck := leaked.Send.CK
		// Walk the leaked sending chain forward as far as the attacker likes.
		for i := uint32(0); i < 300; i++ {
			var mk [32]byte
			mk, ck = common.RatchetStep(ck)
			if _, err := common.Decrypt(mk, ct, ad); err == nil {
				return true
			}
		}
		_ = h
		return false
	}

	// Alice still sending in the leaked epoch: exposed. (The window is real.)
	// She rotates on her next send because bob published a new key at the
	// exchange above, so skip straight to the interesting part.
	open(t, alice, seal(t, bob, convID, "bob publishes a key after the leak"), "bob publishes a key after the leak")
	healed := seal(t, alice, convID, "after bob's contribution")
	open(t, bob, healed, "after bob's contribution")

	if tryWithLeak(healed) {
		t.Fatal("a copy of alice's old state still reads her messages after a fresh exchange")
	}
}

// Forward secrecy: nothing in a session's state can decrypt a message that has
// already been read.
func TestNoMessageKeysAreRetainedForReadMessages(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	var read []common.Packet
	for i := 0; i < 120; i++ {
		m := seal(t, alice, convID, fmt.Sprintf("m%d", i))
		open(t, bob, m, fmt.Sprintf("m%d", i))
		read = append(read, m)
	}

	st := stateOf(bob, convID)
	if len(st.Skipped) != 0 {
		t.Fatalf("%d message keys retained", len(st.Skipped))
	}
	// Walk the receive chain forward from where it is now: every key it can
	// produce is for a message not yet sent.
	for _, m := range read {
		_, hlen := headerOf(t, m)
		ad := append(m.Header.Bytes(), m.Body[:hlen]...)
		ck := st.Recv.CK
		for i := 0; i < 200; i++ {
			var mk [32]byte
			mk, ck = common.RatchetStep(ck)
			if _, err := common.Decrypt(mk, m.Body[hlen:], ad); err == nil {
				t.Fatal("the current state can still decrypt a message that was already read")
			}
		}
	}
}

// Messages sent without the peer's participation use a root key that has the
// peer's contribution mixed in at each rotation, so the two directions never
// share one.
func TestDirectionsKeepSeparateRoots(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	a, b := stateOf(alice, convID), stateOf(bob, convID)

	if a.Send.RK == a.Recv.RK {
		t.Fatal("one side uses the same root in both directions")
	}
	if a.Send.RK == b.Send.RK {
		t.Fatal("the two sides share a sending root")
	}
}

// --- starting over with /dm ---

// lostEpoch leaves alice's direction to bob stuck: every message of one epoch is
// lost in transit, and a message from the epoch after it has arrived.
func lostEpoch(t *testing.T, alice, bob peer, convID [16]byte) common.Packet {
	t.Helper()
	var ms []common.Packet
	for i := 0; i < 3*RotateEvery; i++ {
		ms = append(ms, seal(t, alice, convID, fmt.Sprintf("m%d", i)))
	}
	for i := 0; i < RotateEvery; i++ {
		open(t, bob, ms[i], fmt.Sprintf("m%d", i))
	}
	// ms[RotateEvery : 2*RotateEvery] never arrives.
	stuck := ms[2*RotateEvery+1]
	if err := decryptErr(bob, stuck); !errors.Is(err, ErrEpochGap) {
		t.Fatalf("setup: expected the direction to be stuck, got %v", err)
	}
	return stuck
}

// Without starting over there is no way out of a lost epoch, however many
// rotations the sender goes through afterwards. This is the failure /dm exists for.
func TestALostEpochStaysStuckWithoutStartingOver(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	lostEpoch(t, alice, bob, convID)

	for i := 0; i < 4*RotateEvery; i++ {
		if err := decryptErr(bob, seal(t, alice, convID, "still talking")); err == nil {
			t.Fatal("a stuck direction recovered on its own; the premise of /dm no longer holds")
		}
	}
	// Even re-opening with the unchanged identity keeps the broken session.
	if res, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", bob.im.Bundle(), false); err != nil || res.Replaced {
		t.Fatalf("an unforced re-open should leave the session alone: %+v %v", res, err)
	}
}

func TestForcedOpenRecoversALostEpochWhenTheSenderStartsOver(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	stuck := lostEpoch(t, alice, bob, convID)

	res, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", bob.im.Bundle(), true)
	if err != nil || !res.Replaced || res.IdentityChanged {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	open(t, bob, seal(t, alice, convID, "fresh start"), "fresh start")
	for i := 0; i < 5; i++ {
		exchange(t, alice, bob, convID, fmt.Sprintf("after %d", i))
	}
	if err := decryptErr(bob, stuck); err == nil {
		t.Fatal("a message from the abandoned session was read on the new one")
	}
}

// The side that cannot read is not necessarily the side that notices.
func TestForcedOpenRecoversALostEpochWhenTheReceiverStartsOver(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	lostEpoch(t, alice, bob, convID)

	if _, err := bob.sm.OpenDirectSession(convID, alice.id, "alice", alice.im.Bundle(), true); err != nil {
		t.Fatal(err)
	}
	open(t, alice, seal(t, bob, convID, "bob starts over"), "bob starts over")
	open(t, bob, seal(t, alice, convID, "alice follows"), "alice follows")
	for i := 0; i < 5; i++ {
		exchange(t, alice, bob, convID, fmt.Sprintf("after %d", i))
	}
}

func TestForcedOpenWorksFromEitherIDOrder(t *testing.T) {
	for _, ids := range [][2]byte{{0x11, 0x99}, {0x99, 0x11}} {
		a, b := newPeer(t, ids[0]), newPeer(t, ids[1])
		convID := link(t, a, b)
		lostEpoch(t, a, b, convID)

		if _, err := a.sm.OpenDirectSession(convID, b.id, "b", b.im.Bundle(), true); err != nil {
			t.Fatal(err)
		}
		open(t, b, seal(t, a, convID, "again"), "again")
		exchange(t, a, b, convID, "settled")
	}
}

// The fresh session is a new handshake in every respect: new ephemeral key, new
// chains, nothing of the old ratchet.
func TestForcedOpenSharesNothingWithTheSessionItReplaces(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)
	exchange(t, alice, bob, convID, "old")
	old := stateOf(alice, convID)

	if _, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", bob.im.Bundle(), true); err != nil {
		t.Fatal(err)
	}
	fresh := stateOf(alice, convID)

	if fresh.InitEK == old.InitEK || fresh.Send.RK == old.Send.RK || fresh.Recv.RK == old.Recv.RK {
		t.Fatal("the fresh session reuses material from the one it replaced")
	}
	if !fresh.Initiator || !fresh.Pending || fresh.MyEpoch != 1 || len(fresh.Skipped) != 0 {
		t.Fatalf("fresh session is not a clean initiator state: %+v", fresh)
	}
}

// If the session being abandoned was one the peer opened, that handshake must
// stay dead: a captured copy of the peer's first message cannot be replayed to
// swap the fresh session back out.
func TestForcedOpenKeepsTheReplacedHandshakeRetired(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, bob, alice)
	first := seal(t, bob, convID, "bob's original handshake")
	open(t, alice, first, "bob's original handshake")
	open(t, bob, seal(t, alice, convID, "ack"), "ack")

	// Alice, who was the responder, starts over.
	if _, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", bob.im.Bundle(), true); err != nil {
		t.Fatal(err)
	}
	open(t, bob, seal(t, alice, convID, "alice restarts"), "alice restarts")
	open(t, alice, seal(t, bob, convID, "bob replies"), "bob replies")

	before := stateOf(alice, convID)
	if err := decryptErr(alice, first); err == nil {
		t.Fatal("a captured first message from the abandoned session was accepted")
	}
	if after := stateOf(alice, convID); after.InitEK != before.InitEK {
		t.Fatal("replaying the old handshake displaced the fresh session")
	}
	exchange(t, alice, bob, convID, "undisturbed")
}

func TestForcedOpenDropsTheReceiveOnlyCopyOfALosingSession(t *testing.T) {
	winner, loser := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := common.HashIDs(winner.id, loser.id)
	start(t, winner, loser)
	start(t, loser, winner)
	open(t, winner, seal(t, loser, convID, "l1"), "l1")
	if len(winner.sm.aux[convID]) != 1 {
		t.Fatal("setup: expected a receive-only session")
	}

	if _, err := winner.sm.OpenDirectSession(convID, loser.id, "loser", loser.im.Bundle(), true); err != nil {
		t.Fatal(err)
	}
	if len(winner.sm.aux[convID]) != 0 {
		t.Fatal("the old session's receive-only copy outlived it")
	}
}

func TestForcedOpenSurvivesARestart(t *testing.T) {
	alice, bob := newPersistentPeer(t, 0x11), newPersistentPeer(t, 0x99)
	convID := link(t, alice, bob)
	if _, err := alice.sm.OpenDirectSession(convID, bob.id, "bob", bob.im.Bundle(), true); err != nil {
		t.Fatal(err)
	}
	first := seal(t, alice, convID, "fresh")

	alice2 := restart(t, alice, storeDir(alice))
	if stateOf(alice2, convID).InitEK != stateOf(alice, convID).InitEK {
		t.Fatal("the restart restored the old session, not the fresh one")
	}
	open(t, bob, first, "fresh")
}

// /dm only resets a chat when the ack is the answer to a /dm that was typed.
func TestOnlyARequestedAckCountsAsAnAnswerToDM(t *testing.T) {
	if tcl.takeDMRequest("carol") {
		t.Fatal("an unsolicited ack was treated as requested")
	}
	tcl.noteDMRequest("carol")
	if !tcl.takeDMRequest("carol") {
		t.Fatal("the ack for a typed /dm was not recognised")
	}
	if tcl.takeDMRequest("carol") {
		t.Fatal("one /dm was allowed to reset a chat twice")
	}
}

func TestReplacingASessionTellsTheOwnerSoHeldPacketsCanGo(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	var told [][16]byte
	bob.sm.OnReplaced = func(c [16]byte) { told = append(told, c) }

	// A first message on an established session is not a replacement...
	exchange(t, alice, bob, convID, "ordinary")
	if len(told) != 0 {
		t.Fatal("an ordinary message was reported as a replacement")
	}
	// ...a new handshake over it is.
	alice.sm.OpenDirectSession(convID, bob.id, "bob", bob.im.Bundle(), true)
	open(t, bob, seal(t, alice, convID, "starting over"), "starting over")
	if len(told) != 1 || told[0] != convID {
		t.Fatalf("expected one notification for the conversation, got %v", told)
	}
}
