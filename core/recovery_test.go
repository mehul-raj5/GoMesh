package core

import (
	common "common"
	"errors"
	"testing"
)

// The whole point of the design: alice opens a chat and sends immediately, and
// bob builds his side from the first message alone. Nothing has to be fetched
// first, so nothing is held waiting for a roster, and messages that arrive in
// any order all read.
func TestReceiverRecoversFromFirstMessageAlone(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := start(t, alice, bob)

	first := seal(t, alice, convID, "hello, out of nowhere")
	second := seal(t, alice, convID, "and a follow-up")

	// Bob has no session, and the second message alone is enough to make one.
	open(t, bob, second, "and a follow-up")
	open(t, bob, first, "hello, out of nowhere")

	// And the conversation carries on normally in both directions.
	open(t, bob, seal(t, alice, convID, "third"), "third")
	open(t, alice, seal(t, bob, convID, "reply"), "reply")
}

// A packet that cannot be read yet because an earlier epoch is still in flight
// is held, and is released once that epoch lands.
func TestHeldEpochIsReleasedWhenItsPredecessorArrives(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	var ms []common.Packet
	for i := 0; i < 2*RotateEvery+1; i++ {
		ms = append(ms, seal(t, alice, convID, "m"))
	}
	ahead := ms[2*RotateEvery]

	for _, m := range ms[:RotateEvery] {
		open(t, bob, m, "m")
	}

	q := newPendingQueue()
	p := ahead
	err := bob.sm.DecryptPacket(&p)
	if !errors.Is(err, ErrEpochGap) || !Recoverable(err) {
		t.Fatalf("expected a recoverable ErrEpochGap, got %v", err)
	}
	q.Park(convID, ahead)

	for _, m := range ms[RotateEvery : 2*RotateEvery] {
		open(t, bob, m, "m")
	}
	for _, held := range q.Release(convID) {
		open(t, bob, held, "m")
	}
	if q.Len() != 0 {
		t.Fatalf("%d packets left held", q.Len())
	}
}

// A group message arriving before its sender key is held, then read once the
// key catches up — the same machinery, released per sender.
func TestGroupMessageHeldUntilSenderKeyArrives(t *testing.T) {
	n := newGnet(t, 0x11, 0x55, 0x99)
	alice, bob, carol := n.peer(0x11), n.peer(0x55), n.peer(0x99)
	n.create(alice, bob, carol)

	n.send(alice, "alice speaking")
	n.send(bob, "bob speaking")

	// Carol's queue holds, for each of them, the key and then the message. She
	// sees the messages first.
	var keys, msgs []common.Packet
	for _, pkt := range n.inbox[carol.id] {
		if pkt.Header.MsgType == common.CtrlSenderKey {
			keys = append(keys, pkt)
		} else {
			msgs = append(msgs, pkt)
		}
	}
	n.inbox[carol.id] = nil

	q := newPendingQueue()
	for _, pkt := range msgs {
		p := clonePacket(pkt)
		if err := carol.sm.DecryptGroupPacket(&p); !errors.Is(err, ErrNoSenderKey) {
			t.Fatalf("expected ErrNoSenderKey, got %v", err)
		}
		q.Park(n.gid, pkt)
	}

	install := func(from peer) {
		for _, k := range keys {
			if k.Header.SenderID != from.id {
				continue
			}
			k := clonePacket(k)
			if err := carol.sm.DecryptPacket(&k); err != nil {
				t.Fatal(err)
			}
			if _, err := carol.sm.ReceiveSenderKey(&k); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Alice's key lands first. Only her message should come back.
	install(alice)
	released := q.ReleaseSender(n.gid, alice.id)
	if len(released) != 1 {
		t.Fatalf("expected 1 released for alice, got %d", len(released))
	}
	if err := carol.sm.DecryptGroupPacket(&released[0]); err != nil || string(released[0].Body) != "alice speaking" {
		t.Fatalf("alice's message: %v %q", err, released[0].Body)
	}

	if q.Len() != 1 {
		t.Fatalf("bob's message should still be held, queue has %d", q.Len())
	}

	// Then bob's.
	install(bob)
	released = q.ReleaseSender(n.gid, bob.id)
	if len(released) != 1 {
		t.Fatalf("expected 1 released for bob, got %d", len(released))
	}
	if err := carol.sm.DecryptGroupPacket(&released[0]); err != nil || string(released[0].Body) != "bob speaking" {
		t.Fatalf("bob's message: %v %q", err, released[0].Body)
	}

	if q.Len() != 0 {
		t.Fatalf("queue not drained: %d", q.Len())
	}
}

// Only recoverable failures are worth holding. A forgery must be dropped, or
// anyone in a conversation could fill the queue with garbage.
func TestForgeriesAreNotHeld(t *testing.T) {
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	convID := link(t, alice, bob)

	forged := seal(t, alice, convID, "tampered in flight")
	forged.Body[len(forged.Body)-1] ^= 0xFF

	err := bob.sm.DecryptPacket(&forged)
	if err == nil {
		t.Fatal("a tampered packet was accepted")
	}
	if Recoverable(err) {
		t.Fatalf("a tampered packet was classed as recoverable: %v", err)
	}
}
