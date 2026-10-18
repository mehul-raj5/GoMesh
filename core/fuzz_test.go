package core

import (
	common "common"
	"reflect"
	"testing"
)

// fuzzPeers builds a linked pair from fixed key material so a fuzz target does
// not spend its budget on key generation.
func fuzzPeers(t *testing.T) (peer, peer, [16]byte) {
	t.Helper()
	alice, bob := newPeer(t, 0x11), newPeer(t, 0x99)
	return alice, bob, link(t, alice, bob)
}

// DecryptPacket runs on a body the network chose, using a real session. It may
// reject anything it likes, but it must not panic and must not let a crafted
// counter run the ratchet past its bound.
func FuzzDecryptPacket(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Add(make([]byte, 4+common.NonceSize+16), uint16(0))
	f.Add(make([]byte, 128), uint16(common.FlagEncrypted))

	// A well-formed header, with and without handshake fields, over junk.
	plain := common.RatchetHeader{SenderEpoch: 1, RatchetPub: [32]byte{1}}
	f.Add(append(plain.Encode(), make([]byte, common.NonceSize+16)...), uint16(common.FlagEncrypted))
	withInit := common.RatchetHeader{SenderEpoch: 1, RatchetPub: [32]byte{1}, Init: &common.RatchetInit{IdentityKey: [32]byte{2}, Ephemeral: [32]byte{3}}}
	f.Add(append(withInit.Encode(), make([]byte, common.NonceSize+16)...), uint16(common.FlagEncrypted))

	f.Fuzz(func(t *testing.T, body []byte, flags uint16) {
		alice, bob, convID := fuzzPeers(t)
		_ = alice

		pkt := common.Packet{
			Header: common.Header{
				MsgType:        common.MsgText,
				ConversationID: convID,
				SenderID:       alice.id,
				Flags:          flags,
				BodyLen:        uint32(len(body)),
			},
			Body: append([]byte(nil), body...),
		}
		_ = bob.sm.DecryptPacket(&pkt)

		sess, ok := bob.sm.GetSession(convID)
		if !ok {
			t.Fatal("the session disappeared")
		}
		sess.mu.Lock()
		skipped := len(sess.st.Skipped)
		sess.mu.Unlock()
		if skipped > maxSkippedTotal {
			t.Fatalf("a crafted counter stored %d skipped keys, past the %d bound", skipped, maxSkippedTotal)
		}
	})
}

func FuzzDecryptGroupPacket(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Add(make([]byte, common.GroupHeaderLen+common.SignatureSize+common.NonceSize+16), uint16(common.FlagEncrypted))
	f.Add(make([]byte, 256), uint16(common.FlagEncrypted))

	f.Fuzz(func(t *testing.T, body []byte, flags uint16) {
		n := newGnet(t, 0x11, 0x22)
		a, b := n.peer(0x11), n.peer(0x22)
		n.create(a, b)
		n.send(a, "seed")
		n.pump(b)
		before := gstate(t, b, n.gid)

		pkt := common.Packet{
			Header: common.Header{
				MsgType:        common.MsgText,
				ConversationID: n.gid,
				SenderID:       a.id,
				Flags:          flags,
				BodyLen:        uint32(len(body)),
			},
			Body: append([]byte(nil), body...),
		}
		err := b.sm.DecryptGroupPacket(&pkt)

		after := gstate(t, b, n.gid)
		if err != nil && !reflect.DeepEqual(before.Peers, after.Peers) {
			t.Fatalf("a rejected message moved state: %v", err)
		}
		for _, p := range after.Peers {
			for _, k := range []*peerKey{p.Current, p.Previous} {
				if k != nil && len(k.Skipped) > maxGroupSkipped {
					t.Fatalf("%d skipped keys stored, past the %d bound", len(k.Skipped), maxGroupSkipped)
				}
			}
		}
	})
}

// Park takes packets straight off the wire, so a malformed one must not be able
// to break the queue's accounting or its bounds.
func FuzzPendingQueue(f *testing.F) {
	f.Add([]byte{}, byte(0), byte(0))
	f.Add([]byte("x"), byte(1), byte(2))

	f.Fuzz(func(t *testing.T, body []byte, convByte, senderByte byte) {
		q := newPendingQueue()
		conv, sender := groupID(convByte), groupID(senderByte)

		for i := 0; i < 5; i++ {
			q.Park(conv, heldPacket(conv, sender, string(body)))
		}
		q.ReleaseSender(conv, sender)
		q.Release(conv)

		q.mu.Lock()
		counted := 0
		for _, held := range q.byConv {
			counted += len(held)
		}
		total := q.total
		q.mu.Unlock()

		if counted != total {
			t.Fatalf("total says %d, actually holding %d", total, counted)
		}
		if total > maxPendingTotal {
			t.Fatalf("queue past its global cap: %d", total)
		}
	})
}
