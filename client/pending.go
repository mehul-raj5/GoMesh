package main

import (
	common "common"
	"sync"
	"time"
)

// Bounds on held traffic. Anything parked is memory that arrived unsolicited,
// so the queue is capped twice over and swept by age: a peer that goes quiet
// forever, or a member spraying packets nobody can open, must not be able to
// grow it without limit.
const (
	maxPendingPerConv = 64
	maxPendingTotal   = 512
	pendingTTL        = 30 * time.Second
)

// pendingPacket is one held packet and when it was set aside.
type pendingPacket struct {
	pkt      common.Packet
	parkedAt time.Time
	// ttl is how long this packet may wait. Zero means pendingTTL; group messages
	// wait for a sender key or a membership change that can take far longer.
	ttl time.Duration
}

func (p pendingPacket) expired(now time.Time) bool {
	ttl := p.ttl
	if ttl == 0 {
		ttl = pendingTTL
	}
	return p.parkedAt.Before(now.Add(-ttl))
}

// pendingQueue holds packets that could not be decrypted yet because the key
// for them has not arrived, and hands them back when it does.
//
// Only recoverable failures belong here. A packet that failed its tag check is
// never going to open, and parking those would let anyone fill the queue with
// garbage; the caller decides using the sentinel errors from session.go.
type pendingQueue struct {
	mu     sync.Mutex
	byConv map[[16]byte][]pendingPacket
	total  int
}

// pending is the client's single queue, sized and swept by the constants above.
var pending = newPendingQueue()

func newPendingQueue() *pendingQueue {
	return &pendingQueue{byConv: make(map[[16]byte][]pendingPacket)}
}

// Park holds a packet until the key for it arrives. It reports whether the
// packet was kept; a false return means the queue was full of newer traffic.
//
// Re-parking a packet that a release could not open restarts its clock. The
// count caps are what actually bound the queue; the TTL only clears out
// conversations that have gone quiet.
func (q *pendingQueue) Park(convID [16]byte, pkt common.Packet) bool {
	return q.ParkFor(convID, pkt, pendingTTL)
}

// ParkFor is Park with a lifetime for the packet other than the default.
func (q *pendingQueue) ParkFor(convID [16]byte, pkt common.Packet, ttl time.Duration) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.sweepLocked(time.Now())

	held := q.byConv[convID]
	if len(held) >= maxPendingPerConv {
		// Keep the newest: whatever is blocking this conversation is more
		// likely to be resolved for recent traffic than for a long backlog.
		q.total -= len(held) - (maxPendingPerConv - 1)
		held = append([]pendingPacket(nil), held[len(held)-(maxPendingPerConv-1):]...)
	}

	q.byConv[convID] = append(held, pendingPacket{pkt: pkt, parkedAt: time.Now(), ttl: ttl})
	q.total++

	for q.total > maxPendingTotal {
		if !q.evictOldestLocked() {
			break
		}
	}
	return true
}

// Release returns every packet held for a conversation, in arrival order, and
// forgets them. Used once a session or a roster has arrived.
func (q *pendingQueue) Release(convID [16]byte) []common.Packet {
	return q.release(convID, nil)
}

// ReleaseSender returns only the packets a given member sent. Used when one
// member's sender key arrives, which unblocks nothing else.
func (q *pendingQueue) ReleaseSender(convID, senderID [16]byte) []common.Packet {
	return q.release(convID, &senderID)
}

func (q *pendingQueue) release(convID [16]byte, senderID *[16]byte) []common.Packet {
	q.mu.Lock()
	defer q.mu.Unlock()

	held, ok := q.byConv[convID]
	if !ok {
		return nil
	}

	now := time.Now()
	var out []common.Packet
	kept := held[:0]

	for _, p := range held {
		switch {
		case p.expired(now):
			q.total-- // too old to be worth replaying
		case senderID != nil && p.pkt.Header.SenderID != *senderID:
			kept = append(kept, p)
		default:
			out = append(out, p.pkt)
			q.total--
		}
	}

	if len(kept) == 0 {
		delete(q.byConv, convID)
	} else {
		q.byConv[convID] = kept
	}
	return out
}

// sweepLocked drops everything past its TTL.
func (q *pendingQueue) sweepLocked(now time.Time) {
	for convID, held := range q.byConv {
		kept := held[:0]
		for _, p := range held {
			if p.expired(now) {
				q.total--
				continue
			}
			kept = append(kept, p)
		}
		if len(kept) == 0 {
			delete(q.byConv, convID)
		} else {
			q.byConv[convID] = kept
		}
	}
}

// evictOldestLocked drops one packet from the conversation holding the most, so
// that the noisiest conversation is the one that pays. Reports whether anything
// was dropped.
func (q *pendingQueue) evictOldestLocked() bool {
	var target [16]byte
	longest := 0
	for convID, held := range q.byConv {
		if len(held) > longest {
			target, longest = convID, len(held)
		}
	}
	if longest == 0 {
		return false
	}

	held := q.byConv[target]
	if len(held) == 1 {
		delete(q.byConv, target)
	} else {
		q.byConv[target] = held[1:]
	}
	q.total--
	return true
}

// Len reports how many packets are currently held.
func (q *pendingQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.total
}
