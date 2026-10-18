package core

import (
	common "common"
	"sync"
	"testing"
	"time"
)

func heldPacket(convID, senderID [16]byte, text string) common.Packet {
	return common.Packet{
		Header: common.Header{
			MsgType:        common.MsgText,
			ConversationID: convID,
			SenderID:       senderID,
			BodyLen:        uint32(len(text)),
		},
		Body: []byte(text),
	}
}

func texts(pkts []common.Packet) []string {
	out := make([]string, 0, len(pkts))
	for _, p := range pkts {
		out = append(out, string(p.Body))
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestReleaseReturnsPacketsInArrivalOrder(t *testing.T) {
	q := newPendingQueue()
	conv, sender := groupID(0xAA), groupID(0x11)

	for _, s := range []string{"first", "second", "third"} {
		q.Park(conv, heldPacket(conv, sender, s))
	}
	if q.Len() != 3 {
		t.Fatalf("expected 3 held, got %d", q.Len())
	}

	got := texts(q.Release(conv))
	if want := []string{"first", "second", "third"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if q.Len() != 0 {
		t.Fatalf("release left %d packets behind", q.Len())
	}
	if len(q.Release(conv)) != 0 {
		t.Fatal("second release returned packets again")
	}
}

// A sender key unblocks only its own sender, so everyone else stays held.
func TestReleaseSenderLeavesOtherSendersHeld(t *testing.T) {
	q := newPendingQueue()
	conv := groupID(0xAA)
	alice, bob := groupID(0x11), groupID(0x55)

	q.Park(conv, heldPacket(conv, alice, "a1"))
	q.Park(conv, heldPacket(conv, bob, "b1"))
	q.Park(conv, heldPacket(conv, alice, "a2"))

	got := texts(q.ReleaseSender(conv, alice))
	if want := []string{"a1", "a2"}; !equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if q.Len() != 1 {
		t.Fatalf("expected bob's packet still held, have %d", q.Len())
	}

	if got := texts(q.ReleaseSender(conv, bob)); !equal(got, []string{"b1"}) {
		t.Fatalf("bob: got %v", got)
	}
	if q.Len() != 0 {
		t.Fatalf("queue not drained: %d", q.Len())
	}
}

func TestReleaseIsScopedToOneConversation(t *testing.T) {
	q := newPendingQueue()
	convA, convB := groupID(0xAA), groupID(0xBB)
	sender := groupID(0x11)

	q.Park(convA, heldPacket(convA, sender, "a"))
	q.Park(convB, heldPacket(convB, sender, "b"))

	if got := texts(q.Release(convA)); !equal(got, []string{"a"}) {
		t.Fatalf("got %v", got)
	}
	if q.Len() != 1 {
		t.Fatalf("other conversation was disturbed: %d held", q.Len())
	}
}

// One conversation must not be able to crowd out the rest.
func TestPerConversationCapKeepsNewest(t *testing.T) {
	q := newPendingQueue()
	conv, sender := groupID(0xAA), groupID(0x11)

	for i := 0; i < maxPendingPerConv+10; i++ {
		q.Park(conv, heldPacket(conv, sender, string(rune('a'+i%26))))
	}
	if q.Len() != maxPendingPerConv {
		t.Fatalf("expected the cap of %d, holding %d", maxPendingPerConv, q.Len())
	}
	if got := len(q.Release(conv)); got != maxPendingPerConv {
		t.Fatalf("released %d, expected %d", got, maxPendingPerConv)
	}
}

func TestGlobalCapBoundsTheQueue(t *testing.T) {
	q := newPendingQueue()
	sender := groupID(0x11)

	// Spread across enough conversations that the per-conversation cap alone
	// would allow far more than the global limit.
	for c := 0; c < 40; c++ {
		conv := groupID(byte(c))
		for i := 0; i < 30; i++ {
			q.Park(conv, heldPacket(conv, sender, "x"))
		}
	}
	if q.Len() > maxPendingTotal {
		t.Fatalf("queue grew past the global cap: %d > %d", q.Len(), maxPendingTotal)
	}
}

func TestExpiredPacketsAreNotReplayed(t *testing.T) {
	q := newPendingQueue()
	conv, sender := groupID(0xAA), groupID(0x11)

	q.mu.Lock()
	q.byConv[conv] = []pendingPacket{
		{pkt: heldPacket(conv, sender, "stale"), parkedAt: time.Now().Add(-2 * pendingTTL)},
		{pkt: heldPacket(conv, sender, "fresh"), parkedAt: time.Now()},
	}
	q.total = 2
	q.mu.Unlock()

	if got := texts(q.Release(conv)); !equal(got, []string{"fresh"}) {
		t.Fatalf("got %v, expected the stale packet to be dropped", got)
	}
	if q.Len() != 0 {
		t.Fatalf("accounting drifted: %d held after release", q.Len())
	}
}

// Parking sweeps, so a conversation nobody ever resolves does not linger.
func TestParkSweepsExpiredEntries(t *testing.T) {
	q := newPendingQueue()
	stale, live := groupID(0xAA), groupID(0xBB)
	sender := groupID(0x11)

	q.mu.Lock()
	q.byConv[stale] = []pendingPacket{
		{pkt: heldPacket(stale, sender, "old"), parkedAt: time.Now().Add(-2 * pendingTTL)},
	}
	q.total = 1
	q.mu.Unlock()

	q.Park(live, heldPacket(live, sender, "new"))

	if q.Len() != 1 {
		t.Fatalf("expected only the new packet, holding %d", q.Len())
	}
	if len(q.Release(stale)) != 0 {
		t.Fatal("the expired conversation survived the sweep")
	}
}

func TestReleasingAnUnknownConversationIsHarmless(t *testing.T) {
	q := newPendingQueue()
	if got := q.Release(groupID(0xCC)); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
	if got := q.ReleaseSender(groupID(0xCC), groupID(0x11)); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

// The counter backs the caps, so it has to stay honest across every path.
func TestTotalStaysConsistent(t *testing.T) {
	q := newPendingQueue()
	convA, convB := groupID(0xAA), groupID(0xBB)
	alice, bob := groupID(0x11), groupID(0x55)

	q.Park(convA, heldPacket(convA, alice, "1"))
	q.Park(convA, heldPacket(convA, bob, "2"))
	q.Park(convB, heldPacket(convB, alice, "3"))

	q.ReleaseSender(convA, alice)
	q.Release(convB)

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
	if total != 1 {
		t.Fatalf("expected bob's packet alone, total is %d", total)
	}
}

// readLoop parks, and release happens from packet handlers that may run
// concurrently with it, so the queue has to hold up under both at once.
func TestConcurrentParkAndRelease(t *testing.T) {
	q := newPendingQueue()
	sender := groupID(0x11)

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			conv := groupID(byte(w % 4))
			for i := 0; i < 200; i++ {
				q.Park(conv, heldPacket(conv, sender, "x"))
				if i%10 == 0 {
					q.Release(conv)
					q.ReleaseSender(conv, sender)
				}
				q.Len()
			}
		}(w)
	}
	wg.Wait()

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
}
