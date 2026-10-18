package core

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

var (
	idAlice = [16]byte{1}
	idBob   = [16]byte{2}
	idCarol = [16]byte{3}
	idDave  = [16]byte{4}
)

func outgoing(recipients ...[16]byte) HistoryMessage {
	return HistoryMessage{Outgoing: true, MsgID: [16]byte{0xAA}, Recipients: recipients, Time: time.Now()}
}

// The ticks follow from who has been told what, and who is in the chat now.
func TestSettleWorksOutTheTicks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		m       HistoryMessage
		current [][16]byte
		want    Delivery
		counts  [3]int // delivered, read, total
	}{
		{"nothing heard", outgoing(idBob), nil, DeliveryPending, [3]int{0, 0, 1}},
		{"the server took it", func() HistoryMessage { m := outgoing(idBob); m.Accepted = true; return m }(), nil, DeliveryAccepted, [3]int{0, 0, 1}},
		{"delivered without the server's word", func() HistoryMessage { m := outgoing(idBob); m.Delivered = [][16]byte{idBob}; return m }(), nil, DeliveryDelivered, [3]int{1, 0, 1}},
		{"read implies delivered", func() HistoryMessage { m := outgoing(idBob); m.Read = [][16]byte{idBob}; return m }(), nil, DeliveryRead, [3]int{1, 1, 1}},
		{"one of two has it", func() HistoryMessage {
			m := outgoing(idBob, idCarol)
			m.Delivered = [][16]byte{idBob}
			return m
		}(), nil, DeliveryAccepted, [3]int{1, 0, 2}},
		{"both have it, one has read", func() HistoryMessage {
			m := outgoing(idBob, idCarol)
			m.Delivered = [][16]byte{idBob, idCarol}
			m.Read = [][16]byte{idBob}
			return m
		}(), nil, DeliveryDelivered, [3]int{2, 1, 2}},
		{"someone who left no longer counts", func() HistoryMessage {
			m := outgoing(idBob, idCarol)
			m.Delivered = [][16]byte{idBob}
			m.Read = [][16]byte{idBob}
			return m
		}(), [][16]byte{idAlice, idBob}, DeliveryRead, [3]int{1, 1, 1}},
		{"everyone left", func() HistoryMessage { m := outgoing(idCarol); m.Accepted = true; return m }(), [][16]byte{idAlice}, DeliveryAccepted, [3]int{0, 0, 0}},
		{"no recipients known", func() HistoryMessage { m := outgoing(); m.Accepted = true; return m }(), nil, DeliveryAccepted, [3]int{0, 0, 0}},
		{"still waiting to go", func() HistoryMessage { m := outgoing(idBob); m.Status = StatusQueued; m.Accepted = true; return m }(), nil, DeliveryPending, [3]int{0, 0, 0}},
		{"never went", func() HistoryMessage { m := outgoing(idBob); m.Status = StatusFailed; return m }(), nil, DeliveryPending, [3]int{0, 0, 0}},
		{"from before receipts", HistoryMessage{Outgoing: true}, nil, DeliveryAccepted, [3]int{0, 0, 0}},
		{"incoming", HistoryMessage{MsgID: [16]byte{1}}, nil, DeliveryPending, [3]int{0, 0, 0}},
	} {
		m := tc.m
		m.settle(tc.current)
		if m.Delivery != tc.want || [3]int{m.DeliveredCount, m.ReadCount, m.Total} != tc.counts {
			t.Errorf("%s: %v %d/%d/%d, want %v %v", tc.name, m.Delivery, m.DeliveredCount, m.ReadCount, m.Total, tc.want, tc.counts)
		}
	}
}

// Delivered and read count only from someone the message was for.
func TestReceiptsBindToTheRecipients(t *testing.T) {
	m := outgoing(idBob)
	if !m.apply(receiptAccepted, [16]byte{}) || !m.Accepted {
		t.Fatal("the server's word was not taken")
	}
	if m.apply(receiptRead, idDave) || len(m.Read) != 0 || len(m.Delivered) != 0 {
		t.Fatal("someone it was not for marked it read")
	}
	if !m.apply(receiptRead, idBob) || len(m.Read) != 1 || len(m.Delivered) != 1 {
		t.Fatalf("a recipient's read was not taken: %+v", m)
	}
	if m.apply(receiptRead, idBob) || m.apply(receiptDelivered, idBob) {
		t.Fatal("the same receipt changed a message twice")
	}
	in := HistoryMessage{Sender: idBob}
	if in.apply(receiptRead, idBob) {
		t.Fatal("a receipt marked an incoming message")
	}
}

func receiptClient(t *testing.T) *Client {
	t.Helper()
	freshDataDir(t)
	if err := tcl.openDevice(); err != nil {
		t.Fatal(err)
	}
	tcl.mgr = NewClientManager(idAlice, "alice")
	tcl.sessionMgr = NewSessionManager(tcl.idMgr, idAlice)
	if err := tcl.openHistory(idAlice, "alice"); err != nil {
		t.Fatal(err)
	}
	tcl.receipts = receiptState{}
	t.Cleanup(func() { tcl.hist.Close(); tcl.hist, tcl.myHistory = nil, nil; tcl.sink = nil; tcl.receipts = receiptState{} })
	return tcl
}

// The server can answer before the message has been kept; the answer waits.
func TestAReceiptThatBeatsTheMessageWaitsForIt(t *testing.T) {
	cl := receiptClient(t)
	conv := [16]byte{9}
	cl.mgr.RegisterConversation(conv, directPrefix+"bob", false)
	var events []Event
	cl.sink = func(ev Event) { events = append(events, ev) }

	id := [16]byte{0xAA}
	cl.applyReceipt(id, [16]byte{}, receiptAccepted)
	cl.applyReceipt(id, idBob, receiptDelivered)
	if len(events) != 0 {
		t.Fatalf("%d events about a message that is not there", len(events))
	}
	cl.recordSeq(conv, HistoryMessage{Outgoing: true, MsgID: id, Recipients: [][16]byte{idBob}, Time: time.Now()})

	msgs, err := cl.HistoryMessages(idAlice, conv, 0, 10)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("history: %+v %v", msgs, err)
	}
	if m := msgs[0]; m.Delivery != DeliveryDelivered || !m.Accepted || m.DeliveredCount != 1 {
		t.Fatalf("after the message was kept: %+v", m)
	}
	if len(events) == 0 || events[len(events)-1].Delivery != DeliveryDelivered {
		t.Fatalf("events: %+v", events)
	}
}

func TestWaitingReceiptsAreBoundedAndExpire(t *testing.T) {
	var rs receiptState
	for i := 0; i < maxEarlyReceipts+50; i++ {
		rs.stash([16]byte{byte(i), byte(i >> 8)}, receiptRead, idBob)
	}
	if rs.n != maxEarlyReceipts {
		t.Fatalf("%d waiting, want at most %d", rs.n, maxEarlyReceipts)
	}
	// Age every one past the limit; the next arrival clears them.
	for k, list := range rs.early {
		for i := range list {
			list[i].at = time.Now().Add(-2 * earlyReceiptTTL)
		}
		rs.early[k] = list
	}
	rs.stash([16]byte{0xFF, 0xFF}, receiptRead, idBob)
	if rs.n != 1 || len(rs.early) != 1 {
		t.Fatalf("%d waiting after expiry, in %d messages", rs.n, len(rs.early))
	}
	if got := rs.take([16]byte{0xFF, 0xFF}); len(got) != 1 || rs.n != 0 {
		t.Fatalf("took %d, %d left", len(got), rs.n)
	}
}

// An incoming message with the same ID is never marked, and a message from
// before receipts is never found.
func TestOnlyOutgoingMessagesTakeReceipts(t *testing.T) {
	h, dir := testHistory(t)
	a, err := historyFor(h, newMemVault(), filepath.Join(dir, mediaDirName), idAlice, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	conv := [16]byte{9}
	id := [16]byte{0xAA}
	a.append(conv, directPrefix+"bob", false, HistoryMessage{Sender: idBob, MsgID: id, Text: "incoming", Time: time.Now()})
	a.append(conv, directPrefix+"bob", false, HistoryMessage{Outgoing: true, Text: "old", Time: time.Now()})

	_, found, _, err := a.updateOutgoing(id, func(m *HistoryMessage) bool { return m.apply(receiptRead, idBob) })
	if err != nil || found {
		t.Fatalf("an incoming message counted as found: found=%v err=%v", found, err)
	}
	msgs, _ := a.messages(conv, 0, 10)
	if len(msgs[0].Read) != 0 || msgs[0].Accepted {
		t.Fatalf("an incoming message was changed: %+v", msgs[0])
	}
	if _, found, _, _ := a.updateOutgoing([16]byte{0xEE}, func(*HistoryMessage) bool { return true }); found {
		t.Fatal("a message nobody sent was found")
	}
}

// What was read is reported for incoming messages that carry an ID, and only
// those after the last report.
func TestUnreportedReadsAreOnlyIncomingMessagesWithAnID(t *testing.T) {
	h, dir := testHistory(t)
	a, err := historyFor(h, newMemVault(), filepath.Join(dir, mediaDirName), idAlice, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	conv := [16]byte{9}
	add := func(m HistoryMessage) {
		t.Helper()
		m.Time = time.Now()
		if _, err := a.append(conv, directPrefix+"bob", false, m); err != nil {
			t.Fatal(err)
		}
	}
	add(HistoryMessage{Sender: idBob, MsgID: [16]byte{1}, Text: "one"})
	add(HistoryMessage{Outgoing: true, MsgID: [16]byte{2}, Text: "mine"})
	add(HistoryMessage{Sender: idBob, Text: "from before receipts"})
	add(HistoryMessage{System: true, MsgID: [16]byte{3}, Text: "safety number"})
	add(HistoryMessage{Sender: idBob, MsgID: [16]byte{4}, Text: "two"})

	if w, s, _ := a.readState(conv); w != 0 || s != 0 {
		t.Fatalf("before reading: %d %d", w, s)
	}
	if err := a.markRead(conv); err != nil {
		t.Fatal(err)
	}
	wanted, sent, _ := a.readState(conv)
	if wanted != 5 || sent != 0 {
		t.Fatalf("after reading: wanted %d, sent %d", wanted, sent)
	}
	pending, _ := a.pendingReads()
	if len(pending) != 1 || pending[0] != conv {
		t.Fatalf("pending: %v", pending)
	}
	items, err := a.unreported(conv, sent, wanted)
	if err != nil || len(items) != 2 || items[0].id != [16]byte{1} || items[1].id != [16]byte{4} {
		t.Fatalf("unreported: %+v %v", items, err)
	}
	if err := a.setReadSent(conv, wanted); err != nil {
		t.Fatal(err)
	}
	if pending, _ := a.pendingReads(); len(pending) != 0 {
		t.Fatalf("still pending: %v", pending)
	}
	add(HistoryMessage{Sender: idBob, MsgID: [16]byte{5}, Text: "three"})
	a.markRead(conv)
	w, s, _ := a.readState(conv)
	items, _ = a.unreported(conv, s, w)
	if len(items) != 1 || items[0].id != [16]byte{5} {
		t.Fatalf("after another message: %+v", items)
	}
}

// A history made before receipts opens, gains the column, and keeps its rows.
func TestAnOlderHistoryGainsTheMessageIDColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), historyFile)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE conversations (tag BLOB PRIMARY KEY, sealed BLOB NOT NULL);
		CREATE TABLE messages (tag BLOB NOT NULL, seq INTEGER NOT NULL, sealed BLOB NOT NULL, PRIMARY KEY (tag, seq));
		INSERT INTO messages (tag, seq, sealed) VALUES (x'01', 1, x'02');`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	for i := 0; i < 2; i++ { // and opening it again is harmless
		h, err := openHistory(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		var n int
		if err := h.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE mid IS NULL`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("open %d: %d rows without an ID, %v", i, n, err)
		}
		h.Close()
	}
}

func TestTheReceiptMarkOnlyMovesForward(t *testing.T) {
	h, dir := testHistory(t)
	a, err := historyFor(h, newMemVault(), filepath.Join(dir, mediaDirName), idAlice, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := a.receiptMark(); err != nil || v != 0 {
		t.Fatalf("fresh: %d %v", v, err)
	}
	for _, at := range []int64{100, 300, 200} {
		if err := a.setReceiptMark(at); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := a.receiptMark(); v != 300 {
		t.Fatalf("mark %d, want 300", v)
	}
}
