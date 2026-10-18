package main

import (
	common "common"
	"net"
	"testing"
	"time"
)

// sendMsg sends a text message with an ID, as a client does, and returns the ID.
func sendMsg(t *testing.T, c net.Conn, convID [16]byte, n byte, body string) [16]byte {
	t.Helper()
	id := [16]byte{0xAA, n}
	pkt := common.Packet{
		Header: common.Header{MsgType: common.MsgText, ConversationID: convID, MessageID: id, Flags: common.FlagEncrypted, BodyLen: uint32(len(body))},
		Body:   []byte(body),
	}
	if err := pkt.Encode(c); err != nil {
		t.Fatalf("send: %v", err)
	}
	return id
}

// readReceipt waits for a receipt of a type and decodes it.
func readReceipt(t *testing.T, c net.Conn, msgType uint8) common.Receipt {
	t.Helper()
	r, err := common.DecodeReceipt(readUntil(t, c, msgType, 3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTheSenderIsToldTheServerTookTheMessage(t *testing.T) {
	_, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")

	id := sendMsg(t, alice.conn, convID, 1, "hi")
	r := readReceipt(t, alice.conn, common.CtrlMsgAccepted)
	if r.MessageID != id || r.ConversationID != convID || r.Delivered || r.At == 0 {
		t.Fatalf("accepted receipt %+v for message %x", r, id)
	}
}

func TestDeliveredIsReportedWhenTheRecipientsDeviceHandlesIt(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")

	id := sendMsg(t, alice.conn, convID, 1, "hi")
	readReceipt(t, alice.conn, common.CtrlMsgAccepted)
	readUntil(t, bob.conn, common.MsgText, 3*time.Second)
	// Read but not acknowledged: the device may yet lose it.
	expectNo(t, alice.conn, common.CtrlMsgDelivered, 300*time.Millisecond)

	acknowledge(t, srv, bob)
	r := readReceipt(t, alice.conn, common.CtrlMsgDelivered)
	if r.MessageID != id || r.Recipient != bob.id || !r.Delivered || r.ConversationID != convID {
		t.Fatalf("delivered receipt %+v", r)
	}
}

func TestAnOfflineRecipientIsReportedWhenItComesBack(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")
	dropConn(t, srv, bob)

	id := sendMsg(t, alice.conn, convID, 1, "while you were out")
	readReceipt(t, alice.conn, common.CtrlMsgAccepted)
	expectNo(t, alice.conn, common.CtrlMsgDelivered, 300*time.Millisecond)

	relogin(t, addr, bob)
	readUntil(t, bob.conn, common.MsgText, 3*time.Second)
	acknowledge(t, srv, bob)
	if r := readReceipt(t, alice.conn, common.CtrlMsgDelivered); r.MessageID != id || r.Recipient != bob.id {
		t.Fatalf("delivered receipt %+v", r)
	}
}

func TestASenderThatIsOfflineGetsTheReceiptWhenItReturns(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")

	id := sendMsg(t, alice.conn, convID, 1, "hi")
	readReceipt(t, alice.conn, common.CtrlMsgAccepted)
	dropConn(t, srv, alice)

	readUntil(t, bob.conn, common.MsgText, 3*time.Second)
	acknowledge(t, srv, bob)

	relogin(t, addr, alice)
	if r := readReceipt(t, alice.conn, common.CtrlMsgDelivered); r.MessageID != id || r.Recipient != bob.id {
		t.Fatalf("delivered receipt %+v", r)
	}
}

func TestAPacketDeliveredTwiceIsReportedOnce(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")

	sendMsg(t, alice.conn, convID, 1, "hi")
	readUntil(t, bob.conn, common.MsgText, 3*time.Second)
	// Dropped before the acknowledgement: the packet comes again.
	dropConn(t, srv, bob)
	relogin(t, addr, bob)
	readUntil(t, bob.conn, common.MsgText, 3*time.Second)
	acknowledge(t, srv, bob)
	readReceipt(t, alice.conn, common.CtrlMsgDelivered)

	// A later acknowledgement of the same packet on a new connection changes nothing.
	for _, p := range []common.Packet{common.DeliveredPacket(1)} {
		p.Encode(bob.conn)
	}
	expectNo(t, alice.conn, common.CtrlMsgDelivered, 300*time.Millisecond)
	if n := receiptRows(t, srv.store); n != 1 {
		t.Fatalf("%d receipt rows, want 1", n)
	}
}

func TestEveryMemberOfAGroupIsReportedSeparately(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	carol := newUser(t, addr, "carol", 3)
	g := createGroup(t, alice, "trio", bob, carol)

	id := sendMsg(t, alice.conn, g.id, 1, "hello all")
	readReceipt(t, alice.conn, common.CtrlMsgAccepted)
	for _, u := range []*user{bob, carol} {
		readUntil(t, u.conn, common.MsgText, 3*time.Second)
	}
	acknowledge(t, srv, bob)
	first := readReceipt(t, alice.conn, common.CtrlMsgDelivered)
	acknowledge(t, srv, carol)
	second := readReceipt(t, alice.conn, common.CtrlMsgDelivered)
	got := map[[16]byte]bool{first.Recipient: true, second.Recipient: true}
	if len(got) != 2 || !got[bob.id] || !got[carol.id] || first.MessageID != id || second.MessageID != id {
		t.Fatalf("receipts %+v and %+v", first, second)
	}
	if got[alice.id] {
		t.Fatal("the sender was reported as a recipient of its own message")
	}
}

func TestAReadReceiptIsRelayedInADirectChatAndCausesNoReceipt(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")

	body := common.EncodeReadReceipt([][16]byte{{0xAA, 1}})
	pkt := common.Packet{
		Header: common.Header{MsgType: common.MsgReadReceipt, ConversationID: convID, MessageID: [16]byte{0xBB}, Flags: common.FlagEncrypted, BodyLen: uint32(len(body))},
		Body:   body,
	}
	if err := pkt.Encode(bob.conn); err != nil {
		t.Fatal(err)
	}
	got := readUntil(t, alice.conn, common.MsgReadReceipt, 3*time.Second)
	if got.Header.SenderID != bob.id || string(got.Body) != string(body) {
		t.Fatalf("relayed %+v", got.Header)
	}
	acknowledge(t, srv, alice)
	expectNo(t, bob.conn, common.CtrlMsgAccepted, 300*time.Millisecond)
	expectNo(t, bob.conn, common.CtrlMsgDelivered, 300*time.Millisecond)
	if n := receiptRows(t, srv.store); n != 0 {
		t.Fatalf("a read receipt left %d receipt row(s)", n)
	}
}

func TestAReadReceiptIsNeverFannedOutToAGroup(t *testing.T) {
	_, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	carol := newUser(t, addr, "carol", 3)
	g := createGroup(t, alice, "trio", bob, carol)

	body := common.EncodeReadReceipt([][16]byte{{0xAA, 1}})
	pkt := common.Packet{
		Header: common.Header{MsgType: common.MsgReadReceipt, ConversationID: g.id, Flags: common.FlagEncrypted, BodyLen: uint32(len(body))},
		Body:   body,
	}
	if err := pkt.Encode(bob.conn); err != nil {
		t.Fatal(err)
	}
	expectNo(t, alice.conn, common.MsgReadReceipt, 300*time.Millisecond)
	expectNo(t, carol.conn, common.MsgReadReceipt, 300*time.Millisecond)
}

func TestANonMemberGetsNoReceiptAndLeavesNoRecord(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	newUser(t, addr, "bob", 2)
	mallory := newUser(t, addr, "mallory", 3)
	convID, _ := openDM(t, alice.conn, "bob")

	sendMsg(t, mallory.conn, convID, 9, "let me in")
	expectNo(t, mallory.conn, common.CtrlMsgAccepted, 300*time.Millisecond)
	if n := receiptRows(t, srv.store); n != 0 {
		t.Fatalf("%d receipt rows for a message from a non-member", n)
	}
}

func TestAskingForReceiptsAgainReturnsWhatWasMissed(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")

	before := time.Now().UnixMilli() - 1
	id := sendMsg(t, alice.conn, convID, 1, "hi")
	readReceipt(t, alice.conn, common.CtrlMsgAccepted)
	readUntil(t, bob.conn, common.MsgText, 3*time.Second)
	acknowledge(t, srv, bob)
	readReceipt(t, alice.conn, common.CtrlMsgDelivered)

	// Alice lost both, say: she asks, and is told again.
	rq := common.ReceiptsRequest(before)
	if err := rq.Encode(alice.conn); err != nil {
		t.Fatal(err)
	}
	if r := readReceipt(t, alice.conn, common.CtrlMsgAccepted); r.MessageID != id {
		t.Fatalf("accepted again: %+v", r)
	}
	if r := readReceipt(t, alice.conn, common.CtrlMsgDelivered); r.MessageID != id || r.Recipient != bob.id {
		t.Fatalf("delivered again: %+v", r)
	}

	// Bob has no messages of his own, and a request for the future finds nothing.
	rq = common.ReceiptsRequest(time.Now().UnixMilli() + 60_000)
	rq.Encode(alice.conn)
	expectNo(t, alice.conn, common.CtrlMsgAccepted, 300*time.Millisecond)
	rq = common.ReceiptsRequest(0)
	rq.Encode(bob.conn)
	expectNo(t, bob.conn, common.CtrlMsgAccepted, 300*time.Millisecond)
}

func TestOldReceiptRecordsArePruned(t *testing.T) {
	st, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sender, recipient, conv := [16]byte{1}, [16]byte{2}, [16]byte{3}
	old, fresh := [16]byte{4}, [16]byte{5}
	if err := st.RecordAccepted(old, conv, sender, [][16]byte{recipient}, 1000); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAccepted(fresh, conv, sender, [][16]byte{recipient}, 5000); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneReceipts(3000); err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	if _, _, _, found, _ := st.MarkDelivered(old, recipient, 6000); found {
		t.Error("a pruned record was still found")
	}
	if _, _, first, found, _ := st.MarkDelivered(fresh, recipient, 6000); !found || !first {
		t.Error("the fresh record was lost")
	}
}

func receiptRows(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM msg_receipts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A sender catching up on far more receipts than its connection buffers is
// served in turn, not disconnected as a stalled reader.
func TestACatchUpLargerThanTheBufferIsServedInFull(t *testing.T) {
	_, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")

	const n = 300
	for i := 0; i < n; i++ {
		pkt := common.Packet{
			Header: common.Header{MsgType: common.MsgText, ConversationID: convID, MessageID: [16]byte{0xCC, byte(i), byte(i >> 8)}, Flags: common.FlagEncrypted, BodyLen: 1},
			Body:   []byte("x"),
		}
		if err := pkt.Encode(alice.conn); err != nil {
			t.Fatal(err)
		}
	}
	// Alice reads none of the live replies, then asks again.
	time.Sleep(300 * time.Millisecond)
	rq := common.ReceiptsRequest(0)
	if err := rq.Encode(alice.conn); err != nil {
		t.Fatal(err)
	}
	seen := map[[16]byte]bool{}
	deadline := time.Now().Add(10 * time.Second)
	for len(seen) < n && time.Now().Before(deadline) {
		alice.conn.SetReadDeadline(deadline)
		p, err := decode(alice.conn)
		if err != nil {
			t.Fatalf("after %d distinct receipts: %v", len(seen), err)
		}
		if p.Header.MsgType == common.CtrlMsgAccepted {
			seen[p.Header.MessageID] = true
		}
	}
	if len(seen) != n {
		t.Fatalf("%d of %d receipts", len(seen), n)
	}
}
