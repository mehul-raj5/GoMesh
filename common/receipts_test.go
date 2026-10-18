package common

import "testing"

func TestReceiptRoundTrip(t *testing.T) {
	for _, want := range []Receipt{
		{MessageID: [16]byte{1}, ConversationID: [16]byte{2}, At: 1700000000123},
		{MessageID: [16]byte{3}, ConversationID: [16]byte{4}, Recipient: [16]byte{5}, Delivered: true, At: 42},
	} {
		p := want.Packet()
		if int(p.Header.BodyLen) != len(p.Body) {
			t.Fatalf("BodyLen %d, body %d bytes", p.Header.BodyLen, len(p.Body))
		}
		got, err := DecodeReceipt(p)
		if err != nil || got != want {
			t.Errorf("round trip of %+v gave %+v, %v", want, got, err)
		}
	}
}

func TestReceiptRejectsMalformedBodies(t *testing.T) {
	for _, p := range []Packet{
		{Header: Header{MsgType: CtrlMsgAccepted}, Body: make([]byte, 7)},
		{Header: Header{MsgType: CtrlMsgDelivered}, Body: make([]byte, 8)},
		{Header: Header{MsgType: CtrlMsgDelivered}, Body: make([]byte, 25)},
		{Header: Header{MsgType: MsgText}, Body: make([]byte, 8)},
	} {
		if _, err := DecodeReceipt(p); err == nil {
			t.Errorf("type %#x with a %d-byte body was accepted", p.Header.MsgType, len(p.Body))
		}
	}
}

func TestOnlyTheAcceptedReceiptIsAReply(t *testing.T) {
	if !IsReply(CtrlMsgAccepted) {
		t.Error("an accepted receipt is dropped, not requeued, when its connection never acknowledged it")
	}
	if IsReply(CtrlMsgDelivered) || IsReply(MsgReadReceipt) {
		t.Error("a delivered or read receipt must survive a dropped connection")
	}
}

func TestReceiptsRequestRoundTrip(t *testing.T) {
	p := ReceiptsRequest(-5)
	got, err := DecodeReceiptsRequest(p.Body)
	if err != nil || got != -5 {
		t.Errorf("got %d, %v", got, err)
	}
	if _, err := DecodeReceiptsRequest([]byte{1}); err == nil {
		t.Error("a short body was accepted")
	}
}

func TestReadReceiptBodyBounds(t *testing.T) {
	ids := [][16]byte{{1}, {2}, {3}}
	got, err := DecodeReadReceipt(EncodeReadReceipt(ids))
	if err != nil || len(got) != 3 || got[2] != ids[2] {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, body := range [][]byte{nil, make([]byte, 15), make([]byte, 17), make([]byte, (MaxReadReceiptIDs+1)*IDSize)} {
		if _, err := DecodeReadReceipt(body); err == nil {
			t.Errorf("a %d-byte body was accepted", len(body))
		}
	}
	if _, err := DecodeReadReceipt(make([]byte, MaxReadReceiptIDs*IDSize)); err != nil {
		t.Errorf("the largest allowed body was refused: %v", err)
	}
}
