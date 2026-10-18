package common

import (
	"encoding/binary"
	"fmt"
)

// A Receipt is the server's word on one message: that it took it, or that one
// recipient's device has handled it.
type Receipt struct {
	MessageID      [IDSize]byte
	ConversationID [IDSize]byte
	// Recipient is whose device handled the message. Zero for an accepted one.
	Recipient [IDSize]byte
	// Delivered is false for "the server took it" and true for "a device has it".
	Delivered bool
	// At is when it happened, in unix milliseconds, by the server's clock.
	At int64
}

// Packet is the receipt as the server sends it.
func (r Receipt) Packet() Packet {
	h := Header{MessageID: r.MessageID, ConversationID: r.ConversationID}
	var body []byte
	if r.Delivered {
		h.MsgType = CtrlMsgDelivered
		body = append(body, r.Recipient[:]...)
	} else {
		h.MsgType = CtrlMsgAccepted
	}
	body = binary.BigEndian.AppendUint64(body, uint64(r.At))
	h.BodyLen = uint32(len(body))
	return Packet{Header: h, Body: body}
}

// DecodeReceipt reads a CtrlMsgAccepted or CtrlMsgDelivered packet.
func DecodeReceipt(p Packet) (Receipt, error) {
	r := Receipt{MessageID: p.Header.MessageID, ConversationID: p.Header.ConversationID}
	switch p.Header.MsgType {
	case CtrlMsgAccepted:
		if len(p.Body) != 8 {
			return r, fmt.Errorf("accepted receipt: %d-byte body", len(p.Body))
		}
		r.At = int64(binary.BigEndian.Uint64(p.Body))
	case CtrlMsgDelivered:
		if len(p.Body) != IDSize+8 {
			return r, fmt.Errorf("delivered receipt: %d-byte body", len(p.Body))
		}
		r.Delivered = true
		copy(r.Recipient[:], p.Body[:IDSize])
		r.At = int64(binary.BigEndian.Uint64(p.Body[IDSize:]))
	default:
		return r, fmt.Errorf("packet type %#x is not a receipt", p.Header.MsgType)
	}
	return r, nil
}

// ReceiptsRequest asks the server for the receipts of this account's messages
// since a time, in unix milliseconds.
func ReceiptsRequest(since int64) Packet {
	body := binary.BigEndian.AppendUint64(nil, uint64(since))
	return Packet{Header: Header{MsgType: CtrlReceiptsRq, BodyLen: uint32(len(body))}, Body: body}
}

// DecodeReceiptsRequest reads the time from a CtrlReceiptsRq body.
func DecodeReceiptsRequest(body []byte) (int64, error) {
	if len(body) != 8 {
		return 0, fmt.Errorf("receipts request: %d-byte body", len(body))
	}
	return int64(binary.BigEndian.Uint64(body)), nil
}

// MaxReadReceiptIDs bounds how many messages one MsgReadReceipt names, so a
// peer cannot make a client do unbounded work with one packet.
const MaxReadReceiptIDs = 256

// EncodeReadReceipt is the body of a MsgReadReceipt: the IDs of the messages read.
func EncodeReadReceipt(ids [][IDSize]byte) []byte {
	body := make([]byte, 0, len(ids)*IDSize)
	for _, id := range ids {
		body = append(body, id[:]...)
	}
	return body
}

// DecodeReadReceipt reads the message IDs from a MsgReadReceipt body.
func DecodeReadReceipt(body []byte) ([][IDSize]byte, error) {
	if len(body) == 0 || len(body)%IDSize != 0 || len(body)/IDSize > MaxReadReceiptIDs {
		return nil, fmt.Errorf("read receipt: %d-byte body", len(body))
	}
	ids := make([][IDSize]byte, len(body)/IDSize)
	for i := range ids {
		copy(ids[i][:], body[i*IDSize:])
	}
	return ids, nil
}
