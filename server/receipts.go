package main

import (
	common "common"
	"database/sql"
	"log"
	"sync/atomic"
	"time"
)

// receiptRetention is how long the server remembers a message for receipts. A
// sender offline for longer than this loses the ticks of what it sent before,
// not the messages.
const receiptRetention = 14 * 24 * time.Hour

// receiptsPerRequest bounds what one CtrlReceiptsRq is answered with.
const receiptsPerRequest = 2000

// receiptRow is one recipient's standing on one message.
type receiptRow struct {
	MsgID       [common.IDSize]byte
	Recipient   [common.IDSize]byte
	ConvID      [common.IDSize]byte
	Sender      [common.IDSize]byte
	AcceptedAt  int64
	DeliveredAt int64 // 0 until the recipient's device has handled it
}

var acceptCount atomic.Uint64

// RecordAccepted notes that the server took a message for these recipients.
// A message seen again keeps its first record.
func (st *Store) RecordAccepted(msgID, convID, sender [common.IDSize]byte, recipients [][common.IDSize]byte, at int64) error {
	err := st.tx(func(tx *sql.Tx) error {
		for _, r := range recipients {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO msg_receipts (msg_id, recipient, conv_id, sender, accepted_at)
				VALUES (?, ?, ?, ?, ?)`, msgID[:], r[:], convID[:], sender[:], at); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil && acceptCount.Add(1)%500 == 0 {
		// Often enough that the table stays near two weeks of traffic, rarely
		// enough to cost nothing.
		if n, perr := st.PruneReceipts(time.Now().Add(-receiptRetention).UnixMilli()); perr != nil {
			log.Printf("[ERROR] could not prune receipts: %v", perr)
		} else if n > 0 {
			log.Printf("Pruned %d receipt record(s) older than %v", n, receiptRetention)
		}
	}
	return err
}

// MarkDelivered notes that a recipient's device handled a message. first is
// true only the first time, so a packet delivered again after a dropped
// connection is not reported twice. found is false for a message the server has
// no record of, which it cannot report on.
func (st *Store) MarkDelivered(msgID, recipient [common.IDSize]byte, at int64) (sender, convID [common.IDSize]byte, first, found bool, err error) {
	err = st.tx(func(tx *sql.Tx) error {
		var s, c []byte
		var was int64
		err := tx.QueryRow(`SELECT sender, conv_id, delivered_at FROM msg_receipts WHERE msg_id = ? AND recipient = ?`,
			msgID[:], recipient[:]).Scan(&s, &c, &was)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		copy(sender[:], s)
		copy(convID[:], c)
		if was != 0 {
			return nil
		}
		first = true
		_, err = tx.Exec(`UPDATE msg_receipts SET delivered_at = ? WHERE msg_id = ? AND recipient = ?`, at, msgID[:], recipient[:])
		return err
	})
	return
}

// ReceiptsSince returns the records of one sender's messages taken at or after
// a time, oldest first, at most limit of them.
func (st *Store) ReceiptsSince(sender [common.IDSize]byte, since int64, limit int) ([]receiptRow, error) {
	rows, err := st.db.Query(`SELECT msg_id, recipient, conv_id, accepted_at, delivered_at FROM msg_receipts
		WHERE sender = ? AND accepted_at >= ? ORDER BY accepted_at LIMIT ?`, sender[:], since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []receiptRow
	for rows.Next() {
		r := receiptRow{Sender: sender}
		var m, rc, c []byte
		if err := rows.Scan(&m, &rc, &c, &r.AcceptedAt, &r.DeliveredAt); err != nil {
			return nil, err
		}
		copy(r.MsgID[:], m)
		copy(r.Recipient[:], rc)
		copy(r.ConvID[:], c)
		out = append(out, r)
	}
	return out, rows.Err()
}

// PruneReceipts deletes records of messages taken before a time.
func (st *Store) PruneReceipts(before int64) (int64, error) {
	res, err := st.db.Exec(`DELETE FROM msg_receipts WHERE accepted_at < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// hasReceipts reports whether a packet is one the sender is told about: a
// message, not a control packet, and above all not a receipt, so a receipt can
// never cause one.
func hasReceipts(msgType uint8) bool {
	return msgType == common.MsgText || msgType == common.MsgMediaMeta
}

// reportAccepted tells a sender the server took its message, and remembers it
// for the recipients.
func (s *Server) reportAccepted(sender *Client, p common.Packet, recipients [][common.IDSize]byte) {
	at := time.Now().UnixMilli()
	if s.store != nil {
		if err := s.store.RecordAccepted(p.Header.MessageID, p.Header.ConversationID, sender.UserID, recipients, at); err != nil {
			log.Printf("[ERROR] could not record a receipt for %x: %v", p.Header.MessageID[:4], err)
		}
	}
	s.sendReply(sender, common.Receipt{MessageID: p.Header.MessageID, ConversationID: p.Header.ConversationID, At: at}.Packet())
}

// sendReply hands a reply to a connection that is reading, and drops it if the
// connection has fallen behind: a sender that sends without reading must not be
// disconnected for what the server says back, and it can ask again with
// CtrlReceiptsRq.
func (s *Server) sendReply(to *Client, p common.Packet) {
	to.enqueue(p)
}

// reportDelivered tells a sender that a recipient's device handled its message.
// Who the sender is comes from the server's own record of taking the message,
// not from the packet the recipient was handed.
func (s *Server) reportDelivered(recipient [common.IDSize]byte, p common.Packet) {
	at := time.Now().UnixMilli()
	sender, convID := p.Header.SenderID, p.Header.ConversationID
	if s.store != nil {
		var first, found bool
		var err error
		sender, convID, first, found, err = s.store.MarkDelivered(p.Header.MessageID, recipient, at)
		if err != nil {
			log.Printf("[ERROR] could not record a delivery of %x: %v", p.Header.MessageID[:4], err)
			return
		}
		if !found || !first {
			return
		}
	}
	s.sendPacket(sender, common.Receipt{
		MessageID: p.Header.MessageID, ConversationID: convID, Recipient: recipient, Delivered: true, At: at,
	}.Packet())
}

// handleReceiptsRq answers a sender that wants the receipts it may have missed.
func (s *Server) handleReceiptsRq(client *Client, p common.Packet) {
	since, err := common.DecodeReceiptsRequest(p.Body)
	if err != nil {
		log.Printf("[WARNING] %s (%x): %v", client.Username, client.UserID[:4], err)
		return
	}
	if s.store == nil {
		return
	}
	if floor := time.Now().Add(-receiptRetention).UnixMilli(); since < floor {
		since = floor
	}
	rows, err := s.store.ReceiptsSince(client.UserID, since, receiptsPerRequest)
	if err != nil {
		log.Printf("[ERROR] could not read receipts for %s: %v", client.Username, err)
		return
	}
	var out []common.Packet
	for _, r := range rows {
		out = append(out, common.Receipt{MessageID: r.MsgID, ConversationID: r.ConvID, At: r.AcceptedAt}.Packet())
		if r.DeliveredAt != 0 {
			out = append(out, common.Receipt{
				MessageID: r.MsgID, ConversationID: r.ConvID, Recipient: r.Recipient, Delivered: true, At: r.DeliveredAt,
			}.Packet())
		}
	}
	go s.sendPaced(client, out)
}

// sendPaced hands a long run of packets to a connection as fast as it takes
// them, rather than all at once: the connection's buffer is small, and a client
// that is simply catching up must not be treated as one that has stalled. It
// gives up when the connection ends, or after a minute.
func (s *Server) sendPaced(to *Client, packets []common.Packet) {
	deadline := time.Now().Add(time.Minute)
	for _, p := range packets {
		for !to.enqueue(p) {
			select {
			case <-to.done:
				return
			case <-time.After(5 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				return
			}
		}
	}
}
