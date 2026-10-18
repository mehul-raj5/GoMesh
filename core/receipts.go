package core

import (
	common "common"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"
)

// Receipts tell the sender of a message how far it got. The server says it took
// the message and, for each recipient, that the recipient's device has it; the
// recipient says, end to end, that they have read it. The sender keeps all of it
// with the message, as sets of people, and works out the ticks from them and
// from who is in the chat now.

// Delivery is how far an outgoing message has got.
type Delivery int

const (
	// DeliveryPending: the server has not said it took the message.
	DeliveryPending Delivery = iota
	// DeliveryAccepted: the server took it; not everyone's device has it yet.
	DeliveryAccepted
	// DeliveryDelivered: every recipient's device has it.
	DeliveryDelivered
	// DeliveryRead: every recipient has read it.
	DeliveryRead
)

func (d Delivery) String() string {
	switch d {
	case DeliveryAccepted:
		return "accepted"
	case DeliveryDelivered:
		return "delivered"
	case DeliveryRead:
		return "read"
	default:
		return "pending"
	}
}

type receiptKind int

const (
	receiptAccepted receiptKind = iota
	receiptDelivered
	receiptRead
)

// apply records a receipt and reports whether it changed anything. Delivered
// and read only count from someone the message was for: a read receipt names
// no more than IDs, so who sent it is what binds it.
func (m *HistoryMessage) apply(kind receiptKind, who [16]byte) bool {
	if !m.Outgoing || m.System {
		return false
	}
	changed := false
	if !m.Accepted {
		m.Accepted, changed = true, true
	}
	if kind == receiptAccepted || !slices.Contains(m.Recipients, who) {
		return changed
	}
	if !slices.Contains(m.Delivered, who) {
		m.Delivered = append(m.Delivered, who)
		changed = true
	}
	if kind == receiptRead && !slices.Contains(m.Read, who) {
		m.Read = append(m.Read, who)
		changed = true
	}
	return changed
}

// settle works out Delivery and the counts. current is who is in the chat now,
// or nil if that is not known or not relevant: only those who were recipients
// and still are count, so someone who has left stops holding the ticks back.
func (m *HistoryMessage) settle(current [][16]byte) {
	m.Delivery, m.DeliveredCount, m.ReadCount, m.Total = DeliveryPending, 0, 0, 0
	if !m.Outgoing || m.System {
		return
	}
	switch {
	case m.Status != StatusSent:
		return // still waiting to go, or it never went
	case m.MsgID == ([16]byte{}):
		m.Delivery = DeliveryAccepted // from before receipts: it went, and that is all it can say
		return
	}
	for _, r := range m.Recipients {
		if current != nil && !slices.Contains(current, r) {
			continue
		}
		m.Total++
		if slices.Contains(m.Read, r) {
			m.ReadCount++
			m.DeliveredCount++
		} else if slices.Contains(m.Delivered, r) {
			m.DeliveredCount++
		}
	}
	switch {
	case m.Total > 0 && m.ReadCount == m.Total:
		m.Delivery = DeliveryRead
	case m.Total > 0 && m.DeliveredCount == m.Total:
		m.Delivery = DeliveryDelivered
	case m.Accepted || m.DeliveredCount > 0:
		m.Delivery = DeliveryAccepted
	}
}

// --- the history side ---

// updateOutgoing applies fn to the outgoing message with an ID, and keeps the
// result if fn says it changed. found is false for a message the history does
// not have, or one that is not outgoing.
func (a *accountHistory) updateOutgoing(id [16]byte, fn func(*HistoryMessage) bool) (m HistoryMessage, found, changed bool, err error) {
	tx, err := a.h.db.Begin()
	if err != nil {
		return m, false, false, err
	}
	defer tx.Rollback()
	var tag, sealed []byte
	var seq int64
	err = tx.QueryRow(`SELECT tag, seq, sealed FROM messages WHERE mid = ?`, a.messageKey(id)).Scan(&tag, &seq, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return m, false, false, nil
	}
	if err != nil {
		return m, false, false, err
	}
	m, err = a.openRow(tag, seq, sealed)
	if err != nil {
		return m, false, false, err
	}
	if !m.Outgoing || m.System {
		return m, false, false, nil
	}
	if !fn(&m) {
		return m, true, false, nil
	}
	if err := a.putRow(tx, tag, seq, m); err != nil {
		return m, true, false, err
	}
	return m, true, true, tx.Commit()
}

func (a *accountHistory) openRow(tag []byte, seq int64, sealed []byte) (HistoryMessage, error) {
	var m HistoryMessage
	plain, err := unsealBytes(a.rowKey, sealed, rowAAD(tag, seq))
	if err != nil {
		return m, fmt.Errorf("message %d does not open: %w", seq, err)
	}
	err = gobDecode(plain, &m)
	return m, err
}

func (a *accountHistory) putRow(tx *sql.Tx, tag []byte, seq int64, m HistoryMessage) error {
	plain, err := gobBytes(m)
	if err != nil {
		return err
	}
	sealed, err := sealBytes(a.rowKey, plain, rowAAD(tag, seq))
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE messages SET sealed = ? WHERE tag = ? AND seq = ?`, sealed, tag, seq)
	return err
}

// unreportedRead is an incoming message the person has read.
type unreportedRead struct {
	id, sender [16]byte
}

// readState is where a chat's read receipts stand.
func (a *accountHistory) readState(convID [16]byte) (wanted, sent int64, err error) {
	tx, err := a.h.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	rec, err := a.recordIn(tx, a.tag(convID))
	return rec.ReadWanted, rec.ReadSent, err
}

// unreported lists the incoming messages after seq `after`, up to and including
// `upTo`, that carry an ID the sender can be told about.
func (a *accountHistory) unreported(convID [16]byte, after, upTo int64) ([]unreportedRead, error) {
	tag := a.tag(convID)
	rows, err := a.h.db.Query(`SELECT seq, sealed FROM messages WHERE tag = ? AND seq > ? AND seq <= ? ORDER BY seq`, tag, after, upTo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []unreportedRead
	for rows.Next() {
		var seq int64
		var sealed []byte
		if err := rows.Scan(&seq, &sealed); err != nil {
			return nil, err
		}
		m, err := a.openRow(tag, seq, sealed)
		if err != nil {
			return nil, err
		}
		if m.Outgoing || m.System || m.MsgID == ([16]byte{}) {
			continue
		}
		out = append(out, unreportedRead{id: m.MsgID, sender: m.Sender})
	}
	return out, rows.Err()
}

// setReadSent notes that the senders of everything up to seq know it was read.
func (a *accountHistory) setReadSent(convID [16]byte, seq int64) error {
	tag := a.tag(convID)
	tx, err := a.h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rec, err := a.recordIn(tx, tag)
	if err != nil || rec.Last == 0 || seq <= rec.ReadSent {
		return err
	}
	rec.ReadSent = seq
	if err := a.putRecord(tx, tag, rec); err != nil {
		return err
	}
	return tx.Commit()
}

// pendingReads lists the chats with reads that have not been reported.
func (a *accountHistory) pendingReads() ([][16]byte, error) {
	convs, err := a.conversations()
	if err != nil {
		return nil, err
	}
	var out [][16]byte
	for _, c := range convs {
		if c.readWanted > c.readSent {
			out = append(out, c.ConvID)
		}
	}
	return out, nil
}

// The newest time the server has given for taking one of this account's
// messages, kept so that, after a gap, the account can ask for what it missed.
func (a *accountHistory) receiptMark() (int64, error) {
	var v int64
	err := a.h.db.QueryRow(`SELECT v FROM meta WHERE k = ?`, "receipts|"+fmt.Sprintf("%x", a.account[:])).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func (a *accountHistory) setReceiptMark(at int64) error {
	_, err := a.h.db.Exec(`INSERT INTO meta (k, v) VALUES (?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v WHERE excluded.v > meta.v`,
		"receipts|"+fmt.Sprintf("%x", a.account[:]), at)
	return err
}

// --- the client side ---

// receiptState holds receipts that arrived before the message they are about
// was in the history. A message is kept just after it is sent, and the server
// can be quicker than that.
type receiptState struct {
	mu    sync.Mutex
	early map[[16]byte][]earlyReceipt
	n     int
}

type earlyReceipt struct {
	kind receiptKind
	who  [16]byte
	at   time.Time
}

const (
	maxEarlyReceipts = 512
	earlyReceiptTTL  = 2 * time.Minute
)

func (rs *receiptState) stash(id [16]byte, kind receiptKind, who [16]byte) {
	if rs.early == nil {
		rs.early = map[[16]byte][]earlyReceipt{}
	}
	now := time.Now()
	for k, list := range rs.early { // the stale ones are never going to match
		keep := list[:0]
		for _, e := range list {
			if now.Sub(e.at) < earlyReceiptTTL {
				keep = append(keep, e)
			}
		}
		rs.n -= len(list) - len(keep)
		if len(keep) == 0 {
			delete(rs.early, k)
		} else {
			rs.early[k] = keep
		}
	}
	if rs.n >= maxEarlyReceipts {
		return
	}
	rs.early[id] = append(rs.early[id], earlyReceipt{kind: kind, who: who, at: now})
	rs.n++
}

func (rs *receiptState) take(id [16]byte) []earlyReceipt {
	list := rs.early[id]
	delete(rs.early, id)
	rs.n -= len(list)
	return list
}

// applyReceipt records a receipt on its message. One that arrives before the
// message is in the history waits for it.
func (cl *Client) applyReceipt(id, who [16]byte, kind receiptKind) {
	cl.receipts.mu.Lock()
	defer cl.receipts.mu.Unlock()
	cl.applyReceiptLocked(id, who, kind, true)
}

func (cl *Client) applyReceiptLocked(id, who [16]byte, kind receiptKind, mayWait bool) {
	h := cl.myHistory
	if h == nil || id == ([16]byte{}) {
		return
	}
	m, found, changed, err := h.updateOutgoing(id, func(m *HistoryMessage) bool { return m.apply(kind, who) })
	if err != nil {
		log.Printf("[ERROR] could not record a receipt for %x: %v", id[:4], err)
		return
	}
	if !found {
		if mayWait {
			cl.receipts.stash(id, kind, who)
		}
		return
	}
	if changed {
		cl.emitDelivery(m)
	}
}

// drainReceipts applies the receipts that came before a message was kept.
func (cl *Client) drainReceipts(id [16]byte) {
	cl.receipts.mu.Lock()
	defer cl.receipts.mu.Unlock()
	for _, e := range cl.receipts.take(id) {
		cl.applyReceiptLocked(id, e.who, e.kind, false)
	}
}

func (cl *Client) emitDelivery(m HistoryMessage) {
	m.settle(cl.currentMembers(m.ConvID))
	cl.emit(Event{
		Kind: EventMessageStatus, ConvID: m.ConvID, Seq: m.Seq, Status: m.Status,
		Delivery: m.Delivery, DeliveredCount: m.DeliveredCount, ReadCount: m.ReadCount, Total: m.Total,
	})
}

// currentMembers is who is in a group now, or nil for a direct chat, where the
// only possible recipient is the other person, or for a group not known yet.
func (cl *Client) currentMembers(convID [16]byte) [][16]byte {
	if cl.mgr == nil || !cl.mgr.IsGroup(convID) {
		return nil
	}
	members := cl.mgr.GetGroupMembers(convID)
	if len(members) == 0 {
		return nil
	}
	return members
}

// recipientsOf is who a message sent now to a chat is for: everyone in it but
// this account.
func (cl *Client) recipientsOf(convID [16]byte) [][16]byte {
	if cl.mgr.IsGroup(convID) {
		var out [][16]byte
		for _, m := range cl.mgr.GetGroupMembers(convID) {
			if m != cl.mgr.UserID {
				out = append(out, m)
			}
		}
		return out
	}
	if peer, ok := cl.directPeer(convID); ok {
		return [][16]byte{peer}
	}
	return nil
}

func (cl *Client) directPeer(convID [16]byte) ([16]byte, bool) {
	sess, ok := cl.sessionMgr.GetSession(convID)
	if !ok {
		return [16]byte{}, false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.st.PeerID, sess.st.PeerID != ([16]byte{})
}

// handleReceipt takes a receipt from the server.
func (cl *Client) handleReceipt(pkt common.Packet) {
	r, err := common.DecodeReceipt(pkt)
	if err != nil {
		log.Printf("[INFO] Ignoring a receipt: %v", err)
		return
	}
	kind := receiptAccepted
	if r.Delivered {
		kind = receiptDelivered
	} else if h := cl.myHistory; h != nil {
		if err := h.setReceiptMark(r.At); err != nil {
			log.Printf("[ERROR] could not note when receipts were last heard: %v", err)
		}
	}
	cl.applyReceipt(r.MessageID, r.Recipient, kind)
}

// handleReadReceipt takes word from a peer that they have read some of what
// this account sent. Who read them is who sent the packet, over a channel that
// only they can write to.
func (cl *Client) handleReadReceipt(pkt common.Packet) {
	ids, err := common.DecodeReadReceipt(pkt.Body)
	if err != nil {
		log.Printf("[INFO] Ignoring a read receipt from %x: %v", pkt.Header.SenderID[:4], err)
		return
	}
	for _, id := range ids {
		cl.applyReceipt(id, pkt.Header.SenderID, receiptRead)
	}
}

// receiptHistory is how far back a device with no record of receipts asks.
const receiptHistory = 14 * 24 * time.Hour

// afterConnect runs each time the connection comes up: it asks for the receipts
// missed while away, and reports anything read while it could not be sent.
func (cl *Client) afterConnect() {
	h := cl.myHistory
	if h == nil || cl.mgr == nil {
		return
	}
	cl.spawn(func() {
		since, err := h.receiptMark()
		if err != nil {
			log.Printf("[ERROR] could not read when receipts were last heard: %v", err)
		}
		if floor := time.Now().Add(-receiptHistory).UnixMilli(); since < floor {
			since = floor
		}
		rq := common.ReceiptsRequest(since)
		if err := cl.sendPacket(&rq); err != nil {
			log.Printf("[INFO] could not ask for missed receipts: %v", err)
			return
		}
		convs, err := h.pendingReads()
		if err != nil {
			log.Printf("[ERROR] could not list unreported reads: %v", err)
			return
		}
		for _, c := range convs {
			cl.flushReadReceipts(c)
		}
	})
}

// SetSendReadReceipts says whether this device tells people when it has read
// what they sent. It is on until turned off; off, nothing is said, and what was
// read in the meantime is never reported.
func (cl *Client) SetSendReadReceipts(on bool) { cl.noReadReceipts.Store(!on) }

// flushReadReceipts tells the senders of the messages read in a chat, and not
// yet reported, that they were read. Offline, it leaves them for next time.
func (cl *Client) flushReadReceipts(convID [16]byte) {
	h := cl.myHistory
	if h == nil || cl.mgr == nil {
		return
	}
	cl.readMu.Lock()
	defer cl.readMu.Unlock()
	wanted, sent, err := h.readState(convID)
	if err != nil {
		log.Printf("[ERROR] could not read where read receipts stand in %x: %v", convID[:4], err)
		return
	}
	if wanted <= sent {
		return
	}
	if cl.noReadReceipts.Load() {
		if err := h.setReadSent(convID, wanted); err != nil {
			log.Printf("[ERROR] %v", err)
		}
		return
	}
	if !cl.online() {
		return
	}
	items, err := h.unreported(convID, sent, wanted)
	if err != nil {
		log.Printf("[ERROR] could not list what was read in %x: %v", convID[:4], err)
		return
	}
	bySender := map[[16]byte][][16]byte{}
	for _, it := range items {
		if it.sender != cl.mgr.UserID {
			bySender[it.sender] = append(bySender[it.sender], it.id)
		}
	}
	for sender, ids := range bySender {
		// Over the channel the two share: the conversation itself in a direct
		// chat, the pair's own in a group, so only this one person is told.
		pair := common.HashIDs(cl.mgr.UserID, sender)
		for chunk := range slices.Chunk(ids, common.MaxReadReceiptIDs) {
			body := common.EncodeReadReceipt(chunk)
			pkt := common.Packet{
				Header: common.Header{MsgType: common.MsgReadReceipt, ConversationID: pair, MessageID: genID(),
					SenderID: cl.mgr.UserID, BodyLen: uint32(len(body))},
				Body: body,
			}
			if err := cl.sessionMgr.EncryptPacket(&pkt); err != nil {
				// No session with them: nothing can be said, now or later.
				log.Printf("[INFO] Cannot tell %x what was read: %v", sender[:4], err)
				break
			}
			if err := cl.sendPacket(&pkt); err != nil {
				return // offline again: ReadSent stays, and the next connection retries
			}
		}
	}
	if err := h.setReadSent(convID, wanted); err != nil {
		log.Printf("[ERROR] %v", err)
	}
}
