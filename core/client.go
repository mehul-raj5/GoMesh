package core

import (
	common "common"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// openDevice loads this device's identity and saved state from dataDir,
// creating a new identity if there is none.
func (cl *Client) openDevice() error {
	key, err := cl.accountKey()
	if err != nil {
		return err
	}
	if cl.idMgr, err = openIdentity(cl.secrets(), key, cl.dataPath(legacyKeyFile)); err != nil {
		return err
	}
	if cl.stateStore, err = OpenStateStore(cl.dataPath(stateDirName), key); err != nil {
		return err
	}
	if n, err := cl.stateStore.MigrateLegacy(cl.dataPath(legacyStateDir), cl.idMgr.PublicKey); err != nil {
		return fmt.Errorf("moving earlier saved state into the sealed store: %w", err)
	} else if n > 0 {
		log.Printf("Sealed %d record(s) an earlier version saved in plaintext", n)
	}
	return cl.idMgr.LoadPreKeys(cl.stateStore)
}

// accountKey returns the key this sign-in's crypto state is sealed under,
// making one if the device has none. Only the vault saying it holds no key
// counts as none: a vault that cannot be read now is an error to retry later.
func (cl *Client) accountKey() ([32]byte, error) {
	var key [32]byte
	b, err := cl.secrets().Get(vaultAccountKey)
	switch {
	case err == nil:
		if len(b) != len(key) {
			return key, fmt.Errorf("the account key in the vault is %d bytes", len(b))
		}
		copy(key[:], b)
		return key, nil
	case !errors.Is(err, ErrNotInVault):
		return key, fmt.Errorf("reading the vault: %w", err)
	}
	// No key. Keys sealed under one that is gone would be lost by making another,
	// so that is refused rather than papered over.
	if _, err := cl.secrets().Get(vaultIdentity); err == nil {
		return key, errors.New("the vault holds sealed identity keys but not the key that opens them")
	} else if !errors.Is(err, ErrNotInVault) {
		return key, fmt.Errorf("reading the vault: %w", err)
	}
	if key, err = randomKey(); err != nil {
		return key, err
	}
	if err := cl.secrets().Put(vaultAccountKey, key[:]); err != nil {
		return key, fmt.Errorf("saving the account key: %w", err)
	}
	return key, nil
}

func (cl *Client) setConn(c net.Conn) {
	cl.connLock.Lock()
	cl.conn = c
	cl.connLock.Unlock()
}

func (cl *Client) readLoop() {
	cl.connLock.Lock()
	conn := cl.conn
	cl.connLock.Unlock()
	a := newAcker(cl, conn)
	cl.acks.Store(a)
	defer a.stop()
	for {
		pkt, err := common.Decode(conn)
		if err != nil {
			cl.connectionLost(err)
			return
		}
		if cl.signedOutBy(pkt) {
			return
		}
		cl.deliver(pkt)
		a.done()
	}
}

// deliver decrypts a packet if it needs it and hands it to dispatch. A packet
// whose key has not arrived yet is held rather than dropped, and comes back
// through here once the missing key lands.
func (cl *Client) deliver(pkt common.Packet) {
	wasEncrypted := pkt.Header.Flags&common.FlagEncrypted != 0
	convID := pkt.Header.ConversationID

	if err := cl.tryDecrypt(&pkt); err != nil {
		// A handshake under keys other than the ones the directory gave us: the
		// peer may have signed in on a new device. Ask the server, and hold the
		// packet until it answers; the roster settles which keys are theirs.
		if errors.Is(err, ErrPeerKeyMismatch) {
			cl.pending.Park(convID, pkt)
			cl.requestConvInfo(convID)
			return
		}
		if errors.Is(err, ErrAlreadyRead) {
			log.Printf("[INFO] Dropping packet from %x: %v", pkt.Header.SenderID[:4], err)
			return
		}
		if !Recoverable(err) {
			log.Printf("[ERROR] Dropping packet from %x: %v", pkt.Header.SenderID[:4], err)
			return
		}

		if errors.Is(err, ErrNoGroupSession) || errors.Is(err, ErrNoSenderKey) || errors.Is(err, ErrMembershipBehind) {
			cl.pending.ParkFor(convID, pkt, GroupPendingTTL)
		} else {
			cl.pending.Park(convID, pkt)
		}

		// A missing sender key is already on its way over the direct channel we
		// share with that member, and a missing epoch is waiting on a packet
		// that is itself in flight, so there is nothing to ask for. Not knowing
		// the conversation at all is different: the roster has to be fetched.
		if errors.Is(err, ErrNoSession) || errors.Is(err, ErrNoGroupSession) {
			cl.requestConvInfo(convID)
		}
		// A message from a membership version we have not seen: fetch the log.
		if errors.Is(err, ErrMembershipBehind) {
			cl.requestGroupLog(convID)
		}
		return
	}

	// A sender key arrives over a 1:1 session that exists for the group's sake, so
	// it does not add a private chat to the list.
	direct := wasEncrypted && !cl.mgr.IsGroup(convID) && !cl.sessionMgr.HasGroup(convID) &&
		pkt.Header.MsgType != common.CtrlSenderKey && pkt.Header.MsgType != common.MsgReadReceipt
	if direct {
		cl.learnDirectPeer(convID)
	}
	cl.dispatch(pkt)

	// Reading this message may have supplied what held ones were waiting for: the
	// missing epoch of a direct chain, in particular, arrives as an ordinary packet.
	if direct {
		cl.replay(cl.pending.Release(convID))
	}
}

// discardHeld drops packets parked for a conversation whose session was just
// replaced. They belong to a session that no longer exists, so replaying them
// could only park them again.
func (cl *Client) discardHeld(convID [16]byte) {
	cl.pending.Release(convID)
}

// learnDirectPeer registers a conversation first heard of through an incoming
// message, which is how the responder side of a chat comes to exist: its session
// was built from the message itself. The roster supplies the peer's name, checks
// the identity key it claimed, and replaces this placeholder.
func (cl *Client) learnDirectPeer(convID [16]byte) {
	if cl.mgr.HasConversation(convID) {
		return
	}
	cl.mgr.RegisterConversation(convID, fmt.Sprintf("Private Chat: %x", convID[:4]), false)
	cl.requestConvInfo(convID)
}

// tryDecrypt unwraps an encrypted packet using whichever session applies.
//
// An unknown conversation reads as a direct one, because IsGroup returns false
// for anything unregistered. That resolves itself: the roster reply says which
// it really is, and the replayed packet then takes the right branch.
func (cl *Client) tryDecrypt(pkt *common.Packet) error {
	if pkt.Header.Flags&common.FlagEncrypted == 0 {
		return nil
	}
	convID := pkt.Header.ConversationID
	if cl.mgr.IsGroup(convID) || cl.sessionMgr.HasGroup(convID) {
		return cl.sessionMgr.DecryptGroupPacket(pkt)
	}
	// A group this client has not heard of yet looks like a direct chat. Its body
	// says otherwise, and it is held until the group's log arrives.
	if !cl.mgr.HasConversation(convID) {
		if w, err := common.DecodeGroupWire(pkt.Body); err == nil && w.Header.GroupID == convID {
			return fmt.Errorf("%w: %x", ErrNoGroupSession, convID[:4])
		}
	}
	return cl.sessionMgr.DecryptPacket(pkt)
}

func (cl *Client) dispatch(pkt common.Packet) {
	{
		switch pkt.Header.MsgType {
		case common.MsgText:
			// Kept before the host hears of it: the ratchet has already moved on,
			// so a message lost here could never be read again.
			m := HistoryMessage{
				Sender: pkt.Header.SenderID, SenderName: cl.mgr.GetUsername(pkt.Header.SenderID),
				Time: time.Now(), Text: string(pkt.Body), MsgID: pkt.Header.MessageID,
			}
			cl.record(pkt.Header.ConversationID, m)
			cl.emit(Event{
				Kind: EventMessage, ConvID: pkt.Header.ConversationID,
				Sender: m.Sender, SenderName: m.SenderName, Text: m.Text, Time: m.Time,
			})

		case common.MsgMediaMeta:
			meta, err := common.DecodeMediaMetadata(pkt.Body)
			if err != nil {
				log.Printf("Bad media meta: %v", err)
				return
			}
			sender := cl.mgr.GetUsername(pkt.Header.SenderID)
			cl.notify(LevelInfo, "[%s] Incoming media from %s: %s (%d bytes)",
				cl.mgr.GetConversationName(pkt.Header.ConversationID),
				sender, meta.FileName, meta.FileSize)
			cl.handleIncomingMedia(pkt.Header.ConversationID, pkt.Header.SenderID, pkt.Header.MessageID, sender, meta)

		case common.CtrlMsgAccepted, common.CtrlMsgDelivered:
			cl.handleReceipt(pkt)

		case common.MsgReadReceipt:
			cl.handleReadReceipt(pkt)

		case common.CtrlUploadAck:
			strs, err := common.DecodeSignedURLPayload(pkt.Body, 2)
			if err != nil {
				strs = nil
			}
			cl.mgr.DeliverURL(pkt.Header.MessageID, strs)

		case common.CtrlDownloadAck:
			strs, err := common.DecodeSignedURLPayload(pkt.Body, 1)
			if err != nil {
				strs = nil
			}
			cl.mgr.DeliverURL(pkt.Header.MessageID, strs)

		case common.CtrlDirectAck:
			// convID(16) || peerID(16) || prekey bundle || peerName
			if len(pkt.Body) < 32+common.PreKeyBundleSize {
				return
			}
			var convID, peerID [16]byte
			copy(convID[:], pkt.Body[:16])
			copy(peerID[:], pkt.Body[16:32])
			bundle, err := common.DecodePreKeyBundle(pkt.Body[32:])
			if err != nil {
				return
			}
			peerName := string(pkt.Body[32+common.PreKeyBundleSize:])

			cl.mgr.AddUser(peerID, peerName)
			cl.mgr.UpdatePublicKey(peerID, bundle.IdentityKey)
			cl.mgr.RegisterConversation(convID, "Private Chat: "+peerName, false)
			cl.sessionMgr.NoteDirectoryKey(peerID, bundle.IdentityKey)

			// No packet is sent back. The peer builds its side from the handshake
			// fields in our first message, so it need not be online.
			//
			// An ack is only ever the answer to a /dm, and /dm on a chat that
			// exists means start over. Only an ack we asked for does that, though:
			// an unsolicited one must not be able to reset a working session.
			res, err := cl.sessionMgr.OpenDirectSession(convID, peerID, peerName, bundle, cl.takeDMRequest(peerName))
			cl.chatOpened(convID, err)
			if err != nil {
				cl.notify(LevelError, "Could not open chat with %s: %v", peerName, err)
				return
			}
			if res.Replaced {
				cl.discardHeld(convID)
			}
			if res.Replaced && !res.IdentityChanged {
				// Starting over on the same keys means whatever the peer held of our
				// sender keys is gone. New keys are a move, which NoteDirectoryKey
				// and the peer's signed rekey take care of.
				cl.sessionMgr.PeerKeysChanged(peerID)
			}
			if res.IdentityChanged {
				cl.systemLine(convID, LevelWarn, "%s's identity key has changed since this chat began. Compare safety numbers before trusting it.", peerName)
			}
			if res.Replaced {
				cl.systemLine(convID, LevelInfo, "Started a fresh secure session with %s. Messages either of you sent on the old one may not arrive.", peerName)
			} else {
				cl.notify(LevelInfo, "Secure session ready with %s", peerName)
			}

		case common.CtrlSenderKey:
			cl.handleSenderKey(pkt)

		case common.CtrlGroupChange:
			cl.handleGroupChange(pkt)

		case common.CtrlGroupHints:
			cl.handleGroupHints(pkt)

		case common.CtrlGroupChangeReject:
			cl.handleGroupReject(pkt)

		case common.CtrlUserLookupAck:
			cl.deliverLookup(pkt)

		case common.CtrlConvInfoAck:
			info, err := common.DecodeConvInfo(pkt.Body)
			if err != nil {
				log.Printf("[ERROR] Bad conversation info: %v", err)
				return
			}
			cl.applyConvInfo(info)

		case common.CtrlKeyChange:
			cl.handleKeyChange(pkt)

		case common.CtrlMyGroups:
			cl.handleMyGroups(pkt)

		case common.CtrlSessionReset:
			cl.handleSessionReset(pkt)
		}
	}
}

func (cl *Client) noteDMRequest(name string) {
	cl.dmMu.Lock()
	cl.dmRequests[name] = struct{}{}
	cl.dmMu.Unlock()
}

// takeDMRequest reports whether the user asked for a chat with name, and
// consumes the request.
func (cl *Client) takeDMRequest(name string) bool {
	cl.dmMu.Lock()
	defer cl.dmMu.Unlock()
	_, ok := cl.dmRequests[name]
	delete(cl.dmRequests, name)
	return ok
}

// startPrivateChat asks the server for a private chat with name. If one already
// exists, the answer starts a fresh secure session in its place, which is the
// way out of a conversation that has stopped decrypting.
func (cl *Client) startPrivateChat(name string) {
	if name == "" {
		cl.notify(LevelInfo, "Target username cannot be empty")
		return
	}
	cl.noteDMRequest(strings.ToLower(name))
	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlDirectInit,
			BodyLen: uint32(len(name)),
		},
		Body: []byte(name),
	}
	cl.sendPacket(&pkt)
}

func (cl *Client) listConversations() {
	cl.mgr.mu.Lock()
	defer cl.mgr.mu.Unlock()
	i := 0
	for id, info := range cl.mgr.Conversations {
		typeStr := "Private"
		if info.IsGroup {
			typeStr = "Group"
		}
		cl.notify(LevelInfo, "%d. %s [%s] (%x)", i, info.Name, typeStr, id[:4])
		i++
	}
}

func genID() [16]byte {
	var id [16]byte
	rand.Read(id[:])
	return id
}

func (cl *Client) sendPacket(pkt *common.Packet) error {
	cl.connLock.Lock()
	defer cl.connLock.Unlock()
	if cl.conn == nil { // started offline, before the first connection
		return ErrOffline
	}
	return pkt.Encode(cl.conn)
}

// convInfoRetry throttles roster lookups. The server answers nothing at all
// when the asker is not a member, so without a cooldown a stream of packets for
// a conversation we have no business in would produce a request each.
const convInfoRetry = 5 * time.Second

// requestConvInfo asks the server who is in a conversation, at most once per
// convInfoRetry per conversation.
func (cl *Client) requestConvInfo(convID [16]byte) {
	cl.convInfoMu.Lock()
	if last, asked := cl.convInfoAsked[convID]; asked && time.Since(last) < convInfoRetry {
		cl.convInfoMu.Unlock()
		return
	}
	cl.convInfoAsked[convID] = time.Now()
	cl.convInfoMu.Unlock()

	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlConvInfoRq,
			ConversationID: convID,
			SenderID:       cl.mgr.UserID,
			BodyLen:        common.IDSize,
		},
		Body: convID[:],
	}
	if err := cl.sendPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not request roster for %x: %v", convID[:4], err)
	}
}

// applyConvInfo takes the server's answer about a conversation we did not know,
// establishes whatever keys it makes possible, and replays what was held.
func (cl *Client) applyConvInfo(info common.ConvInfo) {
	if !info.IsGroup {
		for _, m := range info.Members {
			if m.UserID == cl.mgr.UserID {
				continue
			}
			cl.mgr.AddUser(m.UserID, m.Name)
			cl.mgr.UpdatePublicKey(m.UserID, m.PubKey)
			cl.sessionMgr.NoteDirectoryKey(m.UserID, m.PubKey)
		}
	}

	if info.IsGroup {
		// Who is in a group is what its signed log says, not what this roster says.
		// The roster supplies the name and tells us the conversation is a group;
		// the log, requested here, supplies the members.
		name := info.Name
		if name == "" {
			name = fmt.Sprintf("%x", info.ConvID[:4])
		}
		if !cl.mgr.HasConversation(info.ConvID) || !cl.mgr.IsGroup(info.ConvID) {
			cl.mgr.RegisterConversation(info.ConvID, name, true)
		}
		cl.requestGroupLog(info.ConvID)
		return
	}

	{
		for _, m := range info.Members {
			if m.UserID == cl.mgr.UserID {
				continue
			}
			cl.mgr.RegisterConversation(info.ConvID, "Private Chat: "+m.Name, false)

			// The session already exists if a message built it; what the roster
			// adds is the peer's name and signing key, and an independent check of
			// the identity key that message claimed.
			err := cl.sessionMgr.NotePeerKeys(info.ConvID, m.UserID, m.Name, m.PubKey, m.SigningKey)
			switch {
			case errors.Is(err, ErrPeerKeyMismatch):
				// The session was with keys the server no longer gives for them: they
				// signed in on a new device, or someone substituted a key. The old
				// session is gone either way.
				cl.systemLine(info.ConvID, LevelWarn, "%s has new keys, perhaps on a new device. Your safety number with them has changed; compare it again.", m.Name)
			case err != nil:
				log.Printf("[ERROR] Could not record keys for %s: %v", m.Name, err)
				return
			}
			if _, ok := cl.sessionMgr.GetSession(info.ConvID); ok {
				cl.notify(LevelInfo, "Secure session ready with %s", m.Name)
				continue
			}

			// No session. What was held may include a handshake under the keys the
			// roster just confirmed, which can build one now.
			cl.replay(cl.pending.Release(info.ConvID))
			if _, ok := cl.sessionMgr.GetSession(info.ConvID); ok {
				continue
			}

			// Still none, and the roster cannot make one: opening a chat takes the
			// peer's prekey bundle, which only a CtrlDirectAck carries. The peer is
			// sending on a session this device does not have, because it lost its
			// state or took the account over from another device. What is held can
			// never be read, so it is discarded and the peer is asked to start over.
			dropped := len(cl.pending.Release(info.ConvID))
			cl.requestSessionReset(info.ConvID, m.UserID, m.Name, dropped)
			return
		}
	}

	cl.replay(cl.pending.Release(info.ConvID))
}

// restoreSessions brings back the direct conversations saved by earlier runs, so
// a restart picks up each ratchet where it stopped instead of starting over.
func (cl *Client) restoreSessions() {
	peers, err := cl.sessionMgr.LoadSessions()
	if err != nil {
		log.Printf("[ERROR] Could not restore saved sessions: %v", err)
	}
	for _, p := range peers {
		name := p.Name
		if name == "" {
			name = fmt.Sprintf("%x", p.ConversationID[:4])
		}
		cl.mgr.AddUser(p.PeerID, name)
		cl.mgr.RegisterConversation(p.ConversationID, "Private Chat: "+name, false)

		// A key learned only from a message header is not the directory's word, and
		// must not come back out of KnownKey as if it were. The roster is asked for
		// again; its answer confirms the key, supplies the name, and clears the flag.
		if p.Unverified {
			cl.requestConvInfo(p.ConversationID)
			continue
		}
		cl.mgr.UpdatePublicKey(p.PeerID, p.IdentityKey)
	}
}

// replay feeds held packets back through delivery now that a key has arrived.
// Anything still blocked simply parks again.
func (cl *Client) replay(pkts []common.Packet) {
	for _, p := range pkts {
		cl.deliver(p)
	}
}

// sendText encrypts a text message for a conversation and sends it.
func (cl *Client) sendText(convID [16]byte, text string) error {
	// Refused before anything is encrypted: a send that fails after the ratchet
	// has moved would burn a message key, and history would call it sent.
	if !cl.online() {
		return ErrOffline
	}
	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.MsgText,
			ConversationID: convID,
			MessageID:      genID(),
			SenderID:       cl.mgr.UserID,
			BodyLen:        uint32(len(text)),
		},
		Body: []byte(text),
	}
	msg := HistoryMessage{Sender: cl.mgr.UserID, SenderName: cl.mgr.Username, Outgoing: true, Time: time.Now(), Text: text,
		MsgID: pkt.Header.MessageID, Recipients: cl.recipientsOf(convID)}
	var err error
	queued := false
	if cl.mgr.IsGroup(convID) {
		queued, err = cl.sendGroupMessage(&pkt, func() int64 {
			m := msg
			m.Status = StatusQueued
			return cl.recordSeq(convID, m)
		})
	} else if err = cl.sessionMgr.EncryptPacket(&pkt); err == nil {
		err = cl.sendPacket(&pkt)
	}
	if err != nil {
		return err
	}
	if !queued {
		cl.record(convID, msg)
	}
	return nil
}

// setStatus records where a kept outgoing message stands and tells the host.
// seq 0 is a message that was never kept.
func (cl *Client) setStatus(convID [16]byte, seq int64, status MessageStatus) {
	if seq == 0 || cl.myHistory == nil {
		return
	}
	if err := cl.myHistory.setStatus(convID, seq, status); err != nil {
		log.Printf("[ERROR] could not update message %d in %x: %v", seq, convID[:4], err)
	}
	cl.emit(Event{Kind: EventMessageStatus, ConvID: convID, Seq: seq, Status: status})
}

// record keeps a message in this account's history. A failure is logged and
// reported, never swallowed, and does not stop the message reaching the host.
func (cl *Client) record(convID [16]byte, m HistoryMessage) { cl.recordSeq(convID, m) }

// recordSeq is record, returning the message's sequence number, or 0 if it was
// not kept.
func (cl *Client) recordSeq(convID [16]byte, m HistoryMessage) int64 {
	if cl.myHistory == nil {
		log.Printf("[ERROR] no history open; a message in %x was not kept", convID[:4])
		return 0
	}
	seq, err := cl.myHistory.append(convID, cl.mgr.GetConversationName(convID), cl.mgr.IsGroup(convID), m)
	if err != nil {
		log.Printf("[ERROR] could not keep a message in %x: %v", convID[:4], err)
		cl.notify(LevelError, "A message could not be saved to this device's history: %v", err)
		return 0
	}
	if m.Outgoing && m.MsgID != ([16]byte{}) {
		cl.drainReceipts(m.MsgID) // the server may have answered before the row was there
	}
	return seq
}
