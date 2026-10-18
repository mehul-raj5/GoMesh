package core

import (
	common "common"
	"fmt"
	"log"
	"strings"
	"time"
)

// Moving an account to a new device, as seen from the network. An account has
// one device. When it signs in somewhere new, the server tells everyone who
// shares a conversation with it (CtrlKeyChange), and tells the new device which
// groups it belongs to (CtrlMyGroups). The new device then rekeys each group
// with a change it signs, and the direct chats restart on the new keys.

// handleKeyChange takes the server's word that a contact now has new keys.
//
// For a direct chat the server's directory is what keys come from in any case,
// so the old session, which only the old device could read, is replaced by a
// fresh one on the new bundle; the next message carries the handshake. Groups do
// not take the new keys from the server: the contact is marked as moving, left
// out of sender-key distribution, and admitted on their new keys only by their
// own signed rekey.
func (cl *Client) handleKeyChange(pkt common.Packet) {
	u, err := common.DecodeUserLookup(pkt.Body)
	if err != nil || u.ID == cl.mgr.UserID || u.ID != pkt.Header.SenderID || !u.Bundle.Verify() {
		log.Printf("[WARN] ignoring a malformed key change: %v", err)
		return
	}
	old, knew := cl.mgr.GetPublicKey(u.ID)
	cl.mgr.AddUser(u.ID, u.Name)
	cl.mgr.UpdatePublicKey(u.ID, u.Bundle.IdentityKey)

	convID := common.HashIDs(cl.mgr.UserID, u.ID)
	hadChat := false
	if sess, ok := cl.sessionMgr.GetSession(convID); ok {
		sess.mu.Lock()
		stale := sess.st.PeerIK != u.Bundle.IdentityKey
		sess.mu.Unlock()
		if stale {
			hadChat = true
			if _, err := cl.sessionMgr.OpenDirectSession(convID, u.ID, u.Name, u.Bundle, false); err != nil {
				cl.notify(LevelError, "Could not start a new secure session with %s: %v", u.Name, err)
			}
			cl.discardHeld(convID)
		}
	}
	groups := cl.sessionMgr.NoteDirectoryKey(u.ID, u.Bundle.IdentityKey)

	if hadChat || len(groups) > 0 || (knew && old != u.Bundle.IdentityKey) {
		text := fmt.Sprintf("%s signed in on a new device. Your safety number with them has changed; compare it again.", u.Name)
		if cl.mgr.HasConversation(convID) {
			cl.systemLine(convID, LevelWarn, "%s", text)
		} else {
			cl.notify(LevelWarn, "%s", text)
		}
	}
}

// handleMyGroups takes the list of groups this account belongs to, which the
// server sends at every login. A group this device has never heard of, or whose
// log still names the account's old keys, is one this device has just taken
// over: it fetches the log and rekeys it.
func (cl *Client) handleMyGroups(pkt common.Packet) {
	groups, err := common.DecodeMyGroups(pkt.Body)
	if err != nil {
		log.Printf("[ERROR] Bad group list from the server: %v", err)
		return
	}
	for _, g := range groups {
		if !cl.mgr.HasConversation(g.ID) {
			name := g.Name
			if name == "" {
				name = "group"
			}
			cl.mgr.RegisterConversation(g.ID, name, true)
		}
		if cl.needsRekey(g.ID) {
			cl.setIntent(g.ID, &groupIntent{action: common.ActionRekey})
		}
		cl.requestGroupLog(g.ID)
	}
}

// needsRekey reports whether the group's log, as far as this client knows it,
// does not yet name this device's keys for this account.
func (cl *Client) needsRekey(gid [16]byte) bool {
	info, ok := cl.sessionMgr.Group(gid)
	if !ok {
		return true
	}
	for _, k := range info.Members {
		if k.ID == cl.mgr.UserID {
			return k.IdentityKey != cl.idMgr.PublicKey || k.SigningKey != cl.idMgr.SigningKey
		}
	}
	return false
}

// --- session reset ---

// resetEvery bounds how often a reset is sent, or honoured, per conversation.
// Anyone can put one on the wire, the server included, so neither side lets
// them churn a chat.
const resetEvery = time.Minute

func (cl *Client) allowReset(m map[[16]byte]time.Time, convID [16]byte) bool {
	cl.resets.mu.Lock()
	defer cl.resets.mu.Unlock()
	if last, ok := m[convID]; ok && time.Since(last) < resetEvery {
		return false
	}
	m[convID] = time.Now()
	return true
}

// requestSessionReset asks a peer to start a new session, because they are
// sending on one this device does not hold: it lost its state, or it took the
// account over from another device. Without this the chat would stay silent
// until one of the two typed /dm.
func (cl *Client) requestSessionReset(convID, peer [16]byte, name string, dropped int) {
	if convID != common.HashIDs(cl.mgr.UserID, peer) {
		return
	}
	if !cl.allowReset(cl.resets.sent, convID) {
		return
	}
	pkt := common.Packet{Header: common.Header{
		MsgType: common.CtrlSessionReset, ConversationID: convID, SenderID: cl.mgr.UserID,
	}}
	if err := cl.sendPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not ask %s to start a new session: %v", name, err)
		return
	}
	cl.systemLine(convID, LevelInfo, "%s sent %d message(s) this device cannot read. Asked their app to start a new secure session.", name, dropped)
}

// handleSessionReset is a peer saying they cannot read this side of a chat. If
// this side is already on a fresh handshake, which every message repeats until
// the peer answers, that is enough. Otherwise a new session is opened, exactly
// as a typed /dm would.
func (cl *Client) handleSessionReset(pkt common.Packet) {
	from, convID := pkt.Header.SenderID, pkt.Header.ConversationID
	if from == cl.mgr.UserID || convID != common.HashIDs(cl.mgr.UserID, from) ||
		cl.mgr.IsGroup(convID) || cl.sessionMgr.HasGroup(convID) {
		return
	}
	if !cl.allowReset(cl.resets.honoured, convID) {
		return
	}
	name := cl.mgr.GetUsername(from)
	if sess, ok := cl.sessionMgr.GetSession(convID); ok && sess.pendingInitiator() {
		cl.systemLine(convID, LevelInfo, "%s could not read some of your recent messages; they may not have arrived.", name)
		return
	}
	if !cl.mgr.HasUsername(from) {
		log.Printf("[INFO] reset from %x, whose name is not known yet; asking for the roster", from[:4])
		cl.requestConvInfo(convID)
		return
	}
	cl.startPrivateChat(strings.ToLower(name))
	cl.systemLine(convID, LevelInfo, "%s could not read your recent messages, so a new secure session was started. Messages sent just before may not have arrived.", name)
}
