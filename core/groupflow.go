package core

import (
	common "common"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"
)

// This file is the network side of group chats: it signs the membership changes
// the user asks for, applies the ones the server sends, and moves sender keys and
// group messages in and out. The cryptography lives in group.go.

// --- looking people up ---

// lookupUser asks the server who a username is. A change names its targets by ID
// and keys, so this comes before anything that adds or creates.
func (cl *Client) lookupUser(name string) (*common.UserLookup, error) {
	reqID := genID()
	ch := make(chan *common.UserLookup, 1)
	cl.lookups.mu.Lock()
	cl.lookups.waiting[reqID] = ch
	cl.lookups.mu.Unlock()
	defer func() {
		cl.lookups.mu.Lock()
		delete(cl.lookups.waiting, reqID)
		cl.lookups.mu.Unlock()
	}()

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlUserLookupRq, MessageID: reqID, SenderID: cl.mgr.UserID, BodyLen: uint32(len(name)),
		},
		Body: []byte(name),
	}
	if err := cl.sendPacket(&pkt); err != nil {
		return nil, err
	}
	select {
	case u := <-ch:
		if u == nil {
			return nil, fmt.Errorf("%w: %q", ErrUserNotFound, name)
		}
		if !u.Bundle.Verify() {
			return nil, fmt.Errorf("the server returned an invalid bundle for %q", name)
		}
		return u, nil
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timed out looking up %q", name)
	}
}

func (cl *Client) deliverLookup(pkt common.Packet) {
	var u *common.UserLookup
	if len(pkt.Body) > 0 {
		if got, err := common.DecodeUserLookup(pkt.Body); err == nil {
			u = &got
		}
	}
	cl.lookups.mu.Lock()
	ch := cl.lookups.waiting[pkt.Header.MessageID]
	cl.lookups.mu.Unlock()
	if ch != nil {
		ch <- u
	}
}

// selfKey is this client's entry in a change that names it.
func (cl *Client) selfKey() common.MemberKey {
	return common.MemberKey{ID: cl.mgr.UserID, IdentityKey: cl.idMgr.PublicKey, SigningKey: cl.idMgr.SigningKey}
}

func (cl *Client) signChange(c common.GroupChange) common.SignedChange {
	c.Actor = cl.mgr.UserID
	c.Timestamp = time.Now().Unix()
	return common.SignChange(cl.idMgr.SigningSeed, c)
}

// --- membership commands ---

// A groupIntent is something the user asked for, such as adding a person. It is
// not a signed change, because a change is only valid on top of one particular
// version of the log. If another admin's change lands first, the server refuses
// ours; the intent is then worked out again against the new log and resubmitted.
type groupIntent struct {
	action  common.GroupAction
	targets []common.MemberKey // for an add, the people to add with their keys
	names   []string           // for the rest, who the user named

	sent        bool
	inflight    [32]byte
	attempts    int
	waitVersion uint32
	builtOn     uint32 // the log version the change in flight was built on

	// ready is for a rekey: it is driven only once this client has caught up
	// with the log, which a CtrlGroupHints marks, since a rekey built on a
	// version partway through a replay would only be refused.
	ready bool
}

const maxIntentAttempts = 4

func (cl *Client) setIntent(gid [16]byte, in *groupIntent) {
	cl.intents.mu.Lock()
	if cur := cl.intents.m[gid]; cur != nil && cur.action == common.ActionRekey && in.action != common.ActionRekey {
		cl.intents.mu.Unlock()
		cl.notify(LevelInfo, "This device is still being added to the group's keys. Try again in a moment.")
		return
	}
	if cur := cl.intents.m[gid]; cur != nil && cur.action == common.ActionRekey && in.action == common.ActionRekey {
		cl.intents.mu.Unlock() // already on its way
		return
	}
	cl.intents.m[gid] = in
	cl.intents.mu.Unlock()
	cl.driveIntent(gid)
}

// nextChange works out the signed change that moves the group toward what the
// user asked for, or reports that it already has.
func (cl *Client) nextChange(info GroupInfo, head [32]byte, in *groupIntent) (sc common.SignedChange, done bool, err error) {
	self := cl.mgr.UserID
	isAdmin := slices.Contains(info.Admins, self)
	base := common.GroupChange{GroupID: info.ID, Version: info.Version + 1, PrevHash: head}

	byName := func(name string) (common.MemberKey, bool) {
		for _, k := range info.Members {
			if strings.EqualFold(info.Names[k.ID], name) {
				return k, true
			}
		}
		return common.MemberKey{}, false
	}
	isMember := func(id [16]byte) bool {
		for _, k := range info.Members {
			if k.ID == id {
				return true
			}
		}
		return false
	}

	switch in.action {
	case common.ActionAdd:
		var todo []common.MemberKey
		for _, t := range in.targets {
			if !isMember(t.ID) {
				todo = append(todo, t)
			}
		}
		if len(todo) == 0 {
			return sc, true, nil
		}
		if !isAdmin {
			return sc, false, errors.New("only an admin can add members")
		}
		base.Action, base.Targets = common.ActionAdd, todo

	case common.ActionRemove, common.ActionPromote, common.ActionDemote:
		var todo []common.MemberKey
		for _, name := range in.names {
			k, ok := byName(name)
			if !ok {
				if in.action == common.ActionRemove {
					continue // already gone
				}
				return sc, false, fmt.Errorf("%s is not a member of this group", name)
			}
			switch in.action {
			case common.ActionRemove:
				if k.ID == self {
					return sc, false, errors.New("use /leave to leave a group")
				}
				todo = append(todo, k)
			case common.ActionPromote:
				if !slices.Contains(info.Admins, k.ID) {
					todo = append(todo, k)
				}
			case common.ActionDemote:
				if slices.Contains(info.Admins, k.ID) {
					todo = append(todo, k)
				}
			}
		}
		if len(todo) == 0 {
			return sc, true, nil
		}
		if !isAdmin {
			return sc, false, errors.New("only an admin can do that")
		}
		base.Action, base.Targets = in.action, todo

	case common.ActionRekey:
		var cur common.MemberKey
		found := false
		for _, k := range info.Members {
			if k.ID == self {
				cur, found = k, true
			}
		}
		if !found || (cur.IdentityKey == cl.idMgr.PublicKey && cur.SigningKey == cl.idMgr.SigningKey) {
			return sc, true, nil // not ours to rekey, or done
		}
		base.Action, base.Targets = common.ActionRekey, []common.MemberKey{cl.selfKey()}

	case common.ActionLeave:
		if !isMember(self) {
			return sc, true, nil
		}
		// A group with no admin cannot be managed, so the last admin hands the role
		// to someone first. The promotion is signed like any other change.
		if isAdmin && len(info.Admins) == 1 && len(info.Members) > 1 {
			for _, k := range info.Members {
				if k.ID != self {
					base.Action, base.Targets = common.ActionPromote, []common.MemberKey{k}
					return cl.signChange(base), false, nil
				}
			}
		}
		base.Action, base.Targets = common.ActionLeave, []common.MemberKey{cl.selfKey()}
	}
	return cl.signChange(base), false, nil
}

// driveIntent sends the next change for a group's pending intent, if one is due.
func (cl *Client) driveIntent(gid [16]byte) {
	cl.intents.mu.Lock()
	in := cl.intents.m[gid]
	if in == nil || in.sent {
		cl.intents.mu.Unlock()
		return
	}
	info, ok := cl.sessionMgr.Group(gid)
	if !ok {
		if in.action == common.ActionRekey {
			// The log for a group this device has just taken over is on its way.
			cl.intents.mu.Unlock()
			return
		}
		// A group that is gone is the outcome of a leave; for anything else the
		// intent has nothing left to act on.
		delete(cl.intents.m, gid)
		cl.intents.mu.Unlock()
		return
	}
	if info.Version < in.waitVersion || (in.action == common.ActionRekey && !in.ready) {
		cl.intents.mu.Unlock()
		return
	}
	head, _ := cl.sessionMgr.GroupHead(gid)
	sc, done, err := cl.nextChange(info, head, in)
	switch {
	case err != nil:
		delete(cl.intents.m, gid)
		cl.intents.mu.Unlock()
		cl.notify(LevelError, "%v", err)
		return
	case done:
		delete(cl.intents.m, gid)
		cl.intents.mu.Unlock()
		return
	}
	in.sent, in.inflight, in.builtOn = true, sc.Hash(), info.Version
	cl.intents.mu.Unlock()

	if err := cl.sendChange(common.CtrlGroupChange, "", sc); err != nil {
		cl.intents.mu.Lock()
		delete(cl.intents.m, gid)
		cl.intents.mu.Unlock()
		cl.notify(LevelError, "Could not send the change: %v", err)
	}
}

func (cl *Client) sendChange(msgType uint8, name string, sc common.SignedChange) error {
	body := (&common.GroupChangeBody{Name: name, Change: sc}).Encode()
	pkt := common.Packet{
		Header: common.Header{MsgType: msgType, SenderID: cl.mgr.UserID, BodyLen: uint32(len(body))},
		Body:   body,
	}
	return cl.sendPacket(&pkt)
}

func (cl *Client) requireGroup(convID [16]byte) bool {
	if !cl.mgr.IsGroup(convID) {
		cl.notify(LevelInfo, "Error: This is not a group.")
		return false
	}
	return true
}

func (cl *Client) addMember(convID [16]byte, username string) {
	if !cl.requireGroup(convID) {
		return
	}
	go func() {
		u, err := cl.lookupUser(strings.TrimSpace(username))
		if err != nil {
			cl.notify(LevelError, "%v", err)
			return
		}
		cl.mgr.AddUser(u.ID, u.Name)
		cl.setIntent(convID, &groupIntent{
			action:  common.ActionAdd,
			targets: []common.MemberKey{{ID: u.ID, IdentityKey: u.Bundle.IdentityKey, SigningKey: u.Bundle.SigningKey}},
		})
	}()
}

func (cl *Client) removeMember(convID [16]byte, username string) {
	if cl.requireGroup(convID) {
		cl.setIntent(convID, &groupIntent{action: common.ActionRemove, names: []string{strings.TrimSpace(username)}})
	}
}

func (cl *Client) makeGroupAdmin(convID [16]byte, username string) {
	if cl.requireGroup(convID) {
		cl.setIntent(convID, &groupIntent{action: common.ActionPromote, names: []string{strings.TrimSpace(username)}})
	}
}

func (cl *Client) removeGroupAdmin(convID [16]byte, username string) {
	if cl.requireGroup(convID) {
		cl.setIntent(convID, &groupIntent{action: common.ActionDemote, names: []string{strings.TrimSpace(username)}})
	}
}

func (cl *Client) leaveGroup(convID [16]byte) {
	if cl.requireGroup(convID) {
		cl.setIntent(convID, &groupIntent{action: common.ActionLeave})
		cl.notify(LevelInfo, "Leave group request sent.")
	}
}

// --- applying what the server sends ---

func (cl *Client) handleGroupChange(pkt common.Packet) {
	body, err := common.DecodeGroupChangeBody(pkt.Body)
	if err != nil {
		log.Printf("[ERROR] Bad group change from the server: %v", err)
		return
	}
	gid := body.Change.Change.GroupID
	hash := body.Change.Hash()

	upd, err := cl.sessionMgr.ApplyGroupChange(&body)
	if err != nil {
		cl.notify(LevelWarn, "Refused a membership change for group %x: %v", gid[:4], err)
		log.Printf("[WARN] group %x change refused: %v", gid[:4], err)
		return
	}

	cl.intents.mu.Lock()
	if in := cl.intents.m[gid]; in != nil && in.sent && in.inflight == hash {
		in.sent = false
	}
	cl.intents.mu.Unlock()

	if upd.Left {
		name := cl.mgr.GetConversationName(gid)
		cl.systemLine(gid, LevelInfo, "You are no longer a member of %s", name)
		cl.mgr.RemoveConversation(gid)
		cl.discardHeld(gid)
		cl.intents.mu.Lock()
		delete(cl.intents.m, gid)
		cl.intents.mu.Unlock()
		return
	}

	if upd.Progressed {
		cl.syncGroupUI(gid) // first, so the chat exists to record the lines in
		cl.announceEffects(gid, upd)
		// Membership moving may be what held messages were waiting for, and may let
		// us send to people we could not reach before.
		cl.replay(cl.pending.Release(gid))
		for _, owner := range upd.Installed {
			cl.replay(cl.pending.ReleaseSender(gid, owner))
		}
		cl.flushOutbox(gid)
	}
	if upd.Behind {
		cl.requestGroupLog(gid)
	}
	cl.driveIntent(gid)
}

func (cl *Client) announceEffects(gid [16]byte, upd GroupUpdate) {
	info, _ := cl.sessionMgr.Group(gid)
	nameOf := func(id [16]byte) string {
		if n := info.Names[id]; n != "" {
			return n
		}
		return cl.mgr.GetUsername(id)
	}
	for i, e := range upd.Effects {
		if i < len(upd.Witnessed) && !upd.Witnessed[i] {
			continue
		}
		switch e.Action {
		case common.ActionCreate:
			cl.systemLine(gid, LevelInfo, "Group %s created with %d members.", upd.Name, len(e.Added))
		case common.ActionAdd:
			for _, k := range e.Added {
				cl.systemLine(gid, LevelInfo, "%s was added to %s", nameOf(k.ID), upd.Name)
			}
		case common.ActionRemove, common.ActionLeave:
			for _, id := range e.Removed {
				cl.systemLine(gid, LevelInfo, "%s left %s", nameOf(id), upd.Name)
			}
		case common.ActionPromote:
			for _, id := range e.Promoted {
				cl.systemLine(gid, LevelInfo, "%s is now an admin of %s", nameOf(id), upd.Name)
			}
		case common.ActionDemote:
			for _, id := range e.Demoted {
				cl.systemLine(gid, LevelInfo, "%s is no longer an admin of %s", nameOf(id), upd.Name)
			}
		case common.ActionRekey:
			for _, k := range e.Rekeyed {
				if k.ID == cl.mgr.UserID {
					cl.systemLine(gid, LevelInfo, "This device now holds your keys for %s.", upd.Name)
				} else {
					cl.systemLine(gid, LevelInfo, "%s is on a new device; the keys for %s are being replaced.", nameOf(k.ID), upd.Name)
				}
			}
		}
	}
}

// syncGroupUI copies the verified membership into the display state. The
// display state is for showing people and checking commands early; nothing
// cryptographic reads it.
func (cl *Client) syncGroupUI(gid [16]byte) {
	info, ok := cl.sessionMgr.Group(gid)
	if !ok {
		return
	}
	name := info.Name
	if name == "" {
		name = fmt.Sprintf("%x", gid[:4])
	}
	if !cl.mgr.HasConversation(gid) {
		cl.mgr.RegisterConversation(gid, name, true)
	}
	cl.chatOpened(gid, nil) // a CreateGroup waiting on this group
	ids := make([][16]byte, 0, len(info.Members))
	for _, k := range info.Members {
		ids = append(ids, k.ID)
		// A member who is moving has newer keys in the directory than in the log,
		// and the directory's are the ones their handshakes come under.
		if k.ID != cl.mgr.UserID && !slices.Contains(info.Moving, k.ID) {
			// The log vouches for this key, so a session built from a message
			// header is checked against it.
			cl.mgr.UpdatePublicKey(k.ID, k.IdentityKey)
		}
		if n := info.Names[k.ID]; n != "" {
			cl.mgr.AddUser(k.ID, n)
		}
	}
	cl.mgr.SetGroupRoster(gid, ids, info.Admins)
}

func (cl *Client) handleGroupHints(pkt common.Packet) {
	gid, hints, err := common.DecodeGroupHints(pkt.Body)
	if err != nil {
		log.Printf("[ERROR] Bad group hints: %v", err)
		return
	}
	cl.sessionMgr.ApplyGroupHints(gid, hints)
	cl.syncGroupUI(gid)

	// Hints follow a log reply, so this client has caught up: a rekey waiting on
	// that can go, and anyone still unsettled is worth a word.
	cl.intents.mu.Lock()
	if in := cl.intents.m[gid]; in != nil && in.action == common.ActionRekey {
		in.ready = true
	}
	cl.intents.mu.Unlock()
	cl.driveIntent(gid)
	cl.warnUnsettled(gid)
	cl.flushOutbox(gid)
}

// warnUnsettled tells the user about members who will not get this client's
// group messages: their 1:1 session is with other keys than the group's log
// names, and no move explains it. It warns once per member and group.
func (cl *Client) warnUnsettled(gid [16]byte) {
	for _, id := range cl.sessionMgr.UnsettledMembers(gid) {
		key := [32]byte{}
		copy(key[:16], gid[:])
		copy(key[16:], id[:])
		cl.unsettledMu.Lock()
		seen := cl.unsettledWarned[key]
		cl.unsettledWarned[key] = true
		cl.unsettledMu.Unlock()
		if !seen {
			cl.systemLine(gid, LevelWarn, "%s's keys in %s differ from the ones your chat with them uses, so they will not get your messages there. Compare safety numbers with them.",
				cl.mgr.GetUsername(id), cl.mgr.GetConversationName(gid))
		}
	}
}

func (cl *Client) handleGroupReject(pkt common.Packet) {
	rej, err := common.DecodeGroupChangeReject(pkt.Body)
	if err != nil {
		return
	}
	log.Printf("[INFO] server refused change %x for group %x: %s", rej.ChangeHash[:4], rej.GroupID[:4], rej.Reason)

	cl.intents.mu.Lock()
	in := cl.intents.m[rej.GroupID]
	if in == nil || !in.sent || in.inflight != rej.ChangeHash {
		cl.intents.mu.Unlock()
		cl.chatOpened(rej.GroupID, fmt.Errorf("the server refused the group: %s", rej.Reason))
		cl.notify(LevelError, "The server refused a group change: %s", rej.Reason)
		return
	}
	in.sent = false
	in.waitVersion = rej.HeadVersion
	// A rekey refused only because the log moved on under it is not a failure:
	// in a busy group it can happen several times, and giving up would leave this
	// device unable to send until the next login.
	if in.action != common.ActionRekey || rej.HeadVersion <= in.builtOn {
		in.attempts++
	}
	// A rekey stays ready. The server sends the change that beat it to every
	// member before it sends this refusal, so it has already been applied here,
	// and waitVersion holds the retry until the log has caught up. Waiting for a
	// fresh catch-up instead would stall: the log request below is throttled,
	// and usually goes nowhere this soon after the one made at login.
	if in.attempts >= maxIntentAttempts {
		delete(cl.intents.m, rej.GroupID)
		cl.intents.mu.Unlock()
		cl.notify(LevelError, "The server refused the group change: %s", rej.Reason)
		return
	}
	cl.intents.mu.Unlock()

	// Catch up on whatever beat us, then work the request out again.
	cl.requestGroupLog(rej.GroupID)
	cl.driveIntent(rej.GroupID)
}

// --- catching up ---

// groupLogRetry throttles log requests: a stream of messages from a version we
// have not caught up to would otherwise produce a request each.
const groupLogRetry = 2 * time.Second

// requestGroupLog asks the server for the membership changes this client lacks,
// and fresh directory data for the group's members.
func (cl *Client) requestGroupLog(gid [16]byte) {
	cl.logMu.Lock()
	if last, ok := cl.logAsked[gid]; ok && time.Since(last) < groupLogRetry {
		cl.logMu.Unlock()
		return
	}
	cl.logAsked[gid] = time.Now()
	cl.logMu.Unlock()

	body := (&common.GroupLogRequest{GroupID: gid, FromVersion: cl.sessionMgr.GroupVersion(gid)}).Encode()
	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupLogRq, ConversationID: gid, SenderID: cl.mgr.UserID, BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	if err := cl.sendPacket(&pkt); err != nil {
		// Not sent, so it does not count: the login after reconnecting asks again.
		cl.logMu.Lock()
		delete(cl.logAsked, gid)
		cl.logMu.Unlock()
		log.Printf("[INFO] Could not request the log for group %x: %v", gid[:4], err)
	}
}

// restoreGroups brings back the groups saved by earlier runs and asks the server
// for anything that happened while the client was away.
func (cl *Client) restoreGroups() {
	groups, err := cl.sessionMgr.LoadGroups()
	if err != nil {
		log.Printf("[ERROR] Could not restore saved groups: %v", err)
	}
	for _, g := range groups {
		cl.syncGroupUI(g.ID)
		cl.requestGroupLog(g.ID)
	}
}

// --- sender keys ---

// handleSenderKey takes a sender key that arrived in a 1:1 session.
func (cl *Client) handleSenderKey(pkt common.Packet) {
	upd, err := cl.sessionMgr.ReceiveSenderKey(&pkt)
	if err != nil {
		log.Printf("[INFO] Ignoring sender key from %x: %v", pkt.Header.SenderID[:4], err)
		return
	}
	if upd.Behind {
		cl.requestGroupLog(upd.GroupID)
	}
	for _, owner := range upd.Installed {
		cl.replay(cl.pending.ReleaseSender(upd.GroupID, owner))
	}
}

// --- sending ---

const maxOutbox = 64

// ErrOutboxFull means too many messages are already waiting for a group's
// sessions, so this one was not taken.
var ErrOutboxFull = errors.New("too many messages are already waiting to go to this group")

// An outboxItem is a group message waiting for sessions, and the history row
// that shows it as queued, if it has one.
type outboxItem struct {
	pkt common.Packet
	seq int64
}

// queueOutbox holds a message until the group's sessions are ready. hold, if
// given, keeps the message in the history as queued and returns its row.
func (cl *Client) queueOutbox(gid [16]byte, pkt common.Packet, hold func() int64) error {
	cl.groupOutbox.mu.Lock()
	full := len(cl.groupOutbox.m[gid]) >= maxOutbox
	cl.groupOutbox.mu.Unlock()
	if full {
		return ErrOutboxFull
	}
	var seq int64
	if hold != nil {
		seq = hold()
	}
	cl.groupOutbox.mu.Lock()
	cl.groupOutbox.m[gid] = append(cl.groupOutbox.m[gid], outboxItem{pkt: pkt, seq: seq})
	cl.groupOutbox.mu.Unlock()
	return nil
}

// sendGroupMessage seals and sends a group message. It is the only way group
// traffic leaves this client, for text and media alike. A message that cannot go
// yet is held and sent once the group's sessions are ready, and queued is true;
// hold is called then, to keep it in the history as queued.
func (cl *Client) sendGroupMessage(pkt *common.Packet, hold func() int64) (queued bool, err error) {
	gid := pkt.Header.ConversationID
	plain := *pkt
	plain.Body = append([]byte(nil), pkt.Body...)

	pre, err := cl.sessionMgr.EncryptGroupPacket(pkt)
	if errors.Is(err, ErrAwaitingRekey) {
		if err := cl.queueOutbox(gid, plain, hold); err != nil {
			return false, err
		}
		cl.notify(LevelInfo, "This device is still being added to %s's keys; your message will go out as soon as it is.",
			cl.mgr.GetConversationName(gid))
		cl.requestGroupLog(gid)
		return true, nil
	}
	var need *NeedSessionsError
	if errors.As(err, &need) {
		if err := cl.queueOutbox(gid, plain, hold); err != nil {
			return false, err
		}
		cl.notify(LevelInfo, "Setting up secure sessions with %d member(s) of %s; your message will go out as soon as they are ready.",
			len(need.Peers), cl.mgr.GetConversationName(gid))
		cl.requestGroupLog(gid)
		return true, nil
	}
	if err != nil {
		return false, err
	}
	for i := range pre {
		if err := cl.sendPacket(&pre[i]); err != nil {
			return false, err
		}
	}
	return false, cl.sendPacket(pkt)
}

// flushOutbox retries what was waiting on sessions, in order, and stops at the
// first message that still cannot go. Each one's history row says what became
// of it.
func (cl *Client) flushOutbox(gid [16]byte) {
	cl.groupOutbox.mu.Lock()
	queued := cl.groupOutbox.m[gid]
	delete(cl.groupOutbox.m, gid)
	cl.groupOutbox.mu.Unlock()

	for i, item := range queued {
		pkt := item.pkt
		pre, err := cl.sessionMgr.EncryptGroupPacket(&pkt)
		var need *NeedSessionsError
		if errors.As(err, &need) || errors.Is(err, ErrAwaitingRekey) {
			cl.groupOutbox.mu.Lock()
			cl.groupOutbox.m[gid] = append(slices.Clone(queued[i:]), cl.groupOutbox.m[gid]...)
			cl.groupOutbox.mu.Unlock()
			return
		}
		if err == nil {
			for j := range pre {
				if err = cl.sendPacket(&pre[j]); err != nil {
					break
				}
			}
		}
		if err == nil {
			err = cl.sendPacket(&pkt)
		}
		if err != nil {
			cl.notify(LevelError, "Could not send a queued message: %v", err)
			cl.setStatus(gid, item.seq, StatusFailed)
			continue
		}
		cl.setStatus(gid, item.seq, StatusSent)
	}
}

// onSessionReplaced is called when a 1:1 session was replaced by a new one, which
// means the peer started over. What they held of ours is gone.
func (cl *Client) onSessionReplaced(convID [16]byte) {
	cl.discardHeld(convID)
	sess, ok := cl.sessionMgr.GetSession(convID)
	if !ok {
		return
	}
	sess.mu.Lock()
	peer := sess.st.PeerID
	sess.mu.Unlock()
	if affected := cl.sessionMgr.PeerKeysChanged(peer); len(affected) > 0 {
		log.Printf("[INFO] %x started a new session; rotating sender keys in %d group(s)", peer[:4], len(affected))
	}
}
