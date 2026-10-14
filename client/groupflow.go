package main

import (
	common "common"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"
)

// This file is the network side of group chats: it signs the membership changes
// the user asks for, applies the ones the server sends, and moves sender keys and
// group messages in and out. The cryptography lives in group.go.

// --- looking people up ---

var lookups = struct {
	mu      sync.Mutex
	waiting map[[16]byte]chan *common.UserLookup
	signing map[[16]byte][32]byte
}{
	waiting: make(map[[16]byte]chan *common.UserLookup),
	signing: make(map[[16]byte][32]byte),
}

// lookupUser asks the server who a username is. A change names its targets by ID
// and keys, so this comes before anything that adds or creates.
func lookupUser(name string) (*common.UserLookup, error) {
	reqID := genID()
	ch := make(chan *common.UserLookup, 1)
	lookups.mu.Lock()
	lookups.waiting[reqID] = ch
	lookups.mu.Unlock()
	defer func() {
		lookups.mu.Lock()
		delete(lookups.waiting, reqID)
		lookups.mu.Unlock()
	}()

	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlUserLookupRq, MessageID: reqID, SenderID: mgr.UserID, BodyLen: uint32(len(name)),
		},
		Body: []byte(name),
	}
	if err := sendPacket(&pkt); err != nil {
		return nil, err
	}
	select {
	case u := <-ch:
		if u == nil {
			return nil, fmt.Errorf("no user called %q", name)
		}
		if !u.Bundle.Verify() {
			return nil, fmt.Errorf("the server returned an invalid bundle for %q", name)
		}
		lookups.mu.Lock()
		lookups.signing[u.ID] = u.Bundle.SigningKey
		lookups.mu.Unlock()
		return u, nil
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timed out looking up %q", name)
	}
}

func deliverLookup(pkt common.Packet) {
	var u *common.UserLookup
	if len(pkt.Body) > 0 {
		if got, err := common.DecodeUserLookup(pkt.Body); err == nil {
			u = &got
		}
	}
	lookups.mu.Lock()
	ch := lookups.waiting[pkt.Header.MessageID]
	lookups.mu.Unlock()
	if ch != nil {
		ch <- u
	}
}

// knownSigning is what the session manager checks a change against: a signing
// key learned from a bundle rather than from the change itself.
func knownSigning(id [16]byte) ([32]byte, bool) {
	lookups.mu.Lock()
	defer lookups.mu.Unlock()
	k, ok := lookups.signing[id]
	return k, ok
}

// selfKey is this client's entry in a change that names it.
func selfKey() common.MemberKey {
	return common.MemberKey{ID: mgr.UserID, IdentityKey: idMgr.PublicKey, SigningKey: idMgr.SigningKey}
}

func signChange(c common.GroupChange) common.SignedChange {
	c.Actor = mgr.UserID
	c.Timestamp = time.Now().Unix()
	return common.SignChange(idMgr.SigningSeed, c)
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
}

const maxIntentAttempts = 4

var intents = struct {
	mu sync.Mutex
	m  map[[16]byte]*groupIntent
}{m: make(map[[16]byte]*groupIntent)}

func setIntent(gid [16]byte, in *groupIntent) {
	intents.mu.Lock()
	intents.m[gid] = in
	intents.mu.Unlock()
	driveIntent(gid)
}

// nextChange works out the signed change that moves the group toward what the
// user asked for, or reports that it already has.
func nextChange(info GroupInfo, head [32]byte, in *groupIntent) (sc common.SignedChange, done bool, err error) {
	self := mgr.UserID
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
					return signChange(base), false, nil
				}
			}
		}
		base.Action, base.Targets = common.ActionLeave, []common.MemberKey{selfKey()}
	}
	return signChange(base), false, nil
}

// driveIntent sends the next change for a group's pending intent, if one is due.
func driveIntent(gid [16]byte) {
	intents.mu.Lock()
	in := intents.m[gid]
	if in == nil || in.sent {
		intents.mu.Unlock()
		return
	}
	info, ok := sessionMgr.Group(gid)
	if !ok {
		// A group that is gone is the outcome of a leave; for anything else the
		// intent has nothing left to act on.
		delete(intents.m, gid)
		intents.mu.Unlock()
		return
	}
	if info.Version < in.waitVersion {
		intents.mu.Unlock()
		return
	}
	head, _ := sessionMgr.GroupHead(gid)
	sc, done, err := nextChange(info, head, in)
	switch {
	case err != nil:
		delete(intents.m, gid)
		intents.mu.Unlock()
		tuiPrintf("[ERROR] %v", err)
		return
	case done:
		delete(intents.m, gid)
		intents.mu.Unlock()
		return
	}
	in.sent, in.inflight = true, sc.Hash()
	intents.mu.Unlock()

	if err := sendChange(common.CtrlGroupChange, "", sc); err != nil {
		intents.mu.Lock()
		delete(intents.m, gid)
		intents.mu.Unlock()
		tuiPrintf("[ERROR] Could not send the change: %v", err)
	}
}

func sendChange(msgType uint8, name string, sc common.SignedChange) error {
	body := (&common.GroupChangeBody{Name: name, Change: sc}).Encode()
	pkt := common.Packet{
		Header: common.Header{MsgType: msgType, SenderID: mgr.UserID, BodyLen: uint32(len(body))},
		Body:   body,
	}
	return sendPacket(&pkt)
}

func createGroup(name string, users []string) {
	if name == "" {
		tuiPrintln("Group Name cannot be empty")
		return
	}
	go func() {
		keys := []common.MemberKey{selfKey()}
		seen := map[[16]byte]bool{mgr.UserID: true}
		for _, u := range users {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			found, err := lookupUser(u)
			if err != nil {
				tuiPrintf("[ERROR] Could not create the group: %v", err)
				return
			}
			if seen[found.ID] {
				continue
			}
			seen[found.ID] = true
			mgr.AddUser(found.ID, found.Name)
			keys = append(keys, common.MemberKey{ID: found.ID, IdentityKey: found.Bundle.IdentityKey, SigningKey: found.Bundle.SigningKey})
		}
		sc := signChange(common.GroupChange{
			GroupID: genID(), Version: 1, Action: common.ActionCreate, Targets: keys,
		})
		if err := sendChange(common.CtrlGroupCreate, name, sc); err != nil {
			tuiPrintf("[ERROR] Could not create the group: %v", err)
		}
	}()
}

func requireGroup(convID [16]byte) bool {
	if !mgr.IsGroup(convID) {
		tuiPrintln("Error: This is not a group.")
		return false
	}
	return true
}

func addMember(convID [16]byte, username string) {
	if !requireGroup(convID) {
		return
	}
	go func() {
		u, err := lookupUser(strings.TrimSpace(username))
		if err != nil {
			tuiPrintf("[ERROR] %v", err)
			return
		}
		mgr.AddUser(u.ID, u.Name)
		setIntent(convID, &groupIntent{
			action:  common.ActionAdd,
			targets: []common.MemberKey{{ID: u.ID, IdentityKey: u.Bundle.IdentityKey, SigningKey: u.Bundle.SigningKey}},
		})
	}()
}

func removeMember(convID [16]byte, username string) {
	if requireGroup(convID) {
		setIntent(convID, &groupIntent{action: common.ActionRemove, names: []string{strings.TrimSpace(username)}})
	}
}

func makeGroupAdmin(convID [16]byte, username string) {
	if requireGroup(convID) {
		setIntent(convID, &groupIntent{action: common.ActionPromote, names: []string{strings.TrimSpace(username)}})
	}
}

func removeGroupAdmin(convID [16]byte, username string) {
	if requireGroup(convID) {
		setIntent(convID, &groupIntent{action: common.ActionDemote, names: []string{strings.TrimSpace(username)}})
	}
}

func leaveGroup(convID [16]byte) {
	if requireGroup(convID) {
		setIntent(convID, &groupIntent{action: common.ActionLeave})
		tuiPrintln("Leave group request sent.")
	}
}

// --- applying what the server sends ---

func handleGroupChange(pkt common.Packet) {
	body, err := common.DecodeGroupChangeBody(pkt.Body)
	if err != nil {
		log.Printf("[ERROR] Bad group change from the server: %v", err)
		return
	}
	gid := body.Change.Change.GroupID
	hash := body.Change.Hash()

	upd, err := sessionMgr.ApplyGroupChange(&body)
	if err != nil {
		tuiPrintf("[WARN] Refused a membership change for group %x: %v", gid[:4], err)
		log.Printf("[WARN] group %x change refused: %v", gid[:4], err)
		return
	}

	intents.mu.Lock()
	if in := intents.m[gid]; in != nil && in.sent && in.inflight == hash {
		in.sent = false
	}
	intents.mu.Unlock()

	if upd.Left {
		name := mgr.GetConversationName(gid)
		mgr.RemoveConversation(gid)
		discardHeld(gid)
		intents.mu.Lock()
		delete(intents.m, gid)
		intents.mu.Unlock()
		tuiPrintf("[INFO] You are no longer a member of %s", name)
		return
	}

	if upd.Progressed {
		announceEffects(gid, upd)
		syncGroupUI(gid)
		// Membership moving may be what held messages were waiting for, and may let
		// us send to people we could not reach before.
		replay(pending.Release(gid))
		for _, owner := range upd.Installed {
			replay(pending.ReleaseSender(gid, owner))
		}
		flushOutbox(gid)
	}
	if upd.Behind {
		requestGroupLog(gid)
	}
	driveIntent(gid)
}

func announceEffects(gid [16]byte, upd GroupUpdate) {
	info, _ := sessionMgr.Group(gid)
	nameOf := func(id [16]byte) string {
		if n := info.Names[id]; n != "" {
			return n
		}
		return mgr.GetUsername(id)
	}
	for _, e := range upd.Effects {
		switch e.Action {
		case common.ActionCreate:
			tuiPrintf("[INFO] Group %s created with %d members.", upd.Name, len(e.Added))
		case common.ActionAdd:
			for _, k := range e.Added {
				tuiPrintf("[INFO] %s was added to %s", nameOf(k.ID), upd.Name)
			}
		case common.ActionRemove, common.ActionLeave:
			for _, id := range e.Removed {
				tuiPrintf("[INFO] %s left %s", nameOf(id), upd.Name)
			}
		case common.ActionPromote:
			for _, id := range e.Promoted {
				tuiPrintf("[INFO] %s is now an admin of %s", nameOf(id), upd.Name)
			}
		case common.ActionDemote:
			for _, id := range e.Demoted {
				tuiPrintf("[INFO] %s is no longer an admin of %s", nameOf(id), upd.Name)
			}
		}
	}
}

// syncGroupUI copies the verified membership into the display state. The
// display state is for showing people and checking commands early; nothing
// cryptographic reads it.
func syncGroupUI(gid [16]byte) {
	info, ok := sessionMgr.Group(gid)
	if !ok {
		return
	}
	name := info.Name
	if name == "" {
		name = fmt.Sprintf("%x", gid[:4])
	}
	if !mgr.HasConversation(gid) {
		mgr.RegisterConversation(gid, name, true)
	}
	ids := make([][16]byte, 0, len(info.Members))
	for _, k := range info.Members {
		ids = append(ids, k.ID)
		if k.ID != mgr.UserID {
			// The log vouches for this key, so a session built from a message
			// header is checked against it.
			mgr.UpdatePublicKey(k.ID, k.IdentityKey)
		}
		if n := info.Names[k.ID]; n != "" {
			mgr.AddUser(k.ID, n)
		}
	}
	mgr.SetGroupRoster(gid, ids, info.Admins)
}

func handleGroupHints(pkt common.Packet) {
	gid, hints, err := common.DecodeGroupHints(pkt.Body)
	if err != nil {
		log.Printf("[ERROR] Bad group hints: %v", err)
		return
	}
	sessionMgr.ApplyGroupHints(gid, hints)
	syncGroupUI(gid)
	flushOutbox(gid)
}

func handleGroupReject(pkt common.Packet) {
	rej, err := common.DecodeGroupChangeReject(pkt.Body)
	if err != nil {
		return
	}
	log.Printf("[INFO] server refused change %x for group %x: %s", rej.ChangeHash[:4], rej.GroupID[:4], rej.Reason)

	intents.mu.Lock()
	in := intents.m[rej.GroupID]
	if in == nil || !in.sent || in.inflight != rej.ChangeHash {
		intents.mu.Unlock()
		tuiPrintf("[ERROR] The server refused a group change: %s", rej.Reason)
		return
	}
	in.sent = false
	in.attempts++
	in.waitVersion = rej.HeadVersion
	if in.attempts >= maxIntentAttempts {
		delete(intents.m, rej.GroupID)
		intents.mu.Unlock()
		tuiPrintf("[ERROR] The server refused the group change: %s", rej.Reason)
		return
	}
	intents.mu.Unlock()

	// Catch up on whatever beat us, then work the request out again.
	requestGroupLog(rej.GroupID)
	driveIntent(rej.GroupID)
}

// --- catching up ---

var (
	logMu    sync.Mutex
	logAsked = map[[16]byte]time.Time{}
)

// groupLogRetry throttles log requests: a stream of messages from a version we
// have not caught up to would otherwise produce a request each.
const groupLogRetry = 2 * time.Second

// requestGroupLog asks the server for the membership changes this client lacks,
// and fresh directory data for the group's members.
func requestGroupLog(gid [16]byte) {
	logMu.Lock()
	if last, ok := logAsked[gid]; ok && time.Since(last) < groupLogRetry {
		logMu.Unlock()
		return
	}
	logAsked[gid] = time.Now()
	logMu.Unlock()

	body := (&common.GroupLogRequest{GroupID: gid, FromVersion: sessionMgr.GroupVersion(gid)}).Encode()
	pkt := common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupLogRq, ConversationID: gid, SenderID: mgr.UserID, BodyLen: uint32(len(body)),
		},
		Body: body,
	}
	if err := sendPacket(&pkt); err != nil {
		log.Printf("[ERROR] Could not request the log for group %x: %v", gid[:4], err)
	}
}

// restoreGroups brings back the groups saved by earlier runs and asks the server
// for anything that happened while the client was away.
func restoreGroups() {
	groups, err := sessionMgr.LoadGroups()
	if err != nil {
		log.Printf("[ERROR] Could not restore saved groups: %v", err)
	}
	for _, g := range groups {
		syncGroupUI(g.ID)
		requestGroupLog(g.ID)
	}
}

// --- sender keys ---

// handleSenderKey takes a sender key that arrived in a 1:1 session.
func handleSenderKey(pkt common.Packet) {
	upd, err := sessionMgr.ReceiveSenderKey(&pkt)
	if err != nil {
		log.Printf("[INFO] Ignoring sender key from %x: %v", pkt.Header.SenderID[:4], err)
		return
	}
	if upd.Behind {
		requestGroupLog(upd.GroupID)
	}
	for _, owner := range upd.Installed {
		replay(pending.ReleaseSender(upd.GroupID, owner))
	}
}

// --- sending ---

// groupOutbox holds messages for a group whose members could not all be reached
// yet. Sending one anyway would leave the unreachable members unable to read it.
var groupOutbox = struct {
	mu sync.Mutex
	m  map[[16]byte][]common.Packet
}{m: make(map[[16]byte][]common.Packet)}

const maxOutbox = 64

// sendGroupMessage seals and sends a group message. It is the only way group
// traffic leaves this client, for text and media alike.
func sendGroupMessage(pkt *common.Packet) error {
	gid := pkt.Header.ConversationID
	plain := *pkt
	plain.Body = append([]byte(nil), pkt.Body...)

	pre, err := sessionMgr.EncryptGroupPacket(pkt)
	var need *NeedSessionsError
	if errors.As(err, &need) {
		groupOutbox.mu.Lock()
		if len(groupOutbox.m[gid]) < maxOutbox {
			groupOutbox.m[gid] = append(groupOutbox.m[gid], plain)
		}
		groupOutbox.mu.Unlock()
		tuiPrintf("[INFO] Setting up secure sessions with %d member(s) of %s; your message will go out as soon as they are ready.",
			len(need.Peers), mgr.GetConversationName(gid))
		requestGroupLog(gid)
		return nil
	}
	if err != nil {
		return err
	}
	for i := range pre {
		if err := sendPacket(&pre[i]); err != nil {
			return err
		}
	}
	return sendPacket(pkt)
}

// flushOutbox retries what was waiting on sessions, in order, and stops at the
// first message that still cannot go.
func flushOutbox(gid [16]byte) {
	groupOutbox.mu.Lock()
	queued := groupOutbox.m[gid]
	delete(groupOutbox.m, gid)
	groupOutbox.mu.Unlock()

	for i, p := range queued {
		pkt := p
		pre, err := sessionMgr.EncryptGroupPacket(&pkt)
		var need *NeedSessionsError
		if errors.As(err, &need) {
			groupOutbox.mu.Lock()
			groupOutbox.m[gid] = append(slices.Clone(queued[i:]), groupOutbox.m[gid]...)
			groupOutbox.mu.Unlock()
			return
		}
		if err != nil {
			tuiPrintf("[ERROR] Could not send a queued message: %v", err)
			continue
		}
		for j := range pre {
			sendPacket(&pre[j])
		}
		sendPacket(&pkt)
	}
}

// onSessionReplaced is called when a 1:1 session was replaced by a new one, which
// means the peer started over. What they held of ours is gone.
func onSessionReplaced(convID [16]byte) {
	discardHeld(convID)
	sess, ok := sessionMgr.GetSession(convID)
	if !ok {
		return
	}
	sess.mu.Lock()
	peer := sess.st.PeerID
	sess.mu.Unlock()
	if affected := sessionMgr.PeerKeysChanged(peer); len(affected) > 0 {
		log.Printf("[INFO] %x started a new session; rotating sender keys in %d group(s)", peer[:4], len(affected))
	}
}
