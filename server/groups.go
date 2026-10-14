package main

import (
	common "common"
	"errors"
	"fmt"
	"log"
)

// maxGroupName bounds a group's display name.
const maxGroupName = 64

// Group membership is a signed log. A client signs each change; the server
// assigns it its place in the order, refuses what is not valid, and fans it out.
// Clients check every change again for themselves, so what the server enforces
// here is a courtesy that stops honest clients from desynchronizing. It is not
// what group security rests on.

// directoryPin gives common.Membership the signing key the server holds for a
// user, so a change cannot claim a key the account never registered.
// Caller holds s.mu.
func (s *Server) directoryPinLocked(id [common.IDSize]byte) ([32]byte, bool) {
	u, ok := s.users[id]
	if !ok {
		return [32]byte{}, false
	}
	return u.Bundle.SigningKey, true
}

// checkTargetsLocked confirms every person a create or add introduces is a
// registered user, and that the keys the change vouches for are the ones on file.
// Caller holds s.mu.
func (s *Server) checkTargetsLocked(targets []common.MemberKey) error {
	for _, t := range targets {
		u, ok := s.users[t.ID]
		if !ok {
			return fmt.Errorf("%x is not a registered user", t.ID[:4])
		}
		if u.IdentityKey != t.IdentityKey || u.Bundle.SigningKey != t.SigningKey {
			return fmt.Errorf("keys for %x do not match the directory", t.ID[:4])
		}
	}
	return nil
}

// hintsLocked builds directory hints for the given members. Caller holds s.mu.
func (s *Server) hintsLocked(ids [][common.IDSize]byte) []common.GroupHint {
	hints := make([]common.GroupHint, 0, len(ids))
	for _, id := range ids {
		if u, ok := s.users[id]; ok {
			hints = append(hints, common.GroupHint{ID: id, Name: u.Username, Bundle: u.Bundle})
		}
	}
	return hints
}

func (s *Server) reject(to *Client, groupID [common.IDSize]byte, sc *common.SignedChange, head uint32, reason string) {
	log.Printf("[WARNING] rejected %v for group %x from %x: %s", sc.Change.Action, groupID[:4], to.UserID[:4], reason)
	body := (&common.GroupChangeReject{
		GroupID: groupID, ChangeHash: sc.Hash(), HeadVersion: head, Reason: reason,
	}).Encode()
	s.sendPacket(to.UserID, common.Packet{
		Header: common.Header{
			MsgType: common.CtrlGroupChangeReject, ConversationID: groupID, BodyLen: uint32(len(body)),
		},
		Body: body,
	})
}

// handleGroupCreate takes the signed first change of a new group. The creator
// picks the group ID, since it is inside the signature; the server only refuses
// one that is already in use.
func (s *Server) handleGroupCreate(sender *Client, p common.Packet) {
	body, err := common.DecodeGroupChangeBody(p.Body)
	if err != nil {
		log.Printf("[WARNING] bad CtrlGroupCreate from %x: %v", sender.UserID[:4], err)
		return
	}
	sc := body.Change
	groupID := sc.Change.GroupID

	if len(body.Name) == 0 || len(body.Name) > maxGroupName {
		s.reject(sender, groupID, &sc, 0, "group name must be 1 to 64 bytes")
		return
	}
	if sc.Change.Action != common.ActionCreate || sc.Change.Actor != sender.UserID {
		s.reject(sender, groupID, &sc, 0, "not a create by the sender")
		return
	}

	s.mu.Lock()
	if _, exists := s.convs[groupID]; exists || groupID == ([common.IDSize]byte{}) {
		s.mu.Unlock()
		s.reject(sender, groupID, &sc, 0, "group id already in use")
		return
	}
	if err := s.checkTargetsLocked(sc.Change.Targets); err != nil {
		s.mu.Unlock()
		s.reject(sender, groupID, &sc, 0, err.Error())
		return
	}
	conv := &Conversation{ID: groupID, Name: body.Name, IsGroup: true}
	if _, err := conv.Membership.Apply(&sc, func(id [common.IDSize]byte) ([32]byte, bool) {
		return s.directoryPinLocked(id)
	}); err != nil {
		s.mu.Unlock()
		s.reject(sender, groupID, &sc, 0, err.Error())
		return
	}
	conv.Members = conv.Membership.MemberIDs()
	conv.Log = []common.SignedChange{sc}
	s.convs[groupID] = conv
	s.ensurePairwiseConvsLocked(conv.Members)
	hints := s.hintsLocked(conv.Members)
	members := append([][common.IDSize]byte(nil), conv.Members...)
	s.mu.Unlock()

	out := common.GroupChangeBody{Name: conv.Name, Change: sc, Hints: hints}
	s.fanOutChange(groupID, &out, members)
}

// handleGroupChange takes a later signed change. Check and apply happen under
// one lock, so of two admins submitting at the same version the first is
// accepted and the second finds the log has moved on and is refused. The second
// admin is told where the log stands and can resubmit on top of it.
func (s *Server) handleGroupChange(sender *Client, p common.Packet) {
	body, err := common.DecodeGroupChangeBody(p.Body)
	if err != nil {
		log.Printf("[WARNING] bad CtrlGroupChange from %x: %v", sender.UserID[:4], err)
		return
	}
	sc := body.Change
	groupID := sc.Change.GroupID

	s.mu.RLock()
	conv, ok := s.convs[groupID]
	s.mu.RUnlock()
	if !ok || !conv.IsGroup {
		s.reject(sender, groupID, &sc, 0, "no such group")
		return
	}

	conv.changeMu.Lock()
	defer conv.changeMu.Unlock()

	s.mu.Lock()
	if sc.Change.Actor != sender.UserID {
		head := conv.Membership.Version
		s.mu.Unlock()
		s.reject(sender, groupID, &sc, head, "the actor must be the sender")
		return
	}
	if !conv.Membership.IsMember(sender.UserID) {
		s.mu.Unlock()
		s.reject(sender, groupID, &sc, 0, "not a member")
		return
	}
	if a := sc.Change.Action; a == common.ActionAdd {
		if err := s.checkTargetsLocked(sc.Change.Targets); err != nil {
			head := conv.Membership.Version
			s.mu.Unlock()
			s.reject(sender, groupID, &sc, head, err.Error())
			return
		}
	}

	before := append([][common.IDSize]byte(nil), conv.Members...)
	eff, err := conv.Membership.Apply(&sc, func(id [common.IDSize]byte) ([32]byte, bool) {
		return s.directoryPinLocked(id)
	})
	if err != nil {
		head := conv.Membership.Version
		s.mu.Unlock()
		reason := err.Error()
		switch {
		case errors.Is(err, common.ErrChangeStale):
			reason = "the log has moved on; catch up and resubmit"
		case errors.Is(err, common.ErrChangeGap):
			reason = "the change is ahead of the log"
		}
		s.reject(sender, groupID, &sc, head, reason)
		return
	}
	conv.Members = conv.Membership.MemberIDs()
	conv.Log = append(conv.Log, sc)
	if len(eff.Added) > 0 {
		s.ensurePairwiseConvsLocked(conv.Members)
	}

	// Everyone who was a member before the change hears of it, including whoever
	// it removed, who has to learn it stopped being one. A new member is told too,
	// and is sent the whole log by the first LogRq it makes.
	recipients := before
	for _, a := range eff.Added {
		recipients = append(recipients, a.ID)
	}
	var hints []common.GroupHint
	if len(eff.Added) > 0 {
		ids := make([][common.IDSize]byte, len(eff.Added))
		for i, a := range eff.Added {
			ids[i] = a.ID
		}
		hints = s.hintsLocked(ids)
	}
	out := common.GroupChangeBody{Name: conv.Name, Change: sc, Hints: hints}

	// A group nobody belongs to any more is gone.
	if len(conv.Members) == 0 {
		delete(s.convs, groupID)
	}
	s.mu.Unlock()

	s.fanOutChange(groupID, &out, recipients)
}

func (s *Server) fanOutChange(groupID [common.IDSize]byte, body *common.GroupChangeBody, to [][common.IDSize]byte) {
	enc := body.Encode()
	pkt := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlGroupChange,
			ConversationID: groupID,
			SenderID:       body.Change.Change.Actor,
			BodyLen:        uint32(len(enc)),
		},
		Body: enc,
	}
	seen := make(map[[common.IDSize]byte]struct{}, len(to))
	for _, id := range to {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		s.sendPacket(id, pkt)
	}
}

// handleGroupLogRq sends a member the changes after the version they name, then
// fresh directory hints for every current member. A member who was removed is
// not answered: the removal itself was sent to them when it happened.
func (s *Server) handleGroupLogRq(sender *Client, p common.Packet) {
	req, err := common.DecodeGroupLogRequest(p.Body)
	if err != nil {
		return
	}

	s.mu.RLock()
	conv, ok := s.convs[req.GroupID]
	if !ok || !conv.IsGroup || !conv.Membership.IsMember(sender.UserID) {
		s.mu.RUnlock()
		log.Printf("[WARNING] CtrlGroupLogRq from %x for group %x they are not a member of",
			sender.UserID[:4], req.GroupID[:4])
		return
	}
	var changes []common.SignedChange
	for _, c := range conv.Log {
		if c.Change.Version > req.FromVersion {
			changes = append(changes, c)
		}
	}
	name := conv.Name
	hints := s.hintsLocked(conv.Members)
	s.mu.RUnlock()

	for _, c := range changes {
		out := common.GroupChangeBody{Name: name, Change: c}
		enc := out.Encode()
		s.sendPacket(sender.UserID, common.Packet{
			Header: common.Header{
				MsgType: common.CtrlGroupChange, ConversationID: req.GroupID,
				SenderID: c.Change.Actor, BodyLen: uint32(len(enc)),
			},
			Body: enc,
		})
	}
	enc := common.EncodeGroupHints(req.GroupID, hints)
	s.sendPacket(sender.UserID, common.Packet{
		Header: common.Header{MsgType: common.CtrlGroupHints, ConversationID: req.GroupID, BodyLen: uint32(len(enc))},
		Body:   enc,
	})
}

// handleUserLookup answers a username with the ID and bundle behind it, which is
// what a client needs to name someone in a membership change it signs.
func (s *Server) handleUserLookup(sender *Client, p common.Packet) {
	name := string(p.Body)

	s.mu.RLock()
	var body []byte
	if id, ok := s.usernames[name]; ok {
		if u := s.users[id]; u != nil && u.IdentityKey != ([32]byte{}) {
			body = (&common.UserLookup{ID: id, Name: u.Username, Bundle: u.Bundle}).Encode()
		}
	}
	s.mu.RUnlock()

	s.sendPacket(sender.UserID, common.Packet{
		Header: common.Header{
			MsgType: common.CtrlUserLookupAck, MessageID: p.Header.MessageID, BodyLen: uint32(len(body)),
		},
		Body: body,
	})
}
