package core

import (
	common "common"
	"errors"
	"testing"
	"time"
)

// Moving an account to a new device through the real server.

// loginParty signs an existing account in from a new party with fresh keys,
// which makes it that account's new device.
func loginParty(t *testing.T, addr, name string) *party {
	t.Helper()
	return loginWith(t, addr, name, NewSessionManager(newTestIdentity(t), [16]byte{}))
}

// reloginParty signs a party in again on the keys it already has: the same
// device, back after a disconnect or a server restart.
func reloginParty(t *testing.T, addr string, p *party) *party {
	t.Helper()
	return loginWith(t, addr, p.name, p.sm)
}

// loginWith logs name in with password and the identity behind sm. A session
// manager made before the user ID was known is rebuilt around it.
func loginWith(t *testing.T, addr, name string, sm *SessionManager) *party {
	t.Helper()
	im := sm.identity
	c := dialTLS(t, addr)
	body, err := common.EncodeCredentials(&common.Credentials{Username: name, Password: testPassword, Bundle: im.Bundle()})
	if err != nil {
		t.Fatal(err)
	}
	(&common.Packet{Header: common.Header{MsgType: common.CtrlLogin, BodyLen: uint32(len(body))}, Body: body}).Encode(c)
	ch, err := common.Decode(c)
	if err != nil || ch.Header.MsgType != common.CtrlLoginChallenge {
		t.Fatalf("challenge: %v type=%#x", err, ch.Header.MsgType)
	}
	var nonce [common.LoginNonceSize]byte
	copy(nonce[:], ch.Body)
	sig := im.SignLogin(nonce, name)
	(&common.Packet{Header: common.Header{MsgType: common.CtrlLoginProof, BodyLen: common.SignatureSize}, Body: sig[:]}).Encode(c)
	ack, err := common.Decode(c)
	if err != nil || ack.Header.MsgType != common.CtrlLoginAck {
		t.Fatalf("login ack: %v type=%#x", err, ack.Header.MsgType)
	}
	id, _, _ := common.DecodeLoginAck(ack.Body)
	if sm.selfID != id {
		sm = NewSessionManager(im, id)
	}
	return &party{t: t, conn: c, id: id, pub: im.PublicKey, name: name, sm: sm, in: decodeInto(c)}
}

func keyOf(p *party) common.MemberKey {
	return common.MemberKey{ID: p.id, IdentityKey: p.sm.identity.PublicKey, SigningKey: p.sm.identity.SigningKey}
}

// openDM asks the server for a chat with target and opens the session.
func (p *party) openDM(target string) [16]byte {
	p.t.Helper()
	p.send(&common.Packet{Header: common.Header{MsgType: common.CtrlDirectInit, BodyLen: uint32(len(target))}, Body: []byte(target)})
	convID, peerID, b, name := parseDirectAck(p.t, p.await(common.CtrlDirectAck, 5*time.Second))
	if _, err := p.sm.OpenDirectSession(convID, peerID, name, b, false); err != nil {
		p.t.Fatal(err)
	}
	return convID
}

func (p *party) sendDM(convID [16]byte, text string) {
	p.t.Helper()
	pkt := common.Packet{Header: common.Header{MsgType: common.MsgText, ConversationID: convID, SenderID: p.id, BodyLen: uint32(len(text))}, Body: []byte(text)}
	if err := p.sm.EncryptPacket(&pkt); err != nil {
		p.t.Fatalf("%s: encrypt: %v", p.name, err)
	}
	p.send(&pkt)
}

func (p *party) readDM(within time.Duration) string {
	p.t.Helper()
	for {
		pkt := p.await(common.MsgText, within)
		err := p.sm.DecryptPacket(&pkt)
		if errors.Is(err, ErrAlreadyRead) {
			continue // delivered again, as a real client would ignore it
		}
		if err != nil {
			p.t.Fatalf("%s: decrypt: %v", p.name, err)
		}
		return string(pkt.Body)
	}
}

// keyChange is what a party does with the server's key-change notice: replace
// any direct session on the new bundle, and note the directory's key.
func (p *party) keyChange(within time.Duration) common.UserLookup {
	p.t.Helper()
	kc, err := common.DecodeUserLookup(p.await(common.CtrlKeyChange, within).Body)
	if err != nil {
		p.t.Fatal(err)
	}
	convID := common.HashIDs(p.id, kc.ID)
	if _, ok := p.sm.GetSession(convID); ok {
		if _, err := p.sm.OpenDirectSession(convID, kc.ID, kc.Name, kc.Bundle, false); err != nil {
			p.t.Fatal(err)
		}
	}
	p.sm.NoteDirectoryKey(kc.ID, kc.Bundle.IdentityKey)
	return kc
}

func sessionWith(convID [16]byte) (sessionState, bool) {
	sess, ok := tcl.sessionMgr.GetSession(convID)
	if !ok {
		return sessionState{}, false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return *sess.st.clone(), true
}

// The client under test is alice's new device. It is told its groups at login,
// fetches the log, rekeys the group, and talks in it; the old device is signed
// out and the others carry on.
func TestE2EMovedDeviceRekeysItsGroups(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	carol := dialParty(t, addr, "carol")
	oldAlice := dialParty(t, addr, "alice")

	gid := genID()
	sc := common.SignChange(bob.sm.identity.SigningSeed, common.GroupChange{
		GroupID: gid, Version: 1, Action: common.ActionCreate, Actor: bob.id, Timestamp: time.Now().Unix(),
		Targets: []common.MemberKey{keyOf(bob), keyOf(oldAlice), keyOf(carol)},
	})
	body := (&common.GroupChangeBody{Name: "team", Change: sc}).Encode()
	bob.send(&common.Packet{Header: common.Header{MsgType: common.CtrlGroupCreate, BodyLen: uint32(len(body))}, Body: body})
	for _, p := range []*party{bob, carol, oldAlice} {
		p.follow(5 * time.Second)
	}
	bob.sendGroupText(gid, "before the move")
	for _, p := range []*party{carol, oldAlice} {
		if got := p.readGroupText(5 * time.Second); got != "before the move" {
			t.Fatalf("%s read %q", p.name, got)
		}
	}

	aliceID := startClientAs(t, addr, "alice", common.CtrlLogin)
	if aliceID != oldAlice.id {
		t.Fatal("the new device got a different user ID")
	}
	if e, _ := common.DecodeError(oldAlice.await(common.CtrlError, 5*time.Second).Body); e == nil || e.Code != common.ErrDeviceReplaced {
		t.Fatalf("the old device was told %v", e)
	}
	for _, p := range []*party{bob, carol} {
		if kc := p.keyChange(5 * time.Second); kc.ID != aliceID || kc.Bundle.IdentityKey != tcl.idMgr.PublicKey {
			t.Fatalf("%s was told the wrong keys", p.name)
		}
	}

	// The client finds the group, catches up, and rekeys it, on its own.
	if !pumpUntilCond(t, 15*time.Second, func() bool {
		_, known := tcl.sessionMgr.Group(gid)
		return known && !tcl.needsRekey(gid)
	}) {
		t.Fatal("the new device never rekeyed the group")
	}
	for _, p := range []*party{bob, carol} {
		upd := p.follow(5 * time.Second)
		if len(upd.Effects) != 1 || upd.Effects[0].Action != common.ActionRekey {
			t.Fatalf("%s applied %+v", p.name, upd.Effects)
		}
	}

	tcl.sendText(gid, "from alice's new device")
	for _, p := range []*party{bob, carol} {
		if got := p.readGroupText(5 * time.Second); got != "from alice's new device" {
			t.Fatalf("%s read %q", p.name, got)
		}
	}

	bob.sendGroupText(gid, "welcome back")
	if !pumpUntilCond(t, 10*time.Second, func() bool {
		pk := gstateOf(tcl.sessionMgr, gid).peerKeys(bob.id)
		return pk != nil && pk.Current != nil && pk.Current.N >= 1
	}) {
		t.Fatal("the new device did not read bob's reply")
	}
	if got := carol.readGroupText(5 * time.Second); got != "welcome back" {
		t.Fatalf("carol read %q", got)
	}
}

// The mover writes first, and the client under test never saw the key-change
// notice: the handshake under unknown keys is held, the roster settles it, and
// the message is read.
func TestE2EMovedPeerIsReadWithoutTheNotice(t *testing.T) {
	addr := startServer(t)
	oldAlice := dialParty(t, addr, "alice")
	bobID := startClient(t, addr, "bob")

	tcl.startPrivateChat("alice")
	pumpUntil(t, common.CtrlDirectAck, 5*time.Second)
	convID := common.HashIDs(bobID, oldAlice.id)
	tcl.sendText(convID, "hi alice")
	if got := oldAlice.readDM(5 * time.Second); got != "hi alice" {
		t.Fatalf("alice read %q", got)
	}

	newAlice := loginParty(t, addr, "alice")
	newAlice.openDM("bob")
	newAlice.sendDM(convID, "it's me, on my new phone")

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case pkt := <-clientIn:
			if pkt.Header.MsgType == common.CtrlKeyChange {
				continue // lost
			}
			tcl.deliver(pkt)
		case <-time.After(200 * time.Millisecond):
		}
		if st, ok := sessionWith(convID); ok && st.PeerIK == newAlice.pub && st.Recv.N >= 1 && tcl.pending.Len() == 0 {
			return
		}
	}
	st, _ := sessionWith(convID)
	t.Fatalf("the message from the new device was not read: session key new=%v, received=%d, held=%d",
		st.PeerIK == newAlice.pub, st.Recv.N, tcl.pending.Len())
}

// A peer that writes on the old session before hearing of the move is asked to
// start over, and the chat carries on once it does.
func TestE2EPeerOnTheOldSessionIsAskedToStartOver(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	oldAlice := dialParty(t, addr, "alice")
	convID := bob.openDM("alice")
	bob.sendDM(convID, "hi")
	oldAlice.readDM(5 * time.Second)
	oldAlice.sendDM(convID, "hey")
	bob.readDM(5 * time.Second)

	aliceID := startClientAs(t, addr, "alice", common.CtrlLogin)
	bob.sendDM(convID, "on the old session")

	if !pumpUntilCond(t, 10*time.Second, func() bool {
		tcl.resets.mu.Lock()
		defer tcl.resets.mu.Unlock()
		_, sent := tcl.resets.sent[convID]
		return sent
	}) {
		t.Fatal("the new device did not ask bob to start over")
	}
	kc := bob.keyChange(5 * time.Second)
	reset := bob.await(common.CtrlSessionReset, 5*time.Second)
	if reset.Header.SenderID != aliceID || reset.Header.ConversationID != convID {
		t.Fatal("the reset did not come from alice over their chat")
	}
	if kc.Bundle.IdentityKey != tcl.idMgr.PublicKey {
		t.Fatal("bob was told the wrong keys")
	}

	bob.sendDM(convID, "on the new session")
	if !pumpUntilCond(t, 10*time.Second, func() bool {
		st, ok := sessionWith(convID)
		return ok && st.Recv.N >= 1
	}) {
		t.Fatal("the new device did not read bob once he started over")
	}
}

// A reset from the peer starts a fresh session, as a typed /dm would, and a
// second one inside the minute is ignored.
func TestE2EAResetStartsAFreshSession(t *testing.T) {
	addr := startServer(t)
	alice := dialParty(t, addr, "alice")
	bobID := startClient(t, addr, "bob")
	tcl.startPrivateChat("alice")
	pumpUntil(t, common.CtrlDirectAck, 5*time.Second)
	convID := common.HashIDs(bobID, alice.id)
	tcl.sendText(convID, "hi")
	alice.readDM(5 * time.Second)
	alice.sendDM(convID, "hey")
	pumpUntil(t, common.MsgText, 5*time.Second)
	before, _ := sessionWith(convID)
	if before.Pending {
		t.Fatal("setup: the session should be established")
	}

	reset := common.Packet{Header: common.Header{MsgType: common.CtrlSessionReset, ConversationID: convID}}
	alice.send(&reset)
	pumpUntil(t, common.CtrlDirectAck, 5*time.Second)
	after, _ := sessionWith(convID)
	if !after.Initiator || !after.Pending || after.InitEK == before.InitEK {
		t.Fatal("the reset did not start a fresh session")
	}

	alice.send(&reset)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got, ok := pumpClient(200 * time.Millisecond); ok && got == common.CtrlDirectAck {
			t.Fatal("a second reset inside the minute started another session")
		}
	}
}

// The new device's rekey loses a race with another admin's change. The server
// refuses it as stale; the client must work it out again on top of the change
// that won, without waiting for anything else to happen.
func TestE2ERekeyThatLosesARaceIsResubmitted(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	carol := dialParty(t, addr, "carol")
	oldAlice := dialParty(t, addr, "alice")

	gid := genID()
	sc := common.SignChange(bob.sm.identity.SigningSeed, common.GroupChange{
		GroupID: gid, Version: 1, Action: common.ActionCreate, Actor: bob.id, Timestamp: time.Now().Unix(),
		Targets: []common.MemberKey{keyOf(bob), keyOf(oldAlice), keyOf(carol)},
	})
	body := (&common.GroupChangeBody{Name: "team", Change: sc}).Encode()
	bob.send(&common.Packet{Header: common.Header{MsgType: common.CtrlGroupCreate, BodyLen: uint32(len(body))}, Body: body})
	for _, p := range []*party{bob, carol, oldAlice} {
		p.follow(5 * time.Second)
	}

	startClientAs(t, addr, "alice", common.CtrlLogin)
	pumpUntil(t, common.CtrlMyGroups, 5*time.Second)

	// Hold the log reply back until bob's change has landed, so the rekey the
	// client builds on it is already stale when it reaches the server.
	var held []common.Packet
	for {
		select {
		case pkt := <-clientIn:
			held = append(held, pkt)
			if pkt.Header.MsgType == common.CtrlGroupHints {
				goto heldReply
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the log reply never came")
		}
	}
heldReply:
	info, _ := bob.sm.Group(gid)
	head, _ := bob.sm.GroupHead(gid)
	promote := common.SignChange(bob.sm.identity.SigningSeed, common.GroupChange{
		GroupID: gid, Version: info.Version + 1, PrevHash: head, Action: common.ActionPromote,
		Actor: bob.id, Timestamp: time.Now().Unix(), Targets: []common.MemberKey{keyOf(carol)},
	})
	body = (&common.GroupChangeBody{Change: promote}).Encode()
	bob.send(&common.Packet{Header: common.Header{MsgType: common.CtrlGroupChange, BodyLen: uint32(len(body))}, Body: body})
	bob.follow(5 * time.Second)

	for _, pkt := range held {
		tcl.deliver(pkt)
	}
	if !pumpUntilCond(t, 5*time.Second, func() bool { return !tcl.needsRekey(gid) }) {
		t.Fatal("the rekey refused for losing the race was never resubmitted")
	}
	if v := tcl.sessionMgr.GroupVersion(gid); v != 3 {
		t.Fatalf("the group is at version %d, want the create, bob's change and the rekey", v)
	}
}
