package core

import (
	"bytes"
	common "common"
	"reflect"
	"slices"
	"testing"
	"time"
)

// The server restarting, through the real binary: stopped with SIGTERM, started
// again on the same database, certificate and port.

// reconnectClient signs the client under test in again on its own keys.
func reconnectClient(t *testing.T, addr, name string) {
	t.Helper()
	c := dialTLS(t, addr)
	tcl.conn = c
	if _, _, err := tcl.performAuth(common.CtrlLogin, name, testPassword); err != nil {
		t.Fatalf("signing in again: %v", err)
	}
	clientIn = decodeInto(c)
}

func TestE2EARestartLosesNothing(t *testing.T) {
	srv := startServerProc(t)
	addr := srv.addr
	bob := dialParty(t, addr, "bob")
	carol := dialParty(t, addr, "carol")
	aliceID := startClient(t, addr, "alice")

	go tcl.CreateGroup("team", []string{"bob", "carol"})
	pumpUntil(t, common.CtrlGroupChange, 5*time.Second)
	gid := groupNamed("team")
	bob.follow(5 * time.Second)
	carol.follow(5 * time.Second)
	tcl.sendText(gid, "before the restart")
	bob.readGroupText(5 * time.Second)
	carol.readGroupText(5 * time.Second)

	tcl.startPrivateChat("bob")
	pumpUntil(t, common.CtrlDirectAck, 5*time.Second)
	dm := common.HashIDs(aliceID, bob.id)
	tcl.sendText(dm, "a chat before the restart")
	bob.readDM(5 * time.Second)

	// carol is away when bob writes to the group.
	carol.conn.Close()
	time.Sleep(100 * time.Millisecond)
	bob.sendGroupText(gid, "while carol is away")
	if !pumpUntilCond(t, 5*time.Second, func() bool {
		pk := gstateOf(tcl.sessionMgr, gid).peerKeys(bob.id)
		return pk != nil && pk.Current != nil && pk.Current.N >= 1
	}) {
		t.Fatal("alice did not read bob")
	}

	srv.stop()
	srv.start()

	// What was waiting for carol is still waiting, sender key and all.
	carol = reloginParty(t, addr, carol)
	if got := carol.readGroupText(5 * time.Second); got != "while carol is away" {
		t.Fatalf("carol read %q", got)
	}
	bob = reloginParty(t, addr, bob)
	reconnectClient(t, addr, "alice")

	// The group and the chat carry on.
	tcl.sendText(gid, "after the restart")
	for _, p := range []*party{bob, carol} {
		if got := p.readGroupText(5 * time.Second); got != "after the restart" {
			t.Fatalf("%s read %q", p.name, got)
		}
	}
	bob.sendDM(dm, "a chat after the restart")
	if !pumpUntilCond(t, 5*time.Second, func() bool {
		st, ok := sessionWith(dm)
		return ok && st.Recv.N >= 1
	}) {
		t.Fatal("alice did not read bob's message after the restart")
	}

	// A membership change builds on the log the server kept.
	tcl.makeGroupAdmin(gid, "bob")
	upd := bob.follow(5 * time.Second)
	if upd.Version != 2 || len(upd.Effects) != 1 || upd.Effects[0].Action != common.ActionPromote {
		t.Fatalf("bob applied %+v", upd)
	}
}

func comparableGroup(st groupState) groupState {
	slices.SortFunc(st.Hints, func(a, b hintRec) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return st
}

// After a crash the server delivers again what it had written but not yet
// deleted. Everything a client receives must be harmless the second time: a
// direct message, a group message, a sender key, a membership change and a
// key-change notice, delivered twice, leave the client exactly as once did.
func TestRedeliveredPacketsChangeNothing(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	oldAlice := dialParty(t, addr, "alice")
	startClient(t, addr, "carol")
	carolKey := tcl.selfKey()

	var seen []common.Packet
	pumpRec := func(cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatal("the client never got there")
			}
			select {
			case pkt := <-clientIn:
				seen = append(seen, clonePacket(pkt))
				tcl.deliver(pkt)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

	gid := genID()
	sc := common.SignChange(bob.sm.identity.SigningSeed, common.GroupChange{
		GroupID: gid, Version: 1, Action: common.ActionCreate, Actor: bob.id, Timestamp: time.Now().Unix(),
		Targets: []common.MemberKey{keyOf(bob), carolKey, keyOf(oldAlice)},
	})
	body := (&common.GroupChangeBody{Name: "team", Change: sc}).Encode()
	bob.send(&common.Packet{Header: common.Header{MsgType: common.CtrlGroupCreate, BodyLen: uint32(len(body))}, Body: body})
	bob.follow(5 * time.Second)
	oldAlice.follow(5 * time.Second)
	pumpRec(func() bool { _, ok := tcl.sessionMgr.Group(gid); return ok })

	bob.sendGroupText(gid, "hello group")
	pumpRec(func() bool {
		pk := gstateOf(tcl.sessionMgr, gid).peerKeys(bob.id)
		return pk != nil && pk.Current != nil && pk.Current.N >= 1
	})
	dm := bob.openDM("carol")
	bob.sendDM(dm, "hello carol")
	pumpRec(func() bool { st, ok := sessionWith(dm); return ok && st.Recv.N >= 1 && st.PeerSigning != ([32]byte{}) })

	newAlice := loginParty(t, addr, "alice")
	pumpRec(func() bool { k, _ := tcl.mgr.GetPublicKey(newAlice.id); return k == newAlice.pub })

	group := comparableGroup(gstateOf(tcl.sessionMgr, gid))
	chat, _ := sessionWith(dm)
	held := tcl.pending.Len()
	kinds := map[uint8]bool{}
	for _, p := range seen {
		kinds[p.Header.MsgType] = true
	}
	for _, k := range []uint8{common.CtrlGroupChange, common.CtrlSenderKey, common.MsgText, common.CtrlKeyChange} {
		if !kinds[k] {
			t.Fatalf("setup: the client was never sent a packet of type %#x", k)
		}
	}

	events := captureEvents(t)
	for _, p := range seen {
		tcl.deliver(clonePacket(p))
	}

	if got := comparableGroup(gstateOf(tcl.sessionMgr, gid)); !reflect.DeepEqual(got, group) {
		t.Fatal("delivering the same packets again changed the group state")
	}
	if got, _ := sessionWith(dm); !reflect.DeepEqual(got, chat) {
		t.Fatal("delivering the same packets again changed the chat's session")
	}
	if tcl.pending.Len() != held {
		t.Fatalf("delivering the same packets again left %d held, was %d", tcl.pending.Len(), held)
	}
	if w := events.worrying(); len(w) > 0 {
		t.Fatalf("delivering the same packets again told the user: %s", w[0].Text)
	}
}
