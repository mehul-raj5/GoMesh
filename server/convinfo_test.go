package main

import (
	"bytes"
	common "common"
	"net"
	"testing"
	"time"
)

// convInfoRq asks the server for the roster of convID.
func convInfoRq(t *testing.T, c net.Conn, convID [16]byte) {
	t.Helper()
	pkt := common.Packet{
		Header: common.Header{MsgType: common.CtrlConvInfoRq, BodyLen: 16},
		Body:   convID[:],
	}
	if err := pkt.Encode(c); err != nil {
		t.Fatalf("conv info request: %v", err)
	}
}

// readUntil drains packets until one of msgType arrives, or the deadline passes.
func readUntil(t *testing.T, c net.Conn, msgType uint8, within time.Duration) common.Packet {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		c.SetReadDeadline(deadline)
		p, err := decode(c)
		if err != nil {
			t.Fatalf("waiting for type %#x: %v", msgType, err)
		}
		if p.Header.MsgType == msgType {
			return p
		}
	}
}

// expectSilence fails if anything arrives before the window closes.
func expectSilence(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(within))
	p, err := decode(c)
	if err == nil {
		t.Fatalf("expected no reply, got packet type %#x", p.Header.MsgType)
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected a read timeout, got %v", err)
	}
}

// openDM performs a CtrlDirectInit and returns the conversation ID plus the ack.
func openDM(t *testing.T, c net.Conn, target string) ([16]byte, common.Packet) {
	t.Helper()
	init := common.Packet{
		Header: common.Header{MsgType: common.CtrlDirectInit, BodyLen: uint32(len(target))},
		Body:   []byte(target),
	}
	if err := init.Encode(c); err != nil {
		t.Fatalf("direct init: %v", err)
	}
	ack := readUntil(t, c, common.CtrlDirectAck, 3*time.Second)
	var convID [16]byte
	copy(convID[:], ack.Body[:16])
	return convID, ack
}

// The roster is the only route to another user's identity key, so a non-member
// asking for one must come away with nothing.
func TestConvInfoRequiresMembership(t *testing.T) {
	_, addr := startServer(t)

	alice, aliceID := login(t, addr, "alice", 1)
	defer alice.Close()
	bob, bobID := login(t, addr, "bob", 2)
	defer bob.Close()
	carol, _ := login(t, addr, "carol", 3)
	defer carol.Close()

	convID, _ := openDM(t, alice, "bob")

	// A member gets the roster.
	convInfoRq(t, alice, convID)
	ack := readUntil(t, alice, common.CtrlConvInfoAck, 3*time.Second)

	info, err := common.DecodeConvInfo(ack.Body)
	if err != nil {
		t.Fatalf("decode conv info: %v", err)
	}
	if info.IsGroup {
		t.Error("a direct conversation was reported as a group")
	}
	if len(info.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(info.Members))
	}

	byID := map[[16]byte]common.ConvMember{}
	for _, m := range info.Members {
		byID[m.UserID] = m
	}
	if m, ok := byID[bobID]; !ok {
		t.Error("bob missing from the roster")
	} else {
		if m.Name != "bob" {
			t.Errorf("bob's name: got %q want %q", m.Name, "bob")
		}
		if !bytes.Equal(m.PubKey[:], bytes.Repeat([]byte{2}, 32)) {
			t.Errorf("bob's identity key not carried in the roster: %x", m.PubKey)
		}
	}
	if _, ok := byID[aliceID]; !ok {
		t.Error("alice missing from her own roster")
	}

	// A non-member gets no reply at all.
	convInfoRq(t, carol, convID)
	expectSilence(t, carol, 700*time.Millisecond)
	t.Log("ok: non-member roster request dropped without a reply")
}

func TestConvInfoReportsGroupRoster(t *testing.T) {
	_, addr := startServer(t)

	alice, bob, carol := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3)
	g := createGroup(t, alice, "g", bob, carol)

	convInfoRq(t, bob.conn, g.id)
	ack := readUntil(t, bob.conn, common.CtrlConvInfoAck, 3*time.Second)

	info, err := common.DecodeConvInfo(ack.Body)
	if err != nil {
		t.Fatalf("decode conv info: %v", err)
	}
	if !info.IsGroup {
		t.Error("group reported as a direct conversation")
	}
	if info.Name != "g" {
		t.Errorf("group name: got %q", info.Name)
	}
	if len(info.Members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(info.Members))
	}
	for _, m := range info.Members {
		if m.PubKey == [32]byte{} {
			t.Errorf("member %s carries a zero identity key", m.Name)
		}
	}
}

// Sender keys travel over the 1-1 channel each pair of members shares. Those
// conversations must exist server-side the moment the group does, or the very
// first key distribution is dropped as traffic for an unknown conversation.
func TestGroupCreateRegistersPairwiseConvs(t *testing.T) {
	srv, addr := startServer(t)

	alice, bob, carol := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3)
	createGroup(t, alice, "g", bob, carol)

	// bob and carol never exchanged a CtrlDirectInit, yet the server should
	// already know the conversation between them.
	pairID := common.HashIDs(bob.id, carol.id)
	srv.mu.RLock()
	_, known := srv.convs[pairID]
	srv.mu.RUnlock()
	if !known {
		t.Fatal("pairwise conversation between two group members was not registered")
	}

	// And it should relay a sender key across it.
	payload := (&common.SenderKeyDist{GroupID: pairID, KeyID: 1}).Encode()
	key := common.Packet{
		Header: common.Header{
			MsgType:        common.CtrlSenderKey,
			ConversationID: pairID,
			BodyLen:        uint32(len(payload)),
		},
		Body: payload,
	}
	if err := key.Encode(bob.conn); err != nil {
		t.Fatalf("send sender key: %v", err)
	}

	got := readUntil(t, carol.conn, common.CtrlSenderKey, 3*time.Second)
	if got.Header.SenderID != bob.id {
		t.Errorf("sender id: got %x want %x", got.Header.SenderID, bob.id)
	}
	t.Log("ok: sender key relayed between members with no prior direct init")
}

// A sender key is addressed to one person. Sent to a group it would reach all of
// them, so the server refuses to fan one out.
func TestSenderKeyIsNotRelayedToAGroup(t *testing.T) {
	_, addr := startServer(t)

	alice, bob, carol := newUser(t, addr, "alice", 1), newUser(t, addr, "bob", 2), newUser(t, addr, "carol", 3)
	g := createGroup(t, alice, "g", bob, carol)
	readUntil(t, carol.conn, common.CtrlGroupChange, 3*time.Second)

	payload := (&common.SenderKeyDist{GroupID: g.id, KeyID: 1}).Encode()
	key := common.Packet{
		Header: common.Header{MsgType: common.CtrlSenderKey, ConversationID: g.id, BodyLen: uint32(len(payload))},
		Body:   payload,
	}
	if err := key.Encode(bob.conn); err != nil {
		t.Fatal(err)
	}
	expectSilence(t, carol.conn, 500*time.Millisecond)
}
