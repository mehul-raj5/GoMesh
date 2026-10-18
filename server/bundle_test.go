package main

import (
	common "common"
	"testing"
	"time"
)

func TestLoginRejectsBadPreKeySignature(t *testing.T) {
	_, addr := startServer(t)

	b := testBundle(1)
	b.SPK[0] ^= 1
	_, reply := authAttempt(t, addr, common.CtrlRegister, "mallory", testPassword, b, testSeed(1))
	if reply.Header.MsgType == common.CtrlLoginAck {
		t.Fatal("a bundle with a forged prekey was admitted")
	}
}

func TestLoginRejectsMalformedBundle(t *testing.T) {
	_, addr := startServer(t)

	c := dial(t, addr)
	body := append(make([]byte, 32), "bob"...) // the oldest login format
	pkt := common.Packet{Header: common.Header{MsgType: common.CtrlLogin, BodyLen: uint32(len(body))}, Body: body}
	pkt.Encode(c)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply, err := common.Decode(c)
	if err == nil && reply.Header.MsgType == common.CtrlLoginAck {
		t.Fatal("old-format login was admitted")
	}
	if err == nil && errCode(reply) != common.ErrBadRequest {
		t.Fatalf("malformed login answered with %s, want bad request", errCode(reply))
	}
}

// The same device signing in again with its password may present a newer
// signed prekey, which is how it rotates one, and stays the same device.
func TestPreKeyRotatesOnLogin(t *testing.T) {
	srv, addr := startServer(t)

	first := testBundle(1)
	c, id, _ := register(t, addr, "alice", 1)
	c.Close()
	srv.mu.RLock()
	device := srv.users[id].Device.ID
	srv.mu.RUnlock()

	rotated := *first
	rotated.SPKID = 2
	rotated.SPK = [32]byte{9, 9, 9}
	seed := testSeed(1)
	rotated.SPKSig = common.SignPreKey(seed, rotated.SPKID, rotated.SPK)
	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, &rotated, seed)
	if got, _ := ackOf(t, reply); got != id {
		t.Fatal("logging in again gave a different user ID")
	}

	srv.mu.RLock()
	stored := srv.users[id].Bundle
	same := srv.users[id].Device.ID == device
	srv.mu.RUnlock()
	if stored.SPKID != 2 || stored.SPK != rotated.SPK {
		t.Fatal("server did not keep the rotated prekey")
	}
	if !same {
		t.Fatal("rotating a prekey was treated as a new device")
	}
}

func TestDirectAckCarriesTargetsVerifiableBundle(t *testing.T) {
	_, addr := startServer(t)

	alice, _ := login(t, addr, "alice", 1)
	defer alice.Close()
	bob, bobID := login(t, addr, "bob", 2)
	defer bob.Close()

	_, ack := openDM(t, alice, "bob")

	// convID(16) || peerID(16) || bundle || name
	if len(ack.Body) < 32+common.PreKeyBundleSize {
		t.Fatalf("ack too short for a bundle: %d", len(ack.Body))
	}
	var peerID [16]byte
	copy(peerID[:], ack.Body[16:32])
	if peerID != bobID {
		t.Fatal("ack names the wrong peer")
	}
	b, err := common.DecodePreKeyBundle(ack.Body[32:])
	if err != nil {
		t.Fatal(err)
	}
	if !b.Verify() {
		t.Fatal("the bundle in the ack does not verify")
	}
	if b != *testBundle(2) {
		t.Fatal("the ack carried a different bundle from the one bob registered")
	}
	if name := string(ack.Body[32+common.PreKeyBundleSize:]); name != "bob" {
		t.Fatalf("peer name = %q", name)
	}
}

func TestConvInfoCarriesSigningKey(t *testing.T) {
	_, addr := startServer(t)

	alice, _ := login(t, addr, "alice", 1)
	defer alice.Close()
	bob, _ := login(t, addr, "bob", 2)
	defer bob.Close()

	convID, _ := openDM(t, alice, "bob")
	rq := common.Packet{
		Header: common.Header{MsgType: common.CtrlConvInfoRq, ConversationID: convID, BodyLen: 16},
		Body:   convID[:],
	}
	if err := rq.Encode(alice); err != nil {
		t.Fatal(err)
	}
	reply := readUntil(t, alice, common.CtrlConvInfoAck, 3*time.Second)
	info, err := common.DecodeConvInfo(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range info.Members {
		want := testBundle(1)
		if m.PubKey == testBundle(2).IdentityKey {
			want = testBundle(2)
		}
		if m.SigningKey != want.SigningKey {
			t.Fatalf("member %s: signing key missing from the roster", m.Name)
		}
	}
}

// Knowing a user's public bundle, which the server hands to anyone, is not
// enough to log in as them, even with their password: the device must also
// hold the signing key the bundle names.
func TestLoginRequiresTheSigningKey(t *testing.T) {
	srv, addr := startServer(t)
	register(t, addr, "alice", 1)

	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(99))
	if reply.Header.MsgType == common.CtrlLoginAck {
		t.Fatal("logged in as alice with only her public bundle")
	}

	srv.mu.RLock()
	n := len(srv.users)
	srv.mu.RUnlock()
	if n != 1 {
		t.Fatalf("a failed login created or changed accounts: %d users", n)
	}
}

func TestLoginProofIsBoundToTheChallenge(t *testing.T) {
	_, addr := startServer(t)
	register(t, addr, "alice", 1)

	// Capture a valid proof from one connection...
	b := testBundle(1)
	c1 := dial(t, addr)
	sendCredentials(t, c1, common.CtrlLogin, "alice", testPassword, b)
	ch1, err := common.Decode(c1)
	if err != nil || ch1.Header.MsgType != common.CtrlLoginChallenge {
		t.Fatalf("challenge: %v", err)
	}
	var n1 [common.LoginNonceSize]byte
	copy(n1[:], ch1.Body)
	old := common.SignLogin(testSeed(1), n1, b.IdentityKey, "alice")

	// ...and replay it on a second connection, which gets a different nonce.
	c2 := dial(t, addr)
	sendCredentials(t, c2, common.CtrlLogin, "alice", testPassword, b)
	ch2, err := common.Decode(c2)
	if err != nil {
		t.Fatal(err)
	}
	if string(ch1.Body) == string(ch2.Body) {
		t.Fatal("two logins were issued the same challenge")
	}
	(&common.Packet{Header: common.Header{MsgType: common.CtrlLoginProof, BodyLen: common.SignatureSize}, Body: old[:]}).Encode(c2)
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if reply, err := common.Decode(c2); err == nil && reply.Header.MsgType == common.CtrlLoginAck {
		t.Fatal("a proof signed over a different challenge was accepted")
	}
}

func TestLoginProofIsBoundToTheUsername(t *testing.T) {
	_, addr := startServer(t)

	// A proof made for "bob" must not open "alice", even with the same keys.
	b := testBundle(1)
	c := dial(t, addr)
	sendCredentials(t, c, common.CtrlRegister, "alice", testPassword, b)
	ch, err := common.Decode(c)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [common.LoginNonceSize]byte
	copy(nonce[:], ch.Body)
	sig := common.SignLogin(testSeed(1), nonce, b.IdentityKey, "bob")
	(&common.Packet{Header: common.Header{MsgType: common.CtrlLoginProof, BodyLen: common.SignatureSize}, Body: sig[:]}).Encode(c)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if reply, err := common.Decode(c); err == nil && reply.Header.MsgType == common.CtrlLoginAck {
		t.Fatal("a proof made for another username was accepted")
	}
}

func TestLoginWithoutAProofIsRefused(t *testing.T) {
	_, addr := startServer(t)

	c := dial(t, addr)
	sendCredentials(t, c, common.CtrlRegister, "alice", testPassword, testBundle(1))
	if _, err := common.Decode(c); err != nil { // the challenge
		t.Fatal(err)
	}
	// Skip the proof and send a data packet instead.
	(&common.Packet{Header: common.Header{MsgType: common.MsgText}}).Encode(c)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if reply, err := common.Decode(c); err == nil && reply.Header.MsgType == common.CtrlLoginAck {
		t.Fatal("admitted without a proof")
	}
}
