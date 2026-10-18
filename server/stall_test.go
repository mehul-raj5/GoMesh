package main

import (
	common "common"
	"net"
	"runtime"
	"testing"
	"time"
)

// testSeed is the signing seed behind testBundle(keyByte).
func testSeed(keyByte byte) (k [32]byte) {
	for i := range k {
		k[i] = keyByte ^ 0x5a
	}
	return
}

// testBundle builds a valid bundle whose identity key is keyByte repeated, so
// tests can recognise a user's key on the wire. The server only checks that the
// prekey signature is genuine, so the other keys need not be real curve points.
func testBundle(keyByte byte) *common.PreKeyBundle {
	fill := func(b byte) (k [32]byte) {
		for i := range k {
			k[i] = b
		}
		return
	}
	seed := testSeed(keyByte)
	b := &common.PreKeyBundle{
		IdentityKey: fill(keyByte),
		SigningKey:  common.SigningPublicFromSeed(seed),
		SPKID:       1,
		SPK:         fill(keyByte ^ 0xa5),
	}
	b.SPKSig = common.SignPreKey(seed, b.SPKID, b.SPK)
	return b
}

// answerChallenge reads the server's challenge, signs it with seed, and returns
// whatever the server says next. A closed connection is reported as a zero
// packet so a test can tell rejection from acceptance.
func answerChallenge(t *testing.T, c net.Conn, name string, b *common.PreKeyBundle, seed [32]byte) common.Packet {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	ch, err := common.Decode(c)
	if err == nil && ch.Header.MsgType == common.CtrlError {
		return ch // refused before the challenge, e.g. a wrong password
	}
	if err != nil || ch.Header.MsgType != common.CtrlLoginChallenge || len(ch.Body) != common.LoginNonceSize {
		return common.Packet{}
	}
	var nonce [common.LoginNonceSize]byte
	copy(nonce[:], ch.Body)
	sig := common.SignLogin(seed, nonce, b.IdentityKey, name)
	proof := common.Packet{
		Header: common.Header{MsgType: common.CtrlLoginProof, BodyLen: common.SignatureSize},
		Body:   sig[:],
	}
	if err := proof.Encode(c); err != nil {
		t.Fatalf("proof encode: %v", err)
	}
	reply, err := common.Decode(c)
	if err != nil {
		return common.Packet{}
	}
	c.SetReadDeadline(time.Time{})
	return reply
}

// login signs name in with the test bundle for keyByte: it registers the
// account, or logs in with the password if the name is already registered.
// Registering first means a new name never counts as a failed login.
func login(t *testing.T, addr, name string, keyByte byte) (net.Conn, [16]byte) {
	t.Helper()
	c, reply := authAttempt(t, addr, common.CtrlRegister, name, testPassword, testBundle(keyByte), testSeed(keyByte))
	if reply.Header.MsgType == common.CtrlError {
		c.Close()
		if code := errCode(reply); code != common.ErrUsernameTaken {
			t.Fatalf("register %s: %s", name, code)
		}
		c, reply = authAttempt(t, addr, common.CtrlLogin, name, testPassword, testBundle(keyByte), testSeed(keyByte))
	}
	if reply.Header.MsgType != common.CtrlLoginAck {
		t.Fatalf("login %s: reply type=%#x %s", name, reply.Header.MsgType, errCode(reply))
	}
	id, _, err := common.DecodeLoginAck(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	return c, id
}

// TestStalledConsumerIsDisconnected verifies that a peer which never reads gets
// dropped instead of parking a goroutine forever, and that the server survives.
func TestStalledConsumerIsDisconnected(t *testing.T) {
	_, addr := startServer(t)

	alice, _ := login(t, addr, "alice", 1)
	defer alice.Close()
	bob, _ := login(t, addr, "bob", 2)
	defer bob.Close()

	// alice opens a DM with bob; the ack carries the conversation ID.
	init := common.Packet{
		Header: common.Header{MsgType: common.CtrlDirectInit, BodyLen: 3},
		Body:   []byte("bob"),
	}
	if err := init.Encode(alice); err != nil {
		t.Fatalf("init: %v", err)
	}
	ack, err := common.Decode(alice)
	if err != nil || ack.Header.MsgType != common.CtrlDirectAck {
		t.Fatalf("direct ack: %v type=%d", err, ack.Header.MsgType)
	}
	var convID [16]byte
	copy(convID[:], ack.Body[:16])

	before := runtime.NumGoroutine()

	// bob deliberately never reads. Blast enough to overflow socket + channel.
	payload := make([]byte, 4096)
	for i := 0; i < 3000; i++ {
		msg := common.Packet{
			Header: common.Header{
				MsgType:        common.MsgText,
				ConversationID: convID,
				BodyLen:        uint32(len(payload)),
			},
			Body: payload,
		}
		if err := msg.Encode(alice); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	// bob should be disconnected rather than buffered indefinitely.
	bob.SetReadDeadline(time.Now().Add(25 * time.Second))
	var read int
	for {
		p, err := common.Decode(bob)
		if err != nil {
			t.Logf("bob disconnected after %d packets: %v", read, err)
			break
		}
		read += int(p.Header.BodyLen)
		if read > 200<<20 {
			t.Fatal("bob never disconnected; server buffered unboundedly")
		}
	}

	time.Sleep(500 * time.Millisecond)
	after := runtime.NumGoroutine()
	t.Logf("goroutines: before=%d after=%d", before, after)
	if after > before+50 {
		t.Errorf("goroutine leak: before=%d after=%d", before, after)
	}

	// The server must still be serving other clients.
	alice.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := common.Decode(alice); err != nil {
		t.Logf("alice read (expected timeout/none): %v", err)
	}
	carol, _ := login(t, addr, "carol", 3)
	carol.Close()
}
