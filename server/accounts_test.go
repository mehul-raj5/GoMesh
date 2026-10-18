package main

import (
	common "common"
	"errors"
	"net"
	"testing"
	"time"
)

func sendText(t *testing.T, c net.Conn, convID [16]byte, body string) {
	t.Helper()
	pkt := common.Packet{
		Header: common.Header{MsgType: common.MsgText, ConversationID: convID, Flags: common.FlagEncrypted, BodyLen: uint32(len(body))},
		Body:   []byte(body),
	}
	if err := pkt.Encode(c); err != nil {
		t.Fatalf("send: %v", err)
	}
}

// awaitClosed waits for the server to hang up, skipping anything sent first.
func awaitClosed(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(within))
	for {
		if _, err := common.Decode(c); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("the connection is still open")
			}
			return
		}
	}
}

func TestRegisterThenLoginKeepsTheAccount(t *testing.T) {
	_, addr := startServer(t)

	_, id, token := register(t, addr, "alice", 1)
	if token == ([common.SessionTokenSize]byte{}) {
		t.Fatal("registration returned no session token")
	}
	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(1))
	again, newToken := ackOf(t, reply)
	if again != id {
		t.Fatal("logging in gave a different user ID")
	}
	if newToken == token {
		t.Fatal("a password login reused the previous token")
	}
}

func TestWrongPasswordAndUnknownUserAreBadCredentials(t *testing.T) {
	_, addr := startServer(t)
	register(t, addr, "alice", 1)

	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", "not the password at all", testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrBadCredentials {
		t.Fatalf("wrong password answered with %s", errCode(reply))
	}
	_, reply = authAttempt(t, addr, common.CtrlLogin, "nobody", testPassword, testBundle(2), testSeed(2))
	if errCode(reply) != common.ErrBadCredentials {
		t.Fatalf("unknown user answered with %s", errCode(reply))
	}
}

func TestUsernamesAreUniqueIgnoringCase(t *testing.T) {
	_, addr := startServer(t)

	_, reply := authAttempt(t, addr, common.CtrlRegister, "Alice", testPassword, testBundle(1), testSeed(1))
	id, _ := ackOf(t, reply)

	_, reply = authAttempt(t, addr, common.CtrlRegister, "ALICE", testPassword, testBundle(2), testSeed(2))
	if errCode(reply) != common.ErrUsernameTaken {
		t.Fatalf("a second ALICE answered with %s", errCode(reply))
	}
	_, reply = authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(1))
	if got, _ := ackOf(t, reply); got != id {
		t.Fatal("alice and Alice are different accounts")
	}
}

func TestRegistrationRules(t *testing.T) {
	_, addr := startServer(t)

	_, reply := authAttempt(t, addr, common.CtrlRegister, "alice", "", testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrWeakPassword {
		t.Fatalf("an empty password answered with %s", errCode(reply))
	}
	_, reply = authAttempt(t, addr, common.CtrlRegister, "no spaces allowed", testPassword, testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrInvalidUsername {
		t.Fatalf("an invalid username answered with %s", errCode(reply))
	}
	if e, _ := common.DecodeError(reply.Body); e == nil || e.Message == "" {
		t.Fatal("a refused username came without a reason the user can act on")
	}
}

func TestResumeWithToken(t *testing.T) {
	_, addr := startServer(t)
	c, id, token := register(t, addr, "alice", 1)
	c.Close()

	_, reply := resumeAttempt(t, addr, "alice", token, testBundle(1), testSeed(1))
	got, sameToken := ackOf(t, reply)
	if got != id || sameToken != token {
		t.Fatal("resuming changed the account or the token")
	}

	// A token alone is not enough: the device must still sign the challenge.
	_, reply = resumeAttempt(t, addr, "alice", token, testBundle(1), testSeed(42))
	if reply.Header.MsgType == common.CtrlLoginAck {
		t.Fatal("resumed with a token but without the device's signing key")
	}
	var forged [common.SessionTokenSize]byte
	forged[0] = 1
	_, reply = resumeAttempt(t, addr, "alice", forged, testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrSessionRevoked {
		t.Fatalf("an unknown token answered with %s", errCode(reply))
	}
}

func TestLogoutRevokesTheToken(t *testing.T) {
	_, addr := startServer(t)
	c, _, token := register(t, addr, "alice", 1)

	(&common.Packet{Header: common.Header{MsgType: common.CtrlLogout}}).Encode(c)
	awaitClosed(t, c, 3*time.Second)

	_, reply := resumeAttempt(t, addr, "alice", token, testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrSessionRevoked {
		t.Fatalf("a logged-out token answered with %s", errCode(reply))
	}
	// The password still works, and lifts the logout for the same keys.
	_, reply = authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(1))
	ackOf(t, reply)
}

// A token is issued to one set of keys. Coming back with others is a device
// change, and that takes the password.
func TestResumeWithNewKeysNeedsThePassword(t *testing.T) {
	_, addr := startServer(t)
	c, _, token := register(t, addr, "alice", 1)
	c.Close()

	_, reply := resumeAttempt(t, addr, "alice", token, testBundle(2), testSeed(2))
	if errCode(reply) != common.ErrPasswordRequired {
		t.Fatalf("a token with new keys answered with %s", errCode(reply))
	}
}

func TestNewDeviceReplacesTheOld(t *testing.T) {
	srv, addr := startServer(t)
	mac, id, macToken := register(t, addr, "alice", 1)

	// alice signs in on her phone: the right password, new keys.
	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(3), testSeed(3))
	got, phoneToken := ackOf(t, reply)
	if got != id {
		t.Fatal("moving to a new device changed the user ID")
	}

	// The Mac is told, then disconnected.
	notice := readUntil(t, mac, common.CtrlError, 3*time.Second)
	if errCode(notice) != common.ErrDeviceReplaced {
		t.Fatalf("the old device was sent %s, want device replaced", errCode(notice))
	}
	awaitClosed(t, mac, 3*time.Second)

	// Its token is dead, and says why.
	_, reply = resumeAttempt(t, addr, "alice", macToken, testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrDeviceReplaced {
		t.Fatalf("the old device's resume answered with %s", errCode(reply))
	}
	// The phone's is fine, and the directory now hands out the phone's keys.
	_, reply = resumeAttempt(t, addr, "alice", phoneToken, testBundle(3), testSeed(3))
	ackOf(t, reply)
	srv.mu.RLock()
	ik := srv.users[id].IdentityKey
	srv.mu.RUnlock()
	if ik != testBundle(3).IdentityKey {
		t.Fatal("the directory still holds the old device's identity key")
	}
}

func TestOfflineOldDeviceLearnsItWasReplaced(t *testing.T) {
	_, addr := startServer(t)
	mac, _, macToken := register(t, addr, "alice", 1)
	mac.Close()

	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(3), testSeed(3))
	ackOf(t, reply)

	_, reply = resumeAttempt(t, addr, "alice", macToken, testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrDeviceReplaced {
		t.Fatalf("the offline device learned %s, want device replaced", errCode(reply))
	}
}

// Packets queued for the old device were encrypted to its keys. They are
// deleted, and the new device starts with an empty queue.
func TestOldQueueNeverReachesTheNewDevice(t *testing.T) {
	_, addr := startServer(t)
	mac, _, _ := register(t, addr, "alice", 1)
	bob, _ := login(t, addr, "bob", 2)
	convID, _ := openDM(t, bob, "alice")
	mac.Close()
	time.Sleep(100 * time.Millisecond) // let the server see the Mac go

	sendText(t, bob, convID, "for the mac")
	time.Sleep(100 * time.Millisecond)

	phone, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(3), testSeed(3))
	ackOf(t, reply)
	expectSilence(t, phone, 300*time.Millisecond)

	sendText(t, bob, convID, "for the phone")
	got := readUntil(t, phone, common.MsgText, 3*time.Second)
	if string(got.Body) != "for the phone" {
		t.Fatalf("the phone received %q", got.Body)
	}
}

// Nothing a replaced device sends after the move reaches anyone. Its socket
// may already be closed by the time it writes, so write errors are expected.
func TestReplacedDeviceCannotSend(t *testing.T) {
	_, addr := startServer(t)
	mac, _, _ := register(t, addr, "alice", 1)
	bob, _ := login(t, addr, "bob", 2)
	convID, _ := openDM(t, bob, "alice")

	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(3), testSeed(3))
	ackOf(t, reply)
	for i := 0; i < 5; i++ {
		pkt := textPacket("from the old device")
		pkt.Header.ConversationID, pkt.Header.Flags = convID, common.FlagEncrypted
		pkt.Encode(mac)
	}
	expectNo(t, bob, common.MsgText, 300*time.Millisecond)
}

// expectNo fails if a packet of msgType arrives before the window closes.
// Anything else, such as a key-change notice, is skipped.
func expectNo(t *testing.T, c net.Conn, msgType uint8, within time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(within))
	for {
		p, err := decode(c)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return
			}
			t.Fatalf("read: %v", err)
		}
		if p.Header.MsgType == msgType {
			t.Fatalf("a packet of type %#x arrived", msgType)
		}
	}
}

// --- the three races in retiring a connection, checked directly ---

// testUser installs an account with one device, without going through a login.
func testUser(srv *Server, name string) (*User, *Device) {
	dev := &Device{ID: genID(), Name: "mac"}
	u := &User{ID: genID(), Username: name, Device: dev}
	srv.mu.Lock()
	srv.users[u.ID] = u
	srv.usernames[name] = u.ID
	srv.mu.Unlock()
	return u, dev
}

func pipeClient(u *User, dev *Device) (*Client, net.Conn) {
	near, far := net.Pipe()
	return &Client{
		Conn: near, UserID: u.ID, DeviceID: dev.ID, Username: u.Username,
		send: make(chan common.Packet, sendBufferSize), done: make(chan struct{}),
	}, far
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(store)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func textPacket(body string) common.Packet {
	return common.Packet{Header: common.Header{MsgType: common.MsgText, BodyLen: uint32(len(body))}, Body: []byte(body)}
}

// An old connection's backlog spills when it closes. After a move, the spill
// must be dropped, never added to the new device's queue.
func TestRetiredBacklogIsDropped(t *testing.T) {
	srv := newTestServer(t)
	u, oldDev := testUser(srv, "alice")
	c, far := pipeClient(u, oldDev)
	defer far.Close()
	for i := 0; i < 10; i++ {
		c.enqueue(textPacket("backlog"))
	}

	newDev := &Device{ID: genID()}
	srv.mu.Lock()
	u.Device = newDev
	srv.mu.Unlock()
	c.retire(common.ErrorPacket(common.ErrDeviceReplaced, ""))
	srv.spill(c)
	failed := &Client{Conn: closedConn(), UserID: u.ID, DeviceID: oldDev.ID}
	srv.writePacket(failed, textPacket("failed write"))
	srv.requeueUnacked(failed)

	srv.mu.RLock()
	n := len(newDev.Queue)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("%d packets for the old device landed in the new device's queue", n)
	}
}

func closedConn() net.Conn {
	a, b := net.Pipe()
	a.Close()
	b.Close()
	return a
}

// A write loop that starts late, for a device that has since been replaced,
// must not drain the new device's queue.
func TestOfflineQueueIsScopedToTheDevice(t *testing.T) {
	srv := newTestServer(t)
	u, oldDev := testUser(srv, "alice")
	newDev := &Device{ID: genID(), Queue: []queued{{pkt: textPacket("for the phone")}}}
	srv.mu.Lock()
	u.Device = newDev
	srv.mu.Unlock()

	if got := srv.takeOfflineQueue(u.ID, oldDev.ID); len(got) != 0 {
		t.Fatal("the old device took the new device's queue")
	}
	if got := srv.takeOfflineQueue(u.ID, newDev.ID); len(got) != 1 {
		t.Fatalf("the new device's queue holds %d packets, want 1", len(got))
	}
}

// The replaced notice goes out first, not behind the old backlog, and then the
// connection closes.
func TestRetiredClientSendsTheNoticeFirst(t *testing.T) {
	srv := newTestServer(t)
	u, dev := testUser(srv, "alice")
	c, far := pipeClient(u, dev)
	defer far.Close()
	for i := 0; i < 10; i++ {
		c.enqueue(textPacket("backlog"))
	}
	c.retire(common.ErrorPacket(common.ErrDeviceReplaced, ""))
	srv.loops.Add(1)
	go srv.writeLoop(c)

	far.SetReadDeadline(time.Now().Add(3 * time.Second))
	first, err := common.Decode(far)
	if err != nil {
		t.Fatal(err)
	}
	if errCode(first) != common.ErrDeviceReplaced {
		t.Fatalf("the first packet was type %#x, want the replaced notice", first.Header.MsgType)
	}
	if _, err := common.Decode(far); err == nil {
		t.Fatal("the backlog followed the notice")
	}
}

// The same check, without the timing: a retired client's read loop relays
// nothing it reads.
func TestRetiredClientReadsAreDropped(t *testing.T) {
	srv := newTestServer(t)
	alice, aliceDev := testUser(srv, "alice")
	bob, bobDev := testUser(srv, "bob")
	convID := common.HashIDs(alice.ID, bob.ID)
	srv.mu.Lock()
	srv.convs[convID] = &Conversation{ID: convID, Members: [][common.IDSize]byte{alice.ID, bob.ID}}
	srv.mu.Unlock()

	c, far := pipeClient(alice, aliceDev)
	c.retire(common.ErrorPacket(common.ErrDeviceReplaced, ""))
	done := make(chan struct{})
	go func() { srv.readLoop(c); close(done) }()

	for i := 0; i < 3; i++ {
		pkt := textPacket("from the old device")
		pkt.Header.ConversationID, pkt.Header.Flags = convID, common.FlagEncrypted
		if err := pkt.Encode(far); err != nil {
			t.Fatal(err)
		}
	}
	far.Close()
	<-done

	srv.mu.RLock()
	n := len(bobDev.Queue)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("bob was sent %d packets from a replaced device", n)
	}
}

// --- transport and limits ---

func TestPlaintextClientIsRefused(t *testing.T) {
	_, addr := startServer(t)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body, _ := common.EncodeCredentials(&common.Credentials{Username: "alice", Password: testPassword, Bundle: *testBundle(1)})
	(&common.Packet{Header: common.Header{MsgType: common.CtrlRegister, BodyLen: uint32(len(body))}, Body: body}).Encode(c)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if reply, err := common.Decode(c); err == nil && reply.Header.MsgType == common.CtrlLoginAck {
		t.Fatal("a plaintext client was admitted")
	}
}

func TestPreAuthBodyIsCapped(t *testing.T) {
	_, addr := startServer(t)
	c := dial(t, addr)
	// Announce a 1 MB login; the server must refuse without reading it.
	big := common.Packet{Header: common.Header{MsgType: common.CtrlLogin, BodyLen: 1 << 20}, Body: make([]byte, 1<<20)}
	go big.Encode(c)
	awaitClosed(t, c, 3*time.Second)
}

func TestLoginMustFinishInTime(t *testing.T) {
	saved := loginTimeout
	loginTimeout = 300 * time.Millisecond
	defer func() { loginTimeout = saved }()

	_, addr := startServer(t)
	c := dial(t, addr) // handshakes, then says nothing
	awaitClosed(t, c, 3*time.Second)
}

func TestAccountSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	srv, addr := startServerAt(t, dir)
	c, id, token := register(t, addr, "alice", 1)
	c.Close()
	srv.Close()
	srv.store.Close()

	_, addr = startServerAt(t, dir)
	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(1))
	if got, _ := ackOf(t, reply); got != id {
		t.Fatal("after a restart alice has a different user ID")
	}
	// The token from before the restart was replaced by that login.
	_, reply = resumeAttempt(t, addr, "alice", token, testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrSessionRevoked {
		t.Fatalf("a superseded token answered with %s", errCode(reply))
	}
	_, reply = authAttempt(t, addr, common.CtrlRegister, "alice", testPassword, testBundle(2), testSeed(2))
	if errCode(reply) != common.ErrUsernameTaken {
		t.Fatal("after a restart alice's name could be registered again")
	}
}

func TestTokenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	srv, addr := startServerAt(t, dir)
	c, id, token := register(t, addr, "alice", 1)
	c.Close()
	srv.Close()
	srv.store.Close()

	_, addr = startServerAt(t, dir)
	_, reply := resumeAttempt(t, addr, "alice", token, testBundle(1), testSeed(1))
	if got, _ := ackOf(t, reply); got != id {
		t.Fatal("resume after a restart gave a different user ID")
	}
}

func TestRateLimits(t *testing.T) {
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	limited := cheapAuth
	limited.UserFailures = 2
	_, addr := startServerOn(t, store, limited)
	register(t, addr, "alice", 1)

	for i := 0; i < 2; i++ {
		_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", "wrong password here", testBundle(1), testSeed(1))
		if errCode(reply) != common.ErrBadCredentials {
			t.Fatalf("attempt %d answered with %s", i, errCode(reply))
		}
	}
	// Locked out now, even with the right password, and before any hashing.
	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(1))
	if errCode(reply) != common.ErrRateLimited {
		t.Fatalf("a locked-out account answered with %s", errCode(reply))
	}

	store2, _ := OpenStore(":memory:")
	perIP := cheapAuth
	perIP.IPAttempts = 3
	_, addr = startServerOn(t, store2, perIP)
	for i := 0; i < 3; i++ {
		authAttempt(t, addr, common.CtrlLogin, "someone", testPassword, testBundle(1), testSeed(1))
	}
	_, reply = authAttempt(t, addr, common.CtrlRegister, "fresh", testPassword, testBundle(2), testSeed(2))
	if errCode(reply) != common.ErrRateLimited {
		t.Fatalf("the fourth attempt from one IP answered with %s", errCode(reply))
	}
}

// Resumes never hash, so a device reconnecting often does not use up the
// allowance for password logins, and is not itself refused at that rate.
func TestResumesHaveTheirOwnAllowance(t *testing.T) {
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	cfg := cheapAuth
	cfg.IPAttempts = 2
	_, addr := startServerOn(t, store, cfg)
	c, _, token := register(t, addr, "alice", 1) // one password attempt used
	c.Close()

	for i := 0; i < 5; i++ {
		c, reply := resumeAttempt(t, addr, "alice", token, testBundle(1), testSeed(1))
		ackOf(t, reply)
		c.Close()
	}
	_, reply := authAttempt(t, addr, common.CtrlLogin, "alice", testPassword, testBundle(1), testSeed(1))
	ackOf(t, reply) // the second password attempt is still allowed
}

func TestPasswordHashesAreBounded(t *testing.T) {
	cfg := cheapAuth
	cfg.HashSlots = 1
	cfg.HashWait = 50 * time.Millisecond
	a := newAuthenticator(cfg)

	release := make(chan struct{})
	held := make(chan struct{})
	go a.withSlot(func() { close(held); <-release })
	<-held
	if _, err := a.hash("another password"); !errors.Is(err, errBusy) {
		t.Fatalf("a hash ran while every slot was taken: %v", err)
	}
	close(release)
}

func TestPasswordHashRoundTrip(t *testing.T) {
	h, err := hashPassword("correct horse", cheapAuth.Argon)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := verifyPassword("correct horse", h); err != nil || !ok {
		t.Fatalf("the right password did not verify: %v", err)
	}
	if ok, _ := verifyPassword("correct horsE", h); ok {
		t.Fatal("a wrong password verified")
	}
	h2, _ := hashPassword("correct horse", cheapAuth.Argon)
	if h == h2 {
		t.Fatal("two hashes of one password are equal; the salt is not random")
	}
}
