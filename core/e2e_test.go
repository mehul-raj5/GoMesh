package core

import (
	"bytes"
	common "common"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These tests run the real server binary and drive the real client code over a
// socket. Everything else in this package tests one side in isolation; this is
// the only place the two agree on a wire format or fail to.

var (
	buildOnce sync.Once
	serverBin string
	buildErr  error
)

// buildServer compiles the server once per test run.
func buildServer(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gomesh-e2e")
		if err != nil {
			buildErr = err
			return
		}
		serverBin = filepath.Join(dir, "server")
		cmd := exec.Command("go", "build", "-o", serverBin, ".")
		cmd.Dir = "../server"
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("building server: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return serverBin
}

// freePort asks the OS for a port nobody is using.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

const testPassword = "correct horse battery staple"

// serverPins holds the certificate fingerprint of each server a test started.
var (
	serverPinsMu sync.Mutex
	serverPins   = map[string]string{}
)

// startServer runs the server binary with a fresh certificate and database and
// waits for it to accept connections. Password hashing is turned down and the
// per-IP limit up, since every test connects from 127.0.0.1.
func startServer(t *testing.T) string {
	t.Helper()
	return startServerProc(t).addr
}

// serverProc is a running server binary that can be stopped and started again
// on the same database, certificate and port.
type serverProc struct {
	t                 *testing.T
	bin, dir, addr    string
	certFile, keyFile string
	cmd               *exec.Cmd
	output            *bytes.Buffer
	env               []string // extra settings, such as the media storage
}

func startServerProc(t *testing.T, env ...string) *serverProc {
	t.Helper()
	p := &serverProc{t: t, bin: buildServer(t), addr: freePort(t), dir: t.TempDir(), env: env}

	certPEM, keyPEM, err := common.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	_, fp, err := common.ServerTLSConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	p.certFile, p.keyFile = filepath.Join(p.dir, "cert.pem"), filepath.Join(p.dir, "key.pem")
	if err := os.WriteFile(p.certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	serverPinsMu.Lock()
	serverPins[p.addr] = fp
	serverPinsMu.Unlock()

	t.Cleanup(func() {
		if p.cmd != nil {
			_ = p.cmd.Process.Kill()
			_, _ = p.cmd.Process.Wait()
		}
	})
	p.start()
	return p
}

func (p *serverProc) start() {
	p.t.Helper()
	cmd := exec.Command(p.bin)
	cmd.Env = append(append(os.Environ(), p.env...), "LISTEN_ADDR="+p.addr, "TLS_CERT="+p.certFile, "TLS_KEY="+p.keyFile,
		"ARGON2_MEMORY_KIB=64", "ARGON2_TIME=1", "AUTH_IP_ATTEMPTS=1000000")
	cmd.Dir = p.dir
	p.output = &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = p.output, p.output
	if err := cmd.Start(); err != nil {
		p.t.Fatalf("starting server: %v", err)
	}
	p.cmd = cmd

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", p.addr)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	p.t.Fatalf("server never came up on %s", p.addr)
}

// stop sends SIGTERM, as a service manager would, and requires a clean exit.
func (p *serverProc) stop() {
	p.t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		p.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			p.t.Fatalf("the server did not exit cleanly: %v\n%s", err, p.output)
		}
		if !strings.Contains(p.output.String(), "Stopped cleanly") {
			p.t.Fatalf("the server exited without its clean shutdown:\n%s", p.output)
		}
	case <-time.After(10 * time.Second):
		p.t.Fatal("the server did not stop within 10s of SIGTERM")
	}
	p.cmd = nil
}

// --- a second party, speaking the protocol without the package globals ---

type party struct {
	t    *testing.T
	conn net.Conn
	id   [16]byte
	pub  [32]byte
	sm   *SessionManager
	name string
	in   <-chan common.Packet
}

// decodeInto reads whole packets in the background. A read deadline placed
// around common.Decode can fire between a header and its body, leaving the
// stream desynchronized, so waiting is done on the channel instead.
func decodeInto(c net.Conn) <-chan common.Packet {
	ch := make(chan common.Packet, 128)
	go func() {
		defer close(ch)
		for {
			pkt, err := common.Decode(c)
			if err != nil {
				return
			}
			ch <- pkt
		}
	}()
	return ch
}

// dialTLS connects to a test server, pinning its certificate.
func dialTLS(t *testing.T, addr string) net.Conn {
	t.Helper()
	serverPinsMu.Lock()
	fp := serverPins[addr]
	serverPinsMu.Unlock()
	cfg, err := common.PinnedTLSConfig(fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func dialParty(t *testing.T, addr, name string) *party {
	t.Helper()
	im := newTestIdentity(t)
	c := dialTLS(t, addr)

	id := loginAs(t, c, im, name)
	priv, pub := im.PrivateKey, im.PublicKey
	_ = priv

	return &party{
		t: t, conn: c, id: id, pub: pub, name: name,
		sm: NewSessionManager(im, id),
		in: decodeInto(c),
	}
}

// await reads until a packet of the wanted type arrives.
func (p *party) await(msgType uint8, within time.Duration) common.Packet {
	p.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case pkt, ok := <-p.in:
			if !ok {
				p.t.Fatalf("%s: connection closed waiting for %#x", p.name, msgType)
			}
			if pkt.Header.MsgType == msgType {
				return pkt
			}
		case <-deadline:
			p.t.Fatalf("%s never received a %#x packet", p.name, msgType)
		}
	}
}

// silent fails if anything arrives inside the window.
func (p *party) silent(within time.Duration) {
	p.t.Helper()
	select {
	case pkt, ok := <-p.in:
		if ok {
			p.t.Fatalf("%s got an unexpected reply: type %#x", p.name, pkt.Header.MsgType)
		}
	case <-time.After(within):
	}
}

func (p *party) send(pkt *common.Packet) {
	p.t.Helper()
	if err := pkt.Encode(p.conn); err != nil {
		p.t.Fatalf("%s send: %v", p.name, err)
	}
}

// --- the client under test, wired to the package globals it really uses ---

func startClient(t *testing.T, addr, name string) [16]byte {
	t.Helper()
	return startClientAs(t, addr, name, common.CtrlRegister)
}

// startClientAs signs the client under test in on a fresh identity, registering
// (CtrlRegister) or logging in to an existing account (CtrlLogin), which makes
// it that account's new device.
func startClientAs(t *testing.T, addr, name string, kind uint8) [16]byte {
	t.Helper()
	c := dialTLS(t, addr)

	// A fresh client, keeping only where it lives and who is listening.
	prev := tcl
	tcl = newClient()
	tcl.dataDir, tcl.sink = prev.dataDir, prev.sink

	tcl.idMgr = newTestIdentity(t)
	tcl.conn = c
	tcl.isOnline.Store(true) // connected and, below, signed in, as start would mark it

	userID, _, err := tcl.performAuth(kind, name, testPassword)
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	tcl.mgr = NewClientManager(userID, name)
	tcl.sessionMgr = NewSessionManager(tcl.idMgr, userID)
	tcl.sessionMgr.KnownKey = tcl.mgr.GetPublicKey
	tcl.sessionMgr.OnReplaced = tcl.onSessionReplaced
	tcl.pending = newPendingQueue()

	tcl.convInfoMu.Lock()
	tcl.convInfoAsked = map[[16]byte]time.Time{}
	tcl.convInfoMu.Unlock()

	clientIn = decodeInto(c)
	return userID
}

// clientIn carries packets to the test goroutine, which then runs each one
// through deliver exactly as readLoop would.
var clientIn <-chan common.Packet

// pumpClient runs one packet through the real delivery path, which is what
// readLoop does for every packet it receives.
func pumpClient(within time.Duration) (uint8, bool) {
	select {
	case pkt, ok := <-clientIn:
		if !ok {
			return 0, false
		}
		msgType := pkt.Header.MsgType
		tcl.deliver(pkt)
		return msgType, true
	case <-time.After(within):
		return 0, false
	}
}

// pumpUntil keeps delivering until the wanted type has been handled.
func pumpUntil(t *testing.T, msgType uint8, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		got, ok := pumpClient(time.Until(deadline))
		if !ok {
			break
		}
		if got == msgType {
			return
		}
	}
	t.Fatalf("client never handled a %#x packet", msgType)
}

// pumpUntilCond delivers packets until cond holds, or gives up.
func pumpUntilCond(t *testing.T, within time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		pumpClient(250 * time.Millisecond)
	}
}

// parseDirectAck pulls the peer's bundle out of a CtrlDirectAck body.
func parseDirectAck(t *testing.T, ack common.Packet) (convID, peerID [16]byte, b common.PreKeyBundle, name string) {
	t.Helper()
	if len(ack.Body) < 32+common.PreKeyBundleSize {
		t.Fatalf("direct ack too short: %d", len(ack.Body))
	}
	copy(convID[:], ack.Body[:16])
	copy(peerID[:], ack.Body[16:32])
	b, err := common.DecodePreKeyBundle(ack.Body[32:])
	if err != nil {
		t.Fatal(err)
	}
	return convID, peerID, b, string(ack.Body[32+common.PreKeyBundleSize:])
}

// The client opens a DM and sends immediately. The peer is never notified by
// the server, so everything it needs must come off the wire.
func TestE2EDirectMessageInitiatorSide(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	aliceID := startClient(t, addr, "alice")

	tcl.startPrivateChat("bob")
	pumpUntil(t, common.CtrlDirectAck, 5*time.Second)

	convID := common.HashIDs(aliceID, bob.id)
	if _, ok := tcl.sessionMgr.GetSession(convID); !ok {
		t.Fatal("no session after the direct ack")
	}
	if got := tcl.mgr.GetConversationName(convID); got != "Private Chat: bob" {
		t.Errorf("conversation name: got %q want %q", got, "Private Chat: bob")
	}

	tcl.sendText(convID, "hello over a real socket")

	// Bob builds his side from that one message and reads it.
	pkt := bob.await(common.MsgText, 5*time.Second)
	if err := bob.sm.DecryptPacket(&pkt); err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	if got := string(pkt.Body); got != "hello over a real socket" {
		t.Fatalf("plaintext: got %q", got)
	}
}

// The headline flow: the client is told nothing, receives ciphertext for a
// conversation it has never seen, builds the session from the message itself,
// and learns the peer's name from the roster afterwards.
func TestE2EReceiverRecoversWithoutBeingTold(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	aliceID := startClient(t, addr, "alice")

	// Bob opens the conversation and sends two messages before alice knows.
	bob.send(&common.Packet{
		Header: common.Header{MsgType: common.CtrlDirectInit, BodyLen: uint32(len("alice"))},
		Body:   []byte("alice"),
	})
	convID, peerID, bundle, _ := parseDirectAck(t, bob.await(common.CtrlDirectAck, 5*time.Second))
	if convID != common.HashIDs(bob.id, aliceID) || peerID != aliceID {
		t.Fatalf("server minted a different conversation: %x for %x", convID, peerID)
	}
	if _, err := bob.sm.OpenDirectSession(convID, aliceID, "alice", bundle, false); err != nil {
		t.Fatalf("bob open: %v", err)
	}

	for _, text := range []string{"first, out of nowhere", "second"} {
		pkt := common.Packet{
			Header: common.Header{
				MsgType: common.MsgText, ConversationID: convID,
				SenderID: bob.id, BodyLen: uint32(len(text)),
			},
			Body: []byte(text),
		}
		if err := bob.sm.EncryptPacket(&pkt); err != nil {
			t.Fatalf("bob encrypt: %v", err)
		}
		bob.send(&pkt)
	}

	// Reading the first message builds the session at once. The roster then
	// replaces the placeholder name and confirms bob's identity key.
	recovered := pumpUntilCond(t, 10*time.Second, func() bool {
		_, has := tcl.sessionMgr.GetSession(convID)
		return has && tcl.mgr.GetConversationName(convID) == "Private Chat: bob"
	})
	if !recovered {
		_, has := tcl.sessionMgr.GetSession(convID)
		t.Fatalf("client never settled: session=%v name=%q", has, tcl.mgr.GetConversationName(convID))
	}
	if n := tcl.pending.Len(); n != 0 {
		t.Errorf("%d packets held although the handshake came with the message", n)
	}
	if st := stateOf2(convID); st.Unverified {
		t.Error("the peer's key is still unverified after the roster arrived")
	}

	// And the conversation works in the other direction too.
	tcl.sendText(convID, "got them both")
	reply := bob.await(common.MsgText, 5*time.Second)
	if err := bob.sm.DecryptPacket(&reply); err != nil {
		t.Fatalf("bob decrypt reply: %v", err)
	}
	if got := string(reply.Body); got != "got them both" {
		t.Fatalf("reply: got %q", got)
	}
}

// stateOf2 reads the client's own session state for a conversation.
func stateOf2(convID [16]byte) sessionState {
	sess, ok := tcl.sessionMgr.GetSession(convID)
	if !ok {
		return sessionState{}
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return *sess.st.clone()
}

// follow applies a membership change the server sent a party, as a real client does.
func (p *party) follow(within time.Duration) GroupUpdate {
	p.t.Helper()
	pkt := p.await(common.CtrlGroupChange, within)
	body, err := common.DecodeGroupChangeBody(pkt.Body)
	if err != nil {
		p.t.Fatalf("%s: bad change: %v", p.name, err)
	}
	upd, err := p.sm.ApplyGroupChange(&body)
	if err != nil {
		p.t.Fatalf("%s: applying the change: %v", p.name, err)
	}
	return upd
}

// readGroupText reads the next group message a party is sent, first installing
// any sender key that arrives ahead of it.
func (p *party) readGroupText(within time.Duration) string {
	p.t.Helper()
	deadline := time.After(within)
	for {
		select {
		case pkt, ok := <-p.in:
			if !ok {
				p.t.Fatalf("%s: connection closed", p.name)
			}
			switch pkt.Header.MsgType {
			case common.CtrlSenderKey:
				err := p.sm.DecryptPacket(&pkt)
				if errors.Is(err, ErrAlreadyRead) {
					continue // delivered again, as a real client would ignore it
				}
				if err != nil {
					p.t.Fatalf("%s: sender key: %v", p.name, err)
				}
				if _, err := p.sm.ReceiveSenderKey(&pkt); err != nil {
					p.t.Fatalf("%s: installing sender key: %v", p.name, err)
				}
			case common.MsgText:
				if !p.sm.HasGroup(pkt.Header.ConversationID) {
					continue // a direct message delivered again
				}
				err := p.sm.DecryptGroupPacket(&pkt)
				if errors.Is(err, ErrAlreadyRead) {
					continue
				}
				if err != nil {
					p.t.Fatalf("%s: group decrypt: %v", p.name, err)
				}
				return string(pkt.Body)
			}
		case <-deadline:
			p.t.Fatalf("%s: no group message arrived", p.name)
		}
	}
}

func (p *party) sendGroupText(gid [16]byte, text string) {
	p.t.Helper()
	pkt := common.Packet{
		Header: common.Header{MsgType: common.MsgText, ConversationID: gid, SenderID: p.id, BodyLen: uint32(len(text))},
		Body:   []byte(text),
	}
	pre, err := p.sm.EncryptGroupPacket(&pkt)
	if err != nil {
		p.t.Fatalf("%s: group encrypt: %v", p.name, err)
	}
	for i := range pre {
		p.send(&pre[i])
	}
	p.send(&pkt)
}

func groupNamed(name string) [16]byte {
	tcl.mgr.mu.Lock()
	defer tcl.mgr.mu.Unlock()
	for id, info := range tcl.mgr.Conversations {
		if info.IsGroup && info.Name == name {
			return id
		}
	}
	return [16]byte{}
}

// A three-member group end to end: the client looks its members up, signs the
// create, hands its sender key to each over a 1:1 session opened from the bundles
// the server supplied, and both peers read it and reply.
func TestE2EGroupCreateAndMessage(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	carol := dialParty(t, addr, "carol")
	aliceID := startClient(t, addr, "alice")

	go tcl.CreateGroup("team", []string{"bob", "carol"})
	pumpUntil(t, common.CtrlGroupChange, 5*time.Second)

	groupConv := groupNamed("team")
	if groupConv == ([16]byte{}) {
		t.Fatal("the client did not register the group")
	}
	info, ok := tcl.sessionMgr.Group(groupConv)
	if !ok || len(info.Members) != 3 || len(info.Admins) != 1 || info.Admins[0] != aliceID {
		t.Fatalf("verified membership: %+v ok=%v", info, ok)
	}
	if !tcl.mgr.IsGroupAdmin(groupConv) {
		t.Fatal("the display state does not show the creator as admin")
	}

	for _, p := range []*party{bob, carol} {
		if upd := p.follow(5 * time.Second); !upd.Progressed {
			t.Fatalf("%s did not apply the create", p.name)
		}
	}

	tcl.sendText(groupConv, "hello team")
	for _, p := range []*party{bob, carol} {
		if got := p.readGroupText(5 * time.Second); got != "hello team" {
			t.Fatalf("%s read %q", p.name, got)
		}
	}

	// A reply from a peer, whose key travels to the client and the other peer.
	bob.sendGroupText(groupConv, "hi alice")
	pumpUntil(t, common.MsgText, 5*time.Second)
	if n := tcl.pending.Len(); n != 0 {
		t.Fatalf("%d messages still held", n)
	}
	st := gstateOf(tcl.sessionMgr, groupConv)
	if pk := st.peerKeys(bob.id); pk == nil || pk.Current == nil || pk.Current.N != 1 {
		t.Fatal("the client did not read bob's message")
	}
	if got := carol.readGroupText(5 * time.Second); got != "hi alice" {
		t.Fatalf("carol read %q", got)
	}
}

func gstateOf(sm *SessionManager, gid [16]byte) groupState {
	rec := sm.lookupGroup(gid)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return cloneGroupState(rec.st)
}

// Removing a member through the real server: the signed change reaches everyone,
// the client rotates, and the removed party is sent nothing afterwards.
func TestE2EGroupRemovalCutsTheRemovedMemberOff(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	carol := dialParty(t, addr, "carol")
	startClient(t, addr, "alice")

	go tcl.CreateGroup("team", []string{"bob", "carol"})
	pumpUntil(t, common.CtrlGroupChange, 5*time.Second)
	groupConv := groupNamed("team")
	bob.follow(5 * time.Second)
	carol.follow(5 * time.Second)

	tcl.sendText(groupConv, "before")
	bob.readGroupText(5 * time.Second)
	carol.readGroupText(5 * time.Second)
	firstKey := gstateOf(tcl.sessionMgr, groupConv).Own.KeyID

	tcl.removeMember(groupConv, "carol")
	pumpUntil(t, common.CtrlGroupChange, 5*time.Second)
	bob.follow(5 * time.Second)
	if upd := carol.follow(5 * time.Second); !upd.Left {
		t.Fatal("carol was not told she was removed")
	}
	if !gstateOf(tcl.sessionMgr, groupConv).Own.MustRotate {
		t.Fatal("the client did not mark its key for rotation")
	}

	tcl.sendText(groupConv, "after")
	if got := bob.readGroupText(5 * time.Second); got != "after" {
		t.Fatalf("bob read %q", got)
	}
	if id := gstateOf(tcl.sessionMgr, groupConv).Own.KeyID; id <= firstKey {
		t.Fatalf("the key was not replaced: %d then %d", firstKey, id)
	}
	carol.silent(time.Second)
}

// The only admin leaving hands the role on first: both changes are signed by the
// leaver, and the server's rule against admin-less groups is satisfied.
func TestE2ELastAdminLeavesByPromotingFirst(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	carol := dialParty(t, addr, "carol")
	startClient(t, addr, "alice")

	go tcl.CreateGroup("team", []string{"bob", "carol"})
	pumpUntil(t, common.CtrlGroupChange, 5*time.Second)
	groupConv := groupNamed("team")
	bob.follow(5 * time.Second)
	carol.follow(5 * time.Second)

	tcl.leaveGroup(groupConv)
	if !pumpUntilCond(t, 10*time.Second, func() bool { _, ok := tcl.sessionMgr.Group(groupConv); return !ok }) {
		t.Fatal("the client never finished leaving")
	}

	for _, p := range []*party{bob, carol} {
		p.follow(5 * time.Second) // the promotion
		p.follow(5 * time.Second) // the leave
		info, ok := p.sm.Group(groupConv)
		if !ok || len(info.Members) != 2 || len(info.Admins) != 1 {
			t.Fatalf("%s sees %+v", p.name, info)
		}
		if info.Admins[0] != bob.id {
			t.Fatalf("%s sees the wrong successor", p.name)
		}
	}
}

// A non-member asking for a roster gets nothing, over a real connection.
func TestE2ERosterLookupRequiresMembership(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	mallory := dialParty(t, addr, "mallory")
	aliceID := startClient(t, addr, "alice")

	tcl.startPrivateChat("bob")
	pumpUntil(t, common.CtrlDirectAck, 5*time.Second)
	convID := common.HashIDs(aliceID, bob.id)

	mallory.send(&common.Packet{
		Header: common.Header{
			MsgType: common.CtrlConvInfoRq, ConversationID: convID,
			BodyLen: common.IDSize,
		},
		Body: convID[:],
	})

	mallory.silent(time.Second)
}

// A message arrives for a conversation this device has no session for, and it
// carries no handshake fields because the peer's own session is long established.
// This is what a reinstall, a deleted state directory or a session closed over a
// key mismatch looks like from the receiving end. The roster cannot build a
// session, so nothing held can ever be read: it is discarded, not parked again.
func TestE2EMessagesTheDeviceCanNeverReadAreNotHeldForever(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	aliceID := startClient(t, addr, "alice")

	// Bob opens the chat and sends; the client builds its side and replies, so bob's
	// session is established and stops sending handshake fields.
	bob.send(&common.Packet{
		Header: common.Header{MsgType: common.CtrlDirectInit, BodyLen: uint32(len("alice"))},
		Body:   []byte("alice"),
	})
	convID, _, bundle, _ := parseDirectAck(t, bob.await(common.CtrlDirectAck, 5*time.Second))
	if _, err := bob.sm.OpenDirectSession(convID, aliceID, "alice", bundle, false); err != nil {
		t.Fatal(err)
	}
	send := func(text string) {
		pkt := common.Packet{
			Header: common.Header{MsgType: common.MsgText, ConversationID: convID, SenderID: bob.id, BodyLen: uint32(len(text))},
			Body:   []byte(text),
		}
		if err := bob.sm.EncryptPacket(&pkt); err != nil {
			t.Fatalf("bob encrypt: %v", err)
		}
		bob.send(&pkt)
	}
	send("first")
	if !pumpUntilCond(t, 10*time.Second, func() bool {
		_, has := tcl.sessionMgr.GetSession(convID)
		return has && tcl.mgr.GetConversationName(convID) == "Private Chat: bob"
	}) {
		t.Fatal("client never built its session")
	}
	tcl.sendText(convID, "reply")
	reply := bob.await(common.MsgText, 5*time.Second)
	if err := bob.sm.DecryptPacket(&reply); err != nil {
		t.Fatalf("bob could not read the reply: %v", err)
	}

	// The client loses everything: a fresh manager with no sessions, as after a
	// reinstall. Bob does not know and keeps talking on his established session.
	tcl.sessionMgr = NewSessionManager(tcl.idMgr, aliceID)
	tcl.sessionMgr.KnownKey = tcl.mgr.GetPublicKey
	tcl.convInfoMu.Lock()
	tcl.convInfoAsked = map[[16]byte]time.Time{}
	tcl.convInfoMu.Unlock()

	send("does anyone remember me?")
	pumpUntil(t, common.MsgText, 5*time.Second)         // parked, roster requested
	pumpUntil(t, common.CtrlConvInfoAck, 5*time.Second) // roster answered, no session to build

	if n := tcl.pending.Len(); n != 0 {
		t.Fatalf("%d packets still held although nothing can ever read them", n)
	}
	if _, has := tcl.sessionMgr.GetSession(convID); has {
		t.Fatal("a session appeared from a roster alone")
	}
}

// pipeConn stands in for the server connection and collects what the client sends.
func pipeConn(t *testing.T) <-chan common.Packet {
	t.Helper()
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	tcl.conn = near
	return decodeInto(far)
}

// A session built from a message header has never had its identity key confirmed
// by the server. Restoring it must not present that key as the directory's word,
// and must ask the server to settle it.
func TestRestoreDoesNotPromoteAnUnverifiedKeyAndAsksForTheRoster(t *testing.T) {
	alice, bob := newPersistentPeer(t, 0x11), newPersistentPeer(t, 0x99)
	convID := start(t, alice, bob)
	open(t, bob, seal(t, alice, convID, "hi"), "hi")
	if !stateOf(bob, convID).Unverified {
		t.Fatal("setup: bob's session should be unverified")
	}

	sent := pipeConn(t)
	tcl.idMgr = bob.im
	tcl.mgr = NewClientManager(bob.id, "bob")
	tcl.convInfoMu.Lock()
	tcl.convInfoAsked = map[[16]byte]time.Time{}
	tcl.convInfoMu.Unlock()
	tcl.sessionMgr = restart(t, bob, storeDir(bob)).sm
	tcl.sessionMgr.KnownKey = tcl.mgr.GetPublicKey

	tcl.restoreSessions()

	if _, known := tcl.mgr.GetPublicKey(alice.id); known {
		t.Fatal("a key learned from a message header was presented as the directory's")
	}
	if !tcl.mgr.HasConversation(convID) {
		t.Fatal("the conversation was not restored")
	}
	select {
	case pkt := <-sent:
		if pkt.Header.MsgType != common.CtrlConvInfoRq {
			t.Fatalf("expected a roster request, sent type %#x", pkt.Header.MsgType)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no roster was requested for an unverified session")
	}

	// Once the roster has confirmed the key, the next restore trusts it.
	if err := tcl.sessionMgr.NotePeerKeys(convID, alice.id, "alice", alice.pub, alice.im.SigningKey); err != nil {
		t.Fatal(err)
	}
	tcl.mgr = NewClientManager(bob.id, "bob")
	tcl.sessionMgr = restart(t, bob, storeDir(bob)).sm
	tcl.sessionMgr.KnownKey = tcl.mgr.GetPublicKey
	tcl.restoreSessions()
	if k, known := tcl.mgr.GetPublicKey(alice.id); !known || k != alice.pub {
		t.Fatal("a verified session's key was not restored")
	}
	if got := tcl.mgr.GetConversationName(convID); got != "Private Chat: alice" {
		t.Fatalf("restored name %q", got)
	}
}

// Typing /dm on a chat that already exists starts a fresh secure session in its
// place, and the peer follows it without being told anything but the handshake.
func TestE2EDMOnAnExistingChatStartsAFreshSession(t *testing.T) {
	addr := startServer(t)
	bob := dialParty(t, addr, "bob")
	aliceID := startClient(t, addr, "alice")

	tcl.startPrivateChat("bob")
	pumpUntil(t, common.CtrlDirectAck, 5*time.Second)
	convID := common.HashIDs(aliceID, bob.id)

	tcl.sendText(convID, "before")
	first := bob.await(common.MsgText, 5*time.Second)
	if err := bob.sm.DecryptPacket(&first); err != nil || string(first.Body) != "before" {
		t.Fatalf("bob could not read the first message: %v %q", err, first.Body)
	}
	old := stateOf2(convID)

	// Run /dm again. The ack is the answer to a request, so it resets the chat.
	tcl.startPrivateChat("bob")
	pumpUntil(t, common.CtrlDirectAck, 5*time.Second)

	fresh := stateOf2(convID)
	if fresh.InitEK == old.InitEK || fresh.Send.RK == old.Send.RK {
		t.Fatal("/dm on an existing chat kept the old session")
	}
	if !fresh.Initiator || !fresh.Pending {
		t.Fatalf("the fresh session is not a clean initiator: %+v", fresh)
	}

	tcl.sendText(convID, "after")
	second := bob.await(common.MsgText, 5*time.Second)
	if err := bob.sm.DecryptPacket(&second); err != nil {
		t.Fatalf("bob could not follow the fresh session: %v", err)
	}
	if string(second.Body) != "after" {
		t.Fatalf("plaintext: %q", second.Body)
	}
	if tcl.takeDMRequest("bob") {
		t.Fatal("a /dm request was left over after its ack")
	}
}
