package bridge

import (
	"bytes"
	common "common"
	"core"
	"encoding/json"
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

const testPassword = "correct horse battery staple"

// --- a real server ---

var (
	buildOnce sync.Once
	serverBin string
	buildErr  error
)

type serverProc struct {
	t                 *testing.T
	addr, dir, fp     string
	certFile, keyFile string
	cmd               *exec.Cmd
	output            *bytes.Buffer
}

func startServer(t *testing.T) *serverProc {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gomesh-bridge")
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
	p := &serverProc{t: t, addr: freePort(t), dir: t.TempDir()}
	certPEM, keyPEM, err := common.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	if _, p.fp, err = common.ServerTLSConfig(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	p.certFile, p.keyFile = filepath.Join(p.dir, "cert.pem"), filepath.Join(p.dir, "key.pem")
	os.WriteFile(p.certFile, certPEM, 0o600)
	os.WriteFile(p.keyFile, keyPEM, 0o600)
	t.Cleanup(func() {
		if p.cmd != nil {
			p.cmd.Process.Kill()
			p.cmd.Process.Wait()
		}
	})
	p.start()
	return p
}

func (p *serverProc) start() {
	p.t.Helper()
	cmd := exec.Command(serverBin)
	cmd.Env = append(os.Environ(), "LISTEN_ADDR="+p.addr, "TLS_CERT="+p.certFile, "TLS_KEY="+p.keyFile,
		"ARGON2_MEMORY_KIB=64", "ARGON2_TIME=1", "AUTH_IP_ATTEMPTS=1000000")
	cmd.Dir = p.dir
	p.output = &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = p.output, p.output
	if err := cmd.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.cmd = cmd
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(25 * time.Millisecond) {
		if c, err := net.Dial("tcp", p.addr); err == nil {
			c.Close()
			return
		}
	}
	p.t.Fatalf("server never came up on %s", p.addr)
}

func (p *serverProc) stop() {
	p.t.Helper()
	p.cmd.Process.Signal(syscall.SIGTERM)
	p.cmd.Process.Wait()
	p.cmd = nil
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// --- the app's side ---

// memVault behaves as the Swift vault does: empty data for a missing item.
type memVault struct {
	mu      sync.Mutex
	items   map[string][]byte
	failGet error
	puts    int
}

func newMemVault() *memVault { return &memVault{items: map[string][]byte{}} }

func (v *memVault) Get(name string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failGet != nil {
		return nil, v.failGet
	}
	return append([]byte(nil), v.items[name]...), nil
}

func (v *memVault) Put(name string, value []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.puts++
	v.items[name] = append([]byte(nil), value...)
	return nil
}

func (v *memVault) Delete(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.items, name)
	return nil
}

type event struct{ kind, payload string }

type handler struct {
	mu     sync.Mutex
	events []event
}

func (h *handler) OnEvent(kind, payload string) {
	h.mu.Lock()
	h.events = append(h.events, event{kind, payload})
	h.mu.Unlock()
}

func (h *handler) count() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.events) }

// waitFor waits for an event of kind, after the first `after`, whose payload
// decodes into a map that ok accepts.
func (h *handler) waitFor(t *testing.T, kind string, after int, ok func(map[string]any) bool) map[string]any {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		h.mu.Lock()
		for _, ev := range h.events[min(after, len(h.events)):] {
			var p map[string]any
			if json.Unmarshal([]byte(ev.payload), &p) != nil {
				h.mu.Unlock()
				t.Fatalf("an event payload is not JSON: %q", ev.payload)
			}
			if ev.kind == kind && (ok == nil || ok(p)) {
				h.mu.Unlock()
				return p
			}
		}
		h.mu.Unlock()
	}
	t.Fatalf("never saw a %s event", kind)
	return nil
}

func state(s string) func(map[string]any) bool {
	return func(p map[string]any) bool { return p["state"] == s }
}

type device struct {
	e   *Engine
	h   *handler
	v   *memVault
	dir string
}

func newDevice(t *testing.T, name string) *device {
	t.Helper()
	d := &device{h: &handler{}, v: newMemVault(), dir: t.TempDir()}
	d.open(t, name)
	return d
}

func (d *device) open(t *testing.T, name string) {
	t.Helper()
	e, err := NewEngine(d.dir, name, d.v, d.h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	d.e = e
}

// codeOf returns the bridge code an error carries, failing on anything else.
func codeOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("not a bridge error: %T %v", err, err)
	}
	if ErrorCode(err.Error()) != be.Code {
		t.Fatalf("the error's text does not carry its code: %q", err.Error())
	}
	return be.Code
}

func trustAndRegister(t *testing.T, d *device, srv *serverProc, name string) {
	t.Helper()
	check, err := d.e.CheckServer(srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Fingerprint string
		Pinned      bool
	}
	json.Unmarshal([]byte(check), &c)
	if c.Pinned {
		if err := d.e.Register(srv.addr, name, testPassword); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := d.e.TrustServer(srv.addr, c.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := d.e.Register(srv.addr, name, testPassword); err != nil {
		t.Fatal(err)
	}
}

func conversations(t *testing.T, e *Engine) []conversation {
	t.Helper()
	s, err := e.Conversations()
	if err != nil {
		t.Fatal(err)
	}
	var out []conversation
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func accountOf(t *testing.T, e *Engine) account {
	t.Helper()
	s, err := e.Account()
	if err != nil {
		t.Fatal(err)
	}
	var a account
	json.Unmarshal([]byte(s), &a)
	return a
}

// openChat opens a private chat and returns its ID once it exists.
func openChat(t *testing.T, e *Engine, with string) string {
	t.Helper()
	id, err := e.OpenDirect(with)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func chatList(t *testing.T, e *Engine) []chatSummary {
	t.Helper()
	s, err := e.ChatList()
	if err != nil {
		t.Fatal(err)
	}
	var out []chatSummary
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !cond(); time.Sleep(30 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
	}
}

// --- the tests ---

// What the app does, through the bridge: trust a server, create accounts, chat,
// come back to a saved session, and lose the device to a sign-in elsewhere.
func TestTheAppsPathThroughTheBridge(t *testing.T) {
	srv := startServer(t)
	mac := newDevice(t, "Mac")
	if mac.e.SavedSession() != "" {
		t.Fatal("a fresh device has a saved session")
	}

	// Trust is the app's to decide, and exactly the fingerprint it showed.
	check, err := mac.e.CheckServer(srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	var c serverCheck
	json.Unmarshal([]byte(check), &c)
	if c.Pinned || c.Fingerprint != srv.fp || c.Groups != common.FormatFingerprint(srv.fp) || c.Address != srv.addr {
		t.Fatalf("server check: %s", check)
	}
	if got := codeOf(t, mac.e.Register(srv.addr, "alice", testPassword)); got != codeUntrustedServer {
		t.Fatalf("registering before trusting: %s", got)
	}
	if err := mac.e.TrustServer(srv.addr, c.Fingerprint); err != nil {
		t.Fatal(err)
	}

	// The server's refusals arrive as codes.
	for _, tc := range []struct{ user, pass, code string }{
		{"al", testPassword, codeInvalidUsername},
		{"alice", "", codeWeakPassword},
	} {
		if got := codeOf(t, mac.e.Register(srv.addr, tc.user, tc.pass)); got != tc.code {
			t.Errorf("register %q/%q: %s, want %s", tc.user, tc.pass, got, tc.code)
		}
	}
	n := mac.h.count()
	if err := mac.e.Register(srv.addr, "Alice", testPassword); err != nil {
		t.Fatal(err)
	}
	mac.h.waitFor(t, KindConnection, n, state("online"))
	alice := accountOf(t, mac.e)
	if alice.Username != "alice" || len(alice.ID) != 32 {
		t.Fatalf("account: %+v", alice)
	}

	phone := newDevice(t, "iPhone")
	if got := codeOf(t, phone.e.Login(srv.addr, "alice", testPassword)); got != codeUntrustedServer {
		t.Fatalf("login before trusting: %s", got)
	}
	trustAndRegister(t, phone, srv, "bob")
	if got := codeOf(t, phone.e.Login(srv.addr, "bob", testPassword)); got != codeAlreadySignedIn {
		t.Fatalf("signing in twice: %s", got)
	}

	// A chat, both ways. The other side learns of it with the first message.
	if _, err := phone.e.OpenDirect("nobody"); codeOf(t, err) != codeUserNotFound {
		t.Fatalf("an unknown user: %v", err)
	}
	if _, err := phone.e.OpenDirect("bob"); codeOf(t, err) != codeChatWithSelf {
		t.Fatalf("oneself: %v", err)
	}
	n = mac.h.count()
	dm := openChat(t, phone.e, "alice")
	if again := openChat(t, phone.e, "Alice"); again != dm {
		t.Fatalf("opening again gave %s, not %s", again, dm)
	}
	if err := phone.e.SendText(dm, "hello from the phone"); err != nil {
		t.Fatal(err)
	}
	got := mac.h.waitFor(t, KindMessage, n, func(p map[string]any) bool { return p["text"] == "hello from the phone" })
	if got["convID"] != dm || got["senderName"] == "" || got["sender"] == "" {
		t.Fatalf("message event: %v", got)
	}
	// The first message names its sender by ID; the roster names them soon after.
	eventually(t, "the Mac's chat named after bob", func() bool {
		cs := conversations(t, mac.e)
		return len(cs) == 1 && cs[0].ID == dm && !cs[0].IsGroup && strings.Contains(cs[0].Name, "bob")
	})
	if err := mac.e.SendText(dm, "hello back"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the reply kept on the phone", func() bool {
		s, _ := phone.e.Messages(accountOf(t, phone.e).ID, dm, 0, 50)
		return strings.Contains(s, "hello back")
	})
	s, err := mac.e.Messages(alice.ID, dm, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var msgs []message
	json.Unmarshal([]byte(s), &msgs)
	if len(msgs) != 2 || msgs[0].Text != "hello from the phone" || msgs[0].Outgoing || !msgs[1].Outgoing ||
		msgs[1].Status != "sent" || msgs[0].Seq != 1 {
		t.Fatalf("history: %s", s)
	}
	// The phone's list: the reply is unread until the chat is read.
	eventually(t, "the reply counted unread", func() bool {
		l := chatList(t, phone.e)
		return len(l) == 1 && l[0].Unread == 1 && l[0].Preview == "hello back" && !l[0].PreviewFromMe && l[0].Name == "alice"
	})
	if err := phone.e.MarkRead(dm); err != nil {
		t.Fatal(err)
	}
	if l := chatList(t, phone.e); l[0].Unread != 0 || l[0].LastTime == 0 {
		t.Fatalf("after reading: %+v", l[0])
	}
	// A group: its ID comes back, and its members as JSON.
	if _, err := phone.e.CreateGroup(" ", `["alice"]`); codeOf(t, err) != codeNoGroupName {
		t.Fatalf("a group with no name: %v", err)
	}
	gid, err := phone.e.CreateGroup("pals", `["alice"]`)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := phone.e.GroupMembers(gid)
	if err != nil {
		t.Fatal(err)
	}
	var members []member
	json.Unmarshal([]byte(ms), &members)
	if len(members) != 2 || !members[0].IsAdmin || !members[0].IsMe || members[0].Name != "bob" {
		t.Fatalf("members: %s", ms)
	}
	if err := phone.e.GroupAction(gid, "leave", ""); err != nil {
		t.Fatal(err)
	}
	if sn, err := mac.e.SafetyNumber(dm); err != nil || len(sn) < 20 {
		t.Fatalf("safety number: %q %v", sn, err)
	}
	if got := codeOf(t, mac.e.SendText("not-an-id", "x")); got != codeBadRequest {
		t.Fatalf("a bad ID: %s", got)
	}

	// The app comes back later: the saved session resumes without a password.
	mac.e.Close()
	if got := codeOf(t, mac.e.SendText(dm, "x")); got != codeClosed {
		t.Fatalf("a closed engine: %s", got)
	}
	mac.open(t, "Mac")
	var saved map[string]string
	json.Unmarshal([]byte(mac.e.SavedSession()), &saved)
	if saved["username"] != "alice" || saved["server"] != srv.addr {
		t.Fatalf("saved session: %v", saved)
	}
	n = mac.h.count()
	if err := mac.e.Resume(); err != nil {
		t.Fatal(err)
	}
	mac.h.waitFor(t, KindConnection, n, state("online"))
	found := false
	for _, c := range conversations(t, mac.e) {
		found = found || c.ID == dm
	}
	if !found {
		t.Fatal("the chat did not survive a restart")
	}

	// A taken name and a wrong password are codes; the right password,
	// elsewhere, signs the Mac out.
	laptop := newDevice(t, "Laptop")
	check, _ = laptop.e.CheckServer(srv.addr)
	json.Unmarshal([]byte(check), &c)
	laptop.e.TrustServer(srv.addr, c.Fingerprint)
	if got := codeOf(t, laptop.e.Register(srv.addr, "alice", testPassword)); got != codeUsernameTaken {
		t.Fatalf("a taken name: %s", got)
	}
	if got := codeOf(t, laptop.e.Login(srv.addr, "alice", "not the password")); got != codeBadCredentials {
		t.Fatalf("a wrong password: %s", got)
	}
	n = mac.h.count()
	if err := laptop.e.Login(srv.addr, "alice", testPassword); err != nil {
		t.Fatal(err)
	}
	mac.h.waitFor(t, KindSignedOut, n, nil)
	if got := codeOf(t, mac.e.Resume()); got != codeSignedOut {
		t.Fatalf("a signed-out engine: %s", got)
	}
	if _, err := mac.v.Get("account-key"); err != nil || len(mac.v.items["account-key"]) != 0 {
		t.Fatal("the replaced device kept its account key")
	}

	// The history stays, read-only, for whoever uses the Mac next.
	mac.open(t, "Mac")
	if mac.e.SavedSession() != "" {
		t.Fatal("a session survived the sign-out")
	}
	s, err = mac.e.HistoryAccounts()
	if err != nil {
		t.Fatal(err)
	}
	var accts []historyAccount
	json.Unmarshal([]byte(s), &accts)
	if len(accts) != 1 || accts[0].Username != "alice" || accts[0].Current {
		t.Fatalf("history accounts: %s", s)
	}
	if s, _ := mac.e.Messages(alice.ID, dm, 0, 50); !strings.Contains(s, "hello back") {
		t.Fatalf("the kept history: %s", s)
	}
	if _, err := mac.e.Conversations(); codeOf(t, err) != codeNotSignedIn {
		t.Fatalf("conversations with nobody signed in: %v", err)
	}
}

// With the server down at launch, the app still opens the account, refuses
// sends with "offline", and comes online by itself.
func TestResumeOfflineThroughTheBridge(t *testing.T) {
	saved := core.SetReconnectDelayForTest(100 * time.Millisecond)
	defer core.SetReconnectDelayForTest(saved)
	srv := startServer(t)
	mac := newDevice(t, "Mac")
	trustAndRegister(t, mac, srv, "alice")
	phone := newDevice(t, "iPhone")
	trustAndRegister(t, phone, srv, "bob")
	dm := openChat(t, phone.e, "alice")
	phone.e.SendText(dm, "hi")
	eventually(t, "the chat", func() bool { return len(conversations(t, mac.e)) == 1 })
	mac.e.Close()
	srv.stop()

	mac.open(t, "Mac")
	if err := mac.e.Resume(); err != nil {
		t.Fatalf("resuming offline: %v", err)
	}
	mac.h.waitFor(t, KindConnection, 0, state("connecting"))
	if got := codeOf(t, mac.e.SendText(dm, "too early")); got != codeOffline {
		t.Fatalf("an offline send: %s", got)
	}
	n := mac.h.count()
	srv.start()
	mac.e.SetForeground(true)
	mac.h.waitFor(t, KindConnection, n, state("online"))
}

// In the background the iPhone app pauses: no connection, and messages sent
// meanwhile arrive when it comes back.
func TestPauseThroughTheBridge(t *testing.T) {
	saved := core.SetReconnectDelayForTest(50 * time.Millisecond)
	defer core.SetReconnectDelayForTest(saved)
	srv := startServer(t)
	mac := newDevice(t, "Mac")
	trustAndRegister(t, mac, srv, "alice")
	phone := newDevice(t, "iPhone")
	trustAndRegister(t, phone, srv, "bob")
	bob := accountOf(t, phone.e)
	dm := openChat(t, mac.e, "bob")
	mac.e.SendText(dm, "first")
	eventually(t, "the chat on the phone", func() bool { return len(conversations(t, phone.e)) == 1 })

	n := phone.h.count()
	phone.e.Pause()
	phone.h.waitFor(t, KindConnection, n, state("connecting"))
	if err := mac.e.SendText(dm, "sent while paused"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if s, _ := phone.e.Messages(bob.ID, dm, 0, 50); strings.Contains(s, "sent while paused") {
		t.Fatal("a paused engine received a message")
	}
	n = phone.h.count()
	phone.e.SetForeground(true)
	phone.h.waitFor(t, KindConnection, n, state("online"))
	eventually(t, "the message on the phone", func() bool {
		s, _ := phone.e.Messages(bob.ID, dm, 0, 50)
		return strings.Contains(s, "sent while paused")
	})
}

// The vault decides whether keys may be made: empty data is "not there", and
// an error is never mistaken for it.
func TestTheVaultAdapter(t *testing.T) {
	v := newMemVault()
	v.failGet = errors.New("errSecInteractionNotAllowed")
	_, err := NewEngine(t.TempDir(), "Mac", v, &handler{})
	if got := codeOf(t, err); got != codeVault {
		t.Fatalf("an unreadable vault: %s (%v)", got, err)
	}
	if v.puts != 0 {
		t.Fatal("keys were written over a vault that could not be read")
	}

	v = newMemVault()
	dir := t.TempDir()
	e, err := NewEngine(dir, "Mac", v, &handler{})
	if err != nil {
		t.Fatal(err)
	}
	if v.puts == 0 {
		t.Fatal("a fresh device made no keys")
	}
	e.Close()

	// A device that has keys refuses to start over when its vault turns
	// unreadable, rather than making new ones.
	v.failGet = errors.New("the device is locked")
	puts := v.puts
	if _, err := NewEngine(dir, "Mac", v, &handler{}); codeOf(t, err) != codeVault || v.puts != puts {
		t.Fatalf("a locked vault on a device with keys: %v, %d puts", err, v.puts-puts)
	}

	if err := (vaultAdapter{newMemVault()}).Put("x", nil); err == nil {
		t.Fatal("an empty item was stored, and would read back as missing")
	}
}

// Opening a data directory closes whichever engine had it.
func TestOneEnginePerDataDirectory(t *testing.T) {
	d := newDevice(t, "Mac")
	first := d.e
	d.open(t, "Mac")
	if !first.closed.Load() {
		t.Fatal("the first engine is still open")
	}
}

// Every error crossing the bridge has a code.
func TestErrorCodes(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{core.ErrOffline, codeOffline},
		{core.ErrAlreadySignedIn, codeAlreadySignedIn},
		{fmt.Errorf("x: %w", core.ErrUserNotFound), codeUserNotFound},
		{core.ErrChatWithSelf, codeChatWithSelf},
		{core.ErrOutboxFull, codeOutboxFull},
		{core.ErrNoGroupName, codeNoGroupName},
		{fmt.Errorf("x: %w", core.ErrNoSavedSession), codeNoSavedSession},
		{core.ErrUntrustedServer, codeUntrustedServer},
		{fmt.Errorf("%w (got 1234)", common.ErrPinMismatch), codePinMismatch},
		{&common.ServerError{Code: common.ErrBadCredentials}, codeBadCredentials},
		{&common.ServerError{Code: common.ErrUsernameTaken}, codeUsernameTaken},
		{&common.ServerError{Code: common.ErrInvalidUsername}, codeInvalidUsername},
		{&common.ServerError{Code: common.ErrWeakPassword}, codeWeakPassword},
		{&common.ServerError{Code: common.ErrRateLimited}, codeRateLimited},
		{&common.ServerError{Code: common.ErrSessionRevoked}, codeSessionRevoked},
		{&common.ServerError{Code: common.ErrDeviceReplaced}, codeDeviceReplaced},
		{&common.ServerError{Code: common.ErrPasswordRequired}, codePasswordRequired},
		{&common.ServerError{Code: common.ErrInternal}, codeServerError},
		{&common.ServerError{Code: 200}, codeServerError},
		{fmt.Errorf("opening: %w", &vaultError{errors.New("locked")}), codeVault},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, codeUnreachable},
		{errors.New("something else"), codeInternal},
	}
	for _, tc := range cases {
		if got := codeOf(t, wrap(tc.err)); got != tc.code {
			t.Errorf("%v: %s, want %s", tc.err, got, tc.code)
		}
	}
	if wrap(nil) != nil {
		t.Fatal("nil became an error")
	}

	// And a real unreachable server is one too.
	e, err := NewEngine(t.TempDir(), "Mac", newMemVault(), &handler{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.CheckServer(freePort(t)); codeOf(t, err) != codeUnreachable {
		t.Fatalf("nothing listening: %v", err)
	}
}

func TestNormalizeAddress(t *testing.T) {
	for in, want := range map[string]string{
		"localhost":          "localhost:8080",
		" chat.example:443 ": "chat.example:443",
		"127.0.0.1":          "127.0.0.1:8080",
		"[::1]":              "[::1]:8080",
		"[::1]:9000":         "[::1]:9000",
		"::1":                "[::1]:8080",
	} {
		if got := NormalizeAddress(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
