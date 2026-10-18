// Package bridge is the API the native apps call. gomobile turns it into an
// XCFramework for macOS and iOS, so everything exported here stays within what
// gomobile can bind: strings, byte slices, numbers, bools, errors, and
// interfaces made of those. Anything richer crosses as JSON, IDs as hex.
//
// An app makes one Engine per data directory. The Engine reports everything
// through one EventHandler call, from its own goroutine, in order. Every error
// it returns is an *Error whose text is JSON with a stable code, so the app
// can say something sensible without parsing English.
package bridge

import (
	"core"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// Vault stores the device's secrets. The Apple app implements it with the
// Keychain, wrapped by the Secure Enclave where there is one. Get returns empty
// data, and no error, for an item that is not there; any error means the vault
// could not be read, and the engine then refuses to make new keys over it.
type Vault interface {
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Delete(name string) error
}

// EventHandler hears the engine's events: kind is one of the Kind constants,
// payload a JSON object. It is called from a goroutine of the engine's, one
// event at a time, and should hand the event to the app's main thread and
// return; it must not call back into the Engine and wait for it.
type EventHandler interface {
	OnEvent(kind, payload string)
}

// Engine is one device's engine.
type Engine struct {
	cl      *core.Client
	dir     string
	events  *eventQueue
	spent   atomic.Bool // signed out: a new Engine is needed
	closed  atomic.Bool
	closeMu sync.Mutex
}

// Only one Engine may have a data directory open at a time.
var (
	openMu sync.Mutex
	open   = map[string]*Engine{}
)

// NewEngine opens the device kept in dataDir. An Engine still open on the same
// directory is closed first. deviceName is how the server lists this device.
func NewEngine(dataDir, deviceName string, vault Vault, handler EventHandler) (*Engine, error) {
	if dataDir == "" || vault == nil || handler == nil {
		return nil, codeError(codeBadRequest, "a data directory, a vault and an event handler are all needed")
	}
	dir := filepath.Clean(dataDir)
	openMu.Lock()
	old := open[dir]
	openMu.Unlock()
	if old != nil {
		old.Close()
	}

	e := &Engine{dir: dir, events: newEventQueue(handler)}
	cl, err := core.New(core.Config{
		DataDir:    dir,
		DeviceName: deviceName,
		Vault:      vaultAdapter{vault},
		OnEvent:    e.onEvent,
	})
	if err != nil {
		e.events.close()
		return nil, wrap(err)
	}
	e.cl = cl

	openMu.Lock()
	open[dir] = e
	openMu.Unlock()
	return e, nil
}

func (e *Engine) onEvent(ev core.Event) {
	if ev.Kind == core.EventSignedOut {
		e.spent.Store(true)
	}
	kind, payload := encodeEvent(ev)
	e.events.push(kind, payload)
}

// Close disconnects and waits for the engine's loops to end. The device stays
// signed in. It is safe to call more than once.
func (e *Engine) Close() {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	if e.closed.Swap(true) {
		return
	}
	e.cl.Close()
	e.events.close()
	openMu.Lock()
	if open[e.dir] == e {
		delete(open, e.dir)
	}
	openMu.Unlock()
}

// usable refuses calls on an engine that is closed or signed out.
func (e *Engine) usable() error {
	if e.closed.Load() {
		return codeError(codeClosed, "This engine was closed.")
	}
	if e.spent.Load() {
		return codeError(codeSignedOut, "This device was signed out. Start again.")
	}
	return nil
}

// --- signing in ---

// SavedSession returns {"server","username"} for the session this device can
// resume without a password, or "" if there is none.
func (e *Engine) SavedSession() string {
	if e.usable() != nil {
		return ""
	}
	server, username, ok := e.cl.SavedSession()
	if !ok {
		return ""
	}
	return mustJSON(map[string]string{"server": server, "username": username})
}

// CheckServer connects to addr and returns {"address","fingerprint",
// "fingerprintGroups","pinned"}. The app shows an unpinned fingerprint and
// calls TrustServer with exactly that one.
func (e *Engine) CheckServer(addr string) (string, error) {
	if err := e.usable(); err != nil {
		return "", err
	}
	addr = NormalizeAddress(addr)
	fp, pinned, err := e.cl.ServerFingerprint(addr)
	if err != nil {
		return "", wrap(err)
	}
	return mustJSON(serverCheck{Address: addr, Fingerprint: fp, Groups: groupFingerprint(fp), Pinned: pinned}), nil
}

// TrustServer pins fingerprint for addr.
func (e *Engine) TrustServer(addr, fingerprint string) error {
	if err := e.usable(); err != nil {
		return err
	}
	return wrap(e.cl.TrustServer(NormalizeAddress(addr), fingerprint))
}

// ForgetServer removes the pin for addr.
func (e *Engine) ForgetServer(addr string) error {
	if err := e.usable(); err != nil {
		return err
	}
	return wrap(e.cl.ForgetServer(NormalizeAddress(addr)))
}

// Register creates an account and signs this device in to it. It blocks on the
// network: call it off the main thread.
func (e *Engine) Register(addr, username, password string) error {
	if err := e.usable(); err != nil {
		return err
	}
	return wrap(e.cl.Register(NormalizeAddress(addr), username, password))
}

// Login signs this device in with a password. The account's other device, if
// it has one, is signed out. It blocks on the network.
func (e *Engine) Login(addr, username, password string) error {
	if err := e.usable(); err != nil {
		return err
	}
	return wrap(e.cl.Login(NormalizeAddress(addr), username, password))
}

// Resume signs in with the saved session. With the server out of reach it
// still succeeds, offline, and keeps trying in the background. It blocks on
// the network.
func (e *Engine) Resume() error {
	if err := e.usable(); err != nil {
		return err
	}
	return wrap(e.cl.Resume())
}

// Logout signs this device out and deletes its keys; deleteHistory also
// deletes this account's history from the device. A "signedOut" event follows,
// and the Engine is spent.
func (e *Engine) Logout(deleteHistory bool) {
	if e.usable() != nil {
		return
	}
	e.cl.Logout(deleteHistory)
}

// SetForeground tells the engine the app came to the foreground or left it.
// Coming back ends a Pause and cuts any reconnect delay short.
func (e *Engine) SetForeground(foreground bool) {
	if foreground && e.usable() == nil {
		e.cl.ReconnectNow()
	}
}

// Pause disconnects until SetForeground(true), after telling the server what
// this device has read, so that nothing sent meanwhile is written to a socket
// iOS is about to take away. The iPhone app calls it on going to the
// background; the Mac app stays connected.
func (e *Engine) Pause() {
	if e.usable() == nil {
		e.cl.Pause()
	}
}

// Account returns {"userID","username"} for the signed-in account.
func (e *Engine) Account() (string, error) {
	if err := e.signedIn(); err != nil {
		return "", err
	}
	return mustJSON(account{ID: hexID(e.cl.UserID()), Username: e.cl.Username()}), nil
}

func (e *Engine) signedIn() error {
	if err := e.usable(); err != nil {
		return err
	}
	if !e.cl.SignedIn() {
		return codeError(codeNotSignedIn, "Not signed in.")
	}
	return nil
}

// NormalizeAddress trims addr and gives it the default port if it has none.
func NormalizeAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if strings.HasPrefix(addr, "[") { // [::1] or [::1]:8080
		if strings.Contains(addr, "]:") {
			return addr
		}
		return addr + ":" + DefaultPort
	}
	if strings.Count(addr, ":") == 1 {
		return addr
	}
	if strings.Count(addr, ":") == 0 {
		return addr + ":" + DefaultPort
	}
	return "[" + addr + "]:" + DefaultPort // a bare IPv6 address
}

// DefaultPort is the server's port when an address names none.
const DefaultPort = "8080"

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // only ever plain structs
	}
	return string(b)
}
