package core

import (
	"bytes"
	common "common"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Config describes one device: where it keeps its files, what it is called,
// and who hears its events.
type Config struct {
	// DataDir holds this device's state. One directory is one device.
	DataDir string
	// DeviceName is how the server lists this device. Empty means the host name.
	DeviceName string
	// Vault holds the device's secrets: the Keychain on Apple devices. Nil means
	// 0600 files in DataDir/vault, which is what the terminal client uses.
	Vault Vault
	// OnEvent receives everything the engine has to tell the host. It is called
	// from the engine's goroutines and must not block for long.
	OnEvent func(Event)
}

// New opens the device in cfg.DataDir, creating its keys if it has none. It
// does not connect.
func New(cfg Config) (*Client, error) {
	cl := newClient()
	if cfg.DataDir != "" {
		cl.dataDir = cfg.DataDir
	}
	cl.deviceName = cfg.DeviceName
	cl.sink = cfg.OnEvent
	cl.vault = cfg.Vault
	if err := cl.openDevice(); err != nil {
		return nil, fmt.Errorf("opening this device's keys: %w", err)
	}
	return cl, nil
}

// SavedSession reports the server and username of the session this device can
// resume without a password, if it has one.
func (cl *Client) SavedSession() (server, username string, ok bool) {
	s, err := cl.loadSession()
	if err != nil || s == nil {
		return "", "", false
	}
	return s.Server, s.Username, true
}

// CheckServer connects to addr once to settle whether its certificate is
// trusted, before anyone types a password to it. confirm is shown the
// fingerprint of a server not yet pinned, and decides; nil refuses it.
func (cl *Client) CheckServer(addr string, confirm func(fingerprint string) bool) error {
	c, err := cl.connectTLS(addr, confirm)
	if err != nil {
		return err
	}
	return c.Close()
}

// Register creates an account and signs this device in to it.
func (cl *Client) Register(addr, username, password string) error {
	return cl.signIn(addr, common.CtrlRegister, username, password)
}

// Login signs this device in to an existing account with its password. If the
// account is signed in on another device, that device is signed out.
func (cl *Client) Login(addr, username, password string) error {
	return cl.signIn(addr, common.CtrlLogin, username, password)
}

// ErrAlreadySignedIn means this Client already has an account started. One
// Client is one account; sign out and make a new one.
var ErrAlreadySignedIn = errors.New("already signed in")

func (cl *Client) signIn(addr string, kind uint8, username, password string) error {
	if cl.SignedIn() {
		return ErrAlreadySignedIn
	}
	c, err := cl.connectTLS(addr, nil)
	if err != nil {
		return err
	}
	cl.setConn(c)
	id, token, err := cl.performAuth(kind, username, password)
	if err != nil {
		c.Close()
		return err
	}
	name := canonicalUsername(username)
	if err := cl.saveSession(addr, name, id, token); err != nil {
		cl.notify(LevelWarn, "Signed in, but the session could not be saved: %v", err)
	}
	cl.start(id, name)
	return nil
}

// ErrNoSavedSession means there is no session to resume.
var ErrNoSavedSession = errors.New("no saved session")

// Resume signs in with the saved session, without a password. If the server
// says this device was replaced or its session ended, the device's keys are
// deleted and fresh ones made, and the error says why; the host then asks for
// the password. A *common.ServerError carries the reason.
//
// If the server cannot be reached, the device still starts: its chats and
// history are there, sends are refused with ErrOffline, and it keeps trying to
// reconnect in the background. Only the server, or a server this device does
// not trust, ends a resume.
func (cl *Client) Resume() error {
	s, err := cl.loadSession()
	if err != nil {
		return err
	}
	if s == nil {
		return ErrNoSavedSession
	}
	if cl.SignedIn() {
		return ErrAlreadySignedIn
	}
	token, err := s.token()
	if err != nil {
		return &common.ServerError{Code: common.ErrPasswordRequired, Message: err.Error()}
	}
	c, err := cl.connectTLS(s.Server, nil)
	if err != nil {
		if errors.Is(err, ErrUntrustedServer) {
			return err
		}
		return cl.resumeOffline(s, err)
	}
	cl.setConn(c)
	id, err := cl.performResume(token, s.Username)
	if err != nil {
		c.Close()
		var se *common.ServerError
		if !errors.As(err, &se) {
			return cl.resumeOffline(s, err)
		}
		switch se.Code {
		case common.ErrDeviceReplaced, common.ErrSessionRevoked:
			if werr := cl.wipeDeviceState(); werr != nil {
				return errors.Join(err, werr)
			}
			if oerr := cl.openDevice(); oerr != nil {
				return errors.Join(err, oerr)
			}
		}
		return err
	}
	cl.start(id, s.Username)
	return nil
}

// resumeOffline starts the saved account without the server, which could not
// be reached for cause, and leaves the reconnect loop to finish the resume.
func (cl *Client) resumeOffline(s *savedSession, cause error) error {
	b, err := hex.DecodeString(s.UserID)
	if err != nil || len(b) != 16 {
		return cause
	}
	var id [16]byte
	copy(id[:], b)
	log.Printf("[INFO] starting offline: %v", cause)
	cl.prepare(id, s.Username)
	text := "Can't reach the server. Your chats are here; messages will send once it's back."
	if errors.Is(cause, common.ErrPinMismatch) {
		text = "The server presented a certificate this device does not trust. Still trying."
	}
	cl.setState(StateConnecting, text)
	cl.spawn(cl.reconnect)
	return nil
}

// start brings the engine up for a signed-in account: its directory, sessions
// and groups as saved, and the loop that reads from the server.
func (cl *Client) start(userID [16]byte, username string) {
	cl.prepare(userID, username)
	cl.setState(StateOnline, "")
	cl.spawn(cl.readLoop)
	cl.afterConnect()
}

// prepare loads a signed-in account's directory, sessions, groups and history.
func (cl *Client) prepare(userID [16]byte, username string) {
	cl.mgr = NewClientManager(userID, username)
	cl.sessionMgr = NewSessionManager(cl.idMgr, userID)
	cl.sessionMgr.KnownKey = cl.mgr.GetPublicKey
	cl.sessionMgr.OnReplaced = cl.onSessionReplaced
	if err := cl.openHistory(userID, username); err != nil {
		log.Printf("[ERROR] history: %v", err)
		cl.notify(LevelError, "This device's history could not be opened; messages will not be kept: %v", err)
	}
	cl.restoreSessions()
	cl.restoreGroups()
}

func (cl *Client) openHistory(userID [16]byte, username string) error {
	if cl.hist == nil {
		h, err := openHistory(cl.dataPath(historyFile))
		if err != nil {
			return err
		}
		cl.hist = h
	}
	a, err := historyFor(cl.hist, cl.secrets(), cl.dataPath(mediaDirName), userID, username, true)
	if err != nil {
		return err
	}
	cl.myHistory = a
	// Messages queued when the app last stopped waited in memory, and went
	// with it.
	if stale, err := a.failQueued(); err != nil {
		log.Printf("[ERROR] marking unsent messages: %v", err)
	} else if n := len(stale); n > 0 {
		log.Printf("[INFO] messages queued in %d chat(s) when the app stopped are marked not sent", n)
	}
	return nil
}

// Close disconnects and waits for the read and reconnect loops to end, so
// another Client can open the same data directory once it returns. The device
// stays signed in; Resume picks up from here. Close must not be called from an
// OnEvent callback.
func (cl *Client) Close() {
	cl.leaving.Store(true)
	cl.stopOnce.Do(func() { close(cl.stop) })
	cl.isOnline.Store(false)
	cl.connLock.Lock()
	c := cl.conn
	cl.connLock.Unlock()
	if c != nil {
		c.Close()
	}
	done := make(chan struct{})
	go func() { cl.loops.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(closeWait):
		log.Printf("[WARN] the engine's loops did not end within %v", closeWait)
	}
	if cl.hist != nil {
		cl.hist.Close()
	}
}

// closeWait bounds how long Close waits for the loops. A dial is cancelled
// and a read ends with its connection, so this is only ever a backstop.
const closeWait = 5 * time.Second

// Logout signs this device out: the server revokes its session and the
// device's keys are deleted. The account's history stays readable on the
// device unless deleteHistory is set. An EventSignedOut follows.
func (cl *Client) Logout(deleteHistory bool) {
	if deleteHistory && cl.mgr != nil {
		if err := cl.DeleteHistory(cl.mgr.UserID); err != nil {
			cl.notify(LevelError, "Could not delete this account's history: %v", err)
		}
	}
	cl.logout()
}

// --- history ---

// HistoryAccounts lists the accounts with history on this device, the signed-in
// one included. Any other's history is read-only.
func (cl *Client) HistoryAccounts() ([]HistoryAccount, error) { return historyAccounts(cl.secrets()) }

func (cl *Client) historyOf(account [16]byte) (*accountHistory, error) {
	if cl.myHistory != nil && cl.myHistory.account == account {
		return cl.myHistory, nil
	}
	if cl.hist == nil {
		h, err := openHistory(cl.dataPath(historyFile))
		if err != nil {
			return nil, err
		}
		cl.hist = h
	}
	return historyFor(cl.hist, cl.secrets(), cl.dataPath(mediaDirName), account, "", false)
}

// HistoryConversations lists an account's chats as this device kept them,
// newest first.
func (cl *Client) HistoryConversations(account [16]byte) ([]HistoryConversation, error) {
	a, err := cl.historyOf(account)
	if err != nil {
		return nil, err
	}
	return a.conversations()
}

// HistoryMessages returns up to limit messages of a chat before sequence
// number before (0 for the newest), oldest first.
func (cl *Client) HistoryMessages(account, convID [16]byte, before int64, limit int) ([]HistoryMessage, error) {
	a, err := cl.historyOf(account)
	if err != nil {
		return nil, err
	}
	msgs, err := a.messages(convID, before, limit)
	if err != nil {
		return msgs, err
	}
	var current [][16]byte
	if cl.SignedIn() && account == cl.mgr.UserID {
		current = cl.currentMembers(convID)
	}
	for i := range msgs {
		msgs[i].settle(current)
	}
	if !cl.SignedIn() || account != cl.mgr.UserID {
		return msgs, nil
	}
	// A message from someone new is kept under the first bytes of their ID
	// until the server names them; name them now if it has.
	for i := range msgs {
		m := &msgs[i]
		if !m.Outgoing && !m.System && m.SenderName == fmt.Sprintf("%x", m.Sender[:4]) && cl.mgr.HasUsername(m.Sender) {
			m.SenderName = cl.mgr.GetUsername(m.Sender)
		}
	}
	return msgs, nil
}

// MarkRead clears a chat's unread count.
func (cl *Client) MarkRead(convID [16]byte) error {
	if cl.myHistory == nil {
		return nil
	}
	if err := cl.myHistory.markRead(convID); err != nil {
		return err
	}
	cl.flushReadReceipts(convID)
	return nil
}

// ChatSummary is a chat as a chat list shows it.
type ChatSummary struct {
	ID            [16]byte
	Name          string
	IsGroup       bool
	IsAdmin       bool
	LastTime      time.Time // zero for a chat with nothing in it yet
	Preview       string
	PreviewIsFile bool
	PreviewFromMe bool
	Unread        int64
	// PreviewDelivery is how far the chat's last message has got, when it is
	// the account's own.
	PreviewDelivery Delivery
	// ReadOnly is a group kept in this device's history that the account is no
	// longer in. A private chat is never read-only: if this device has no
	// session for it, as after signing back in, sending opens one.
	ReadOnly bool
}

// ChatList returns the signed-in account's chats, the most recent first, each
// with its last message and unread count from this device's history.
func (cl *Client) ChatList() ([]ChatSummary, error) {
	live := cl.Conversations()
	kept := map[[16]byte]HistoryConversation{}
	if cl.myHistory != nil {
		convs, err := cl.myHistory.conversations()
		if err != nil {
			return nil, err
		}
		for _, c := range convs {
			kept[c.ConvID] = c
		}
	}
	out := make([]ChatSummary, 0, len(live))
	for _, c := range live {
		s := ChatSummary{ID: c.ID, Name: c.Name, IsGroup: c.IsGroup, IsAdmin: c.IsAdmin}
		if h, ok := kept[c.ID]; ok {
			s.LastTime, s.Preview, s.PreviewIsFile, s.PreviewFromMe, s.Unread = h.LastTime, h.Preview, h.PreviewIsFile, h.PreviewFromMe, h.Unread
			if s.PreviewFromMe {
				s.PreviewDelivery = cl.lastDelivery(c.ID)
			}
		}
		out = append(out, s)
		delete(kept, c.ID)
	}
	for _, h := range kept {
		out = append(out, ChatSummary{ID: h.ConvID, Name: h.Name, IsGroup: h.IsGroup, LastTime: h.LastTime,
			Preview: h.Preview, PreviewIsFile: h.PreviewIsFile, PreviewFromMe: h.PreviewFromMe, Unread: h.Unread,
			ReadOnly: h.IsGroup})
	}
	slices.SortStableFunc(out, func(a, b ChatSummary) int { return b.LastTime.Compare(a.LastTime) })
	return out, nil
}

// NameOf returns a user's name, if this device knows it.
func (cl *Client) NameOf(id [16]byte) (string, bool) {
	if !cl.mgr.HasUsername(id) {
		return "", false
	}
	return cl.mgr.GetUsername(id), true
}

// ExportMedia writes a kept file out, decrypted, into dir, and returns its path.
// This is the one way a received file leaves the sealed store.
func (cl *Client) ExportMedia(account [16]byte, mediaID, fileName, dir string) (string, error) {
	a, err := cl.historyOf(account)
	if err != nil {
		return "", err
	}
	data, err := a.openMedia(mediaID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, filepath.Base(fileName))
	if _, err := os.Stat(path); err == nil {
		path += "." + mediaID[:8]
	}
	return path, os.WriteFile(path, data, 0o600)
}

// DeleteHistory deletes an account's history from this device: its rows, its
// kept files, and its key, so whatever the storage fails to erase can no
// longer be read.
func (cl *Client) DeleteHistory(account [16]byte) error {
	a, err := cl.historyOf(account)
	if err != nil {
		return err
	}
	if err := a.deleteAll(); err != nil {
		return err
	}
	v := cl.secrets()
	if err := v.Delete(historyKeyName(account)); err != nil {
		return err
	}
	accts, err := historyAccounts(v)
	if err != nil {
		return err
	}
	accts = slices.DeleteFunc(accts, func(h HistoryAccount) bool { return h.ID == account })
	if cl.myHistory == a {
		cl.myHistory = nil
	}
	return putHistoryAccounts(v, accts)
}

// UserID and Username identify the signed-in account.
func (cl *Client) UserID() [16]byte { return cl.mgr.UserID }
func (cl *Client) Username() string { return cl.mgr.Username }

// Conversation is a chat as the host shows it.
type Conversation struct {
	ID      [16]byte
	Name    string
	IsGroup bool
	IsAdmin bool // for a group: whether this account is an admin
}

// Conversations lists the chats this account has, in a stable order: by name,
// then by ID.
func (cl *Client) Conversations() []Conversation {
	m := cl.mgr
	m.mu.Lock()
	out := make([]Conversation, 0, len(m.Conversations))
	for id, info := range m.Conversations {
		_, admin := info.Admins[m.UserID]
		out = append(out, Conversation{ID: id, Name: displayName(info.Name), IsGroup: info.IsGroup, IsAdmin: admin})
	}
	m.mu.Unlock()
	slices.SortFunc(out, func(a, b Conversation) int {
		if c := strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)); c != 0 {
			return c
		}
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	return out
}

func (cl *Client) ConversationName(id [16]byte) string {
	return displayName(cl.mgr.GetConversationName(id))
}
func (cl *Client) IsGroup(id [16]byte) bool { return cl.mgr.IsGroup(id) }

// SafetyNumber is what two people compare to confirm nobody substituted a key.
func (cl *Client) SafetyNumber(convID [16]byte) (string, error) {
	if cl.mgr.IsGroup(convID) {
		return "", errors.New("safety numbers are for private chats")
	}
	return cl.sessionMgr.SafetyNumber(convID)
}

// SendText sends a message to a chat.
func (cl *Client) SendText(convID [16]byte, text string) error {
	if err := cl.ensureDirect(convID); err != nil {
		return err
	}
	return cl.sendText(convID, text)
}

// ensureDirect gives a private chat a secure session if this device has none
// for it: one kept in the history from before this device signed in again, or
// whose session was lost. It is opened with the person the history names, and
// must come out as the same chat. A group, or a chat with a session, is left as
// it is.
func (cl *Client) ensureDirect(convID [16]byte) error {
	if cl.mgr.IsGroup(convID) {
		return nil
	}
	if _, ok := cl.sessionMgr.GetSession(convID); ok {
		return nil
	}
	if !cl.online() {
		return ErrOffline
	}
	var name string
	if cl.mgr.HasConversation(convID) {
		name = cl.ConversationName(convID)
	} else if cl.myHistory != nil {
		if h, ok := cl.myHistory.conversation(convID); ok && !h.IsGroup {
			name = h.Name
		}
	}
	if name == "" || name == fmt.Sprintf("%x", convID[:4]) {
		return errors.New("this chat cannot be reopened from this device")
	}
	got, err := cl.OpenChat(name)
	if err != nil {
		return err
	}
	if got != convID {
		return errors.New("the chat reopened as a different conversation")
	}
	return nil
}

// MaxFileSize bounds what SendFile takes: the file is read whole, encrypted in
// memory and uploaded in one request.
const MaxFileSize = 50 << 20

// ErrFileTooLarge means a file is over MaxFileSize.
var ErrFileTooLarge = errors.New("files can be at most 50 MB")

// SendFile encrypts a file, uploads it, and sends its envelope to the chat. It
// returns at once with the transfer's ID; progress and the result arrive as
// events carrying it, and the file is in the chat's history once it has gone.
func (cl *Client) SendFile(convID [16]byte, path string) (string, error) {
	if !cl.online() {
		return "", ErrOffline
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", errors.New("that is a folder, not a file")
	}
	if st.Size() > MaxFileSize {
		return "", ErrFileTooLarge
	}
	if err := cl.ensureDirect(convID); err != nil {
		return "", err
	}
	t := newTransfer(cl, convID, filepath.Base(path), [16]byte{})
	go cl.sendMedia(convID, path, t)
	return t.id, nil
}

// The actions below all write to the server, so each is refused while the
// client is offline: a packet written during a reconnect would land in the
// middle of its login exchange.

// ErrUserNotFound means the server knows no user by that name.
var ErrUserNotFound = errors.New("no such user")

// ErrChatWithSelf means the name given is this account's own.
var ErrChatWithSelf = errors.New("that is you")

// openTimeout bounds how long OpenChat waits for the server.
const openTimeout = 10 * time.Second

// OpenChat returns the private chat with a user, opening it if there is none.
// A chat that exists is returned as it is: starting over is RestartChat's job,
// since it can lose messages in flight. It blocks on the server, so a host calls
// it off its main thread, and never from an event callback.
func (cl *Client) OpenChat(username string) ([16]byte, error) {
	var none [16]byte
	if !cl.online() {
		return none, ErrOffline
	}
	name := canonicalUsername(username)
	if name == "" {
		return none, ErrUserNotFound
	}
	if name == cl.mgr.Username {
		return none, ErrChatWithSelf
	}
	u, err := cl.lookupUser(name)
	if err != nil {
		return none, err
	}
	convID := common.HashIDs(cl.mgr.UserID, u.ID)
	if _, ok := cl.sessionMgr.GetSession(convID); ok && cl.mgr.HasConversation(convID) {
		return convID, nil
	}

	done := make(chan error, 1)
	cl.opening.mu.Lock()
	cl.opening.m[convID] = done
	cl.opening.mu.Unlock()
	defer func() {
		cl.opening.mu.Lock()
		delete(cl.opening.m, convID)
		cl.opening.mu.Unlock()
	}()
	cl.startPrivateChat(name)
	select {
	case err := <-done:
		return convID, err
	case <-cl.stop:
		return none, ErrOffline
	case <-time.After(openTimeout):
		return none, errors.New("the server did not answer in time")
	}
}

// chatOpened tells a waiting OpenChat how opening convID went.
func (cl *Client) chatOpened(convID [16]byte, err error) {
	cl.opening.mu.Lock()
	ch := cl.opening.m[convID]
	cl.opening.mu.Unlock()
	if ch != nil {
		select {
		case ch <- err:
		default:
		}
	}
}

// RestartChat abandons a private chat's secure session and starts a fresh one,
// the way out of a chat that has stopped decrypting. Messages either side sent
// on the old session may not arrive.
func (cl *Client) RestartChat(convID [16]byte) error {
	if cl.mgr.IsGroup(convID) || !cl.mgr.HasConversation(convID) {
		return errors.New("not a private chat")
	}
	name := cl.ConversationName(convID)
	return cl.whenOnline(func() { cl.startPrivateChat(name) })
}

// ErrNoGroupName means a group was asked for without a name.
var ErrNoGroupName = errors.New("a group needs a name")

// CreateGroup makes a group of this account and members, and returns its ID
// once the server has taken it. A member who does not exist is an
// ErrUserNotFound, and nothing is created. It blocks on the server.
func (cl *Client) CreateGroup(name string, members []string) ([16]byte, error) {
	var none [16]byte
	if !cl.online() {
		return none, ErrOffline
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return none, ErrNoGroupName
	}
	keys := []common.MemberKey{cl.selfKey()}
	seen := map[[16]byte]bool{cl.mgr.UserID: true}
	for _, u := range members {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		found, err := cl.lookupUser(canonicalUsername(u))
		if err != nil {
			return none, err
		}
		if seen[found.ID] {
			continue
		}
		seen[found.ID] = true
		cl.mgr.AddUser(found.ID, found.Name)
		keys = append(keys, common.MemberKey{ID: found.ID, IdentityKey: found.Bundle.IdentityKey, SigningKey: found.Bundle.SigningKey})
	}
	gid := genID()
	done := make(chan error, 1)
	cl.opening.mu.Lock()
	cl.opening.m[gid] = done
	cl.opening.mu.Unlock()
	defer func() {
		cl.opening.mu.Lock()
		delete(cl.opening.m, gid)
		cl.opening.mu.Unlock()
	}()
	sc := cl.signChange(common.GroupChange{GroupID: gid, Version: 1, Action: common.ActionCreate, Targets: keys})
	if err := cl.sendChange(common.CtrlGroupCreate, name, sc); err != nil {
		return none, err
	}
	select {
	case err := <-done:
		return gid, err
	case <-cl.stop:
		return none, ErrOffline
	case <-time.After(openTimeout):
		return none, errors.New("the server did not confirm the group in time")
	}
}

// Member is someone in a group, as the group's signed log has them.
type Member struct {
	ID      [16]byte
	Name    string
	IsAdmin bool
	IsMe    bool
}

// GroupMembers lists a group's members, admins first, then by name.
func (cl *Client) GroupMembers(group [16]byte) ([]Member, error) {
	info, ok := cl.sessionMgr.Group(group)
	if !ok {
		return nil, errors.New("not a group this device knows")
	}
	out := make([]Member, 0, len(info.Members))
	for _, k := range info.Members {
		name := info.Names[k.ID]
		if name == "" {
			name = cl.mgr.GetUsername(k.ID)
		}
		out = append(out, Member{ID: k.ID, Name: name, IsAdmin: slices.Contains(info.Admins, k.ID), IsMe: k.ID == cl.mgr.UserID})
	}
	slices.SortFunc(out, func(a, b Member) int {
		if a.IsAdmin != b.IsAdmin {
			if a.IsAdmin {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out, nil
}

func (cl *Client) AddMember(group [16]byte, username string) error {
	return cl.whenOnline(func() { cl.addMember(group, username) })
}

func (cl *Client) RemoveMember(group [16]byte, username string) error {
	return cl.whenOnline(func() { cl.removeMember(group, username) })
}

func (cl *Client) MakeAdmin(group [16]byte, username string) error {
	return cl.whenOnline(func() { cl.makeGroupAdmin(group, username) })
}

func (cl *Client) RemoveAdmin(group [16]byte, username string) error {
	return cl.whenOnline(func() { cl.removeGroupAdmin(group, username) })
}

func (cl *Client) LeaveGroup(group [16]byte) error {
	return cl.whenOnline(func() { cl.leaveGroup(group) })
}

func (cl *Client) whenOnline(fn func()) error {
	if !cl.online() {
		return ErrOffline
	}
	fn()
	return nil
}

// SignedIn reports whether an account has been started on this Client, online
// or not.
func (cl *Client) SignedIn() bool { return cl.mgr != nil }

// lastDelivery is how far the newest message in a chat has got, if it is one
// the account sent; a line the engine wrote does not count as a message.
func (cl *Client) lastDelivery(convID [16]byte) Delivery {
	if cl.myHistory == nil {
		return DeliveryPending
	}
	msgs, err := cl.myHistory.messages(convID, 0, 8)
	if err != nil {
		return DeliveryPending
	}
	for i := len(msgs) - 1; i >= 0; i-- {
		if m := msgs[i]; !m.System {
			if !m.Outgoing {
				return DeliveryPending
			}
			m.settle(cl.currentMembers(convID))
			return m.Delivery
		}
	}
	return DeliveryPending
}
