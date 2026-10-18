package bridge

import (
	"core"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Conversations returns the signed-in account's chats as a JSON array of
// {"id","name","isGroup","isAdmin"}.
func (e *Engine) Conversations() (string, error) {
	if err := e.signedIn(); err != nil {
		return "", err
	}
	out := []conversation{}
	for _, c := range e.cl.Conversations() {
		out = append(out, conversation{ID: hexID(c.ID), Name: c.Name, IsGroup: c.IsGroup, IsAdmin: c.IsAdmin})
	}
	return mustJSON(out), nil
}

// HistoryAccounts returns the accounts with history on this device as a JSON
// array of {"id","username","current"}. Only the current one can send.
func (e *Engine) HistoryAccounts() (string, error) {
	if err := e.usable(); err != nil {
		return "", err
	}
	accts, err := e.cl.HistoryAccounts()
	if err != nil {
		return "", wrap(err)
	}
	var me [16]byte
	if e.cl.SignedIn() {
		me = e.cl.UserID()
	}
	out := []historyAccount{}
	for _, a := range accts {
		out = append(out, historyAccount{ID: hexID(a.ID), Username: a.Username, Current: a.ID == me})
	}
	return mustJSON(out), nil
}

// HistoryConversations returns an account's kept chats, newest first, as a
// JSON array of {"id","name","isGroup","messages","lastTime"}.
func (e *Engine) HistoryConversations(accountID string) (string, error) {
	if err := e.usable(); err != nil {
		return "", err
	}
	acct, err := parseID(accountID)
	if err != nil {
		return "", err
	}
	convs, err := e.cl.HistoryConversations(acct)
	if err != nil {
		return "", wrap(err)
	}
	out := []historyConversation{}
	for _, c := range convs {
		out = append(out, historyConversation{
			ID: hexID(c.ConvID), Name: c.Name, IsGroup: c.IsGroup, Messages: c.Messages, LastTime: millis(c.LastTime),
			Preview: c.Preview, PreviewIsFile: c.PreviewIsFile, PreviewFromMe: c.PreviewFromMe,
		})
	}
	return mustJSON(out), nil
}

// Messages returns up to limit messages of a chat before sequence number
// before (0 for the newest), oldest first, as a JSON array.
func (e *Engine) Messages(accountID, convID string, before int64, limit int) (string, error) {
	if err := e.usable(); err != nil {
		return "", err
	}
	acct, err := parseID(accountID)
	if err != nil {
		return "", err
	}
	conv, err := parseID(convID)
	if err != nil {
		return "", err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	msgs, err := e.cl.HistoryMessages(acct, conv, before, limit)
	if err != nil {
		return "", wrap(err)
	}
	out := []message{}
	for _, m := range msgs {
		out = append(out, encodeMessage(m))
	}
	return mustJSON(out), nil
}

// SendText sends a message. Offline, it fails with code "offline" and nothing
// is encrypted.
func (e *Engine) SendText(convID, text string) error {
	if err := e.signedIn(); err != nil {
		return err
	}
	conv, err := parseID(convID)
	if err != nil {
		return err
	}
	return wrap(e.cl.SendText(conv, text))
}

// SendFile encrypts and uploads the file at path and returns the transfer's
// ID. The file must stay readable until a "progress" event for that transfer
// reports 1 (sent) or -1 (failed).
func (e *Engine) SendFile(convID, path string) (string, error) {
	if err := e.signedIn(); err != nil {
		return "", err
	}
	conv, err := parseID(convID)
	if err != nil {
		return "", err
	}
	id, err := e.cl.SendFile(conv, path)
	return id, wrap(err)
}

// OpenDirect returns the ID of the private chat with username, opening it if
// there is none. A chat that exists is returned as it is. It blocks on the
// server.
func (e *Engine) OpenDirect(username string) (string, error) {
	if err := e.signedIn(); err != nil {
		return "", err
	}
	id, err := e.cl.OpenChat(username)
	if err != nil {
		return "", wrap(err)
	}
	return hexID(id), nil
}

// RestartChat abandons a private chat's secure session and starts a fresh one.
// Messages either side sent on the old session may not arrive.
func (e *Engine) RestartChat(convID string) error {
	if err := e.signedIn(); err != nil {
		return err
	}
	conv, err := parseID(convID)
	if err != nil {
		return err
	}
	return wrap(e.cl.RestartChat(conv))
}

// ChatList returns the signed-in account's chats, the most recent first, as a
// JSON array of {"id","name","isGroup","isAdmin","lastTime","preview",
// "previewIsFile","previewFromMe","unread","readOnly"}.
func (e *Engine) ChatList() (string, error) {
	if err := e.signedIn(); err != nil {
		return "", err
	}
	list, err := e.cl.ChatList()
	if err != nil {
		return "", wrap(err)
	}
	out := []chatSummary{}
	for _, c := range list {
		out = append(out, chatSummary{
			ID: hexID(c.ID), Name: c.Name, IsGroup: c.IsGroup, IsAdmin: c.IsAdmin, LastTime: millis(c.LastTime),
			Preview: c.Preview, PreviewIsFile: c.PreviewIsFile, PreviewFromMe: c.PreviewFromMe,
			Unread: c.Unread, ReadOnly: c.ReadOnly,
		})
		if c.PreviewFromMe {
			out[len(out)-1].PreviewDelivery = c.PreviewDelivery.String()
		}
	}
	return mustJSON(out), nil
}

// MarkRead clears a chat's unread count.
func (e *Engine) MarkRead(convID string) error {
	if err := e.signedIn(); err != nil {
		return err
	}
	conv, err := parseID(convID)
	if err != nil {
		return err
	}
	return wrap(e.cl.MarkRead(conv))
}

// SetSendReadReceipts says whether this device tells people when it has read
// what they sent. It is on until turned off; the app keeps the choice and
// passes it on at every start.
func (e *Engine) SetSendReadReceipts(on bool) {
	e.cl.SetSendReadReceipts(on)
}

// CreateGroup makes a group and returns its ID once the server has taken it;
// members is a JSON array of usernames. It blocks on the server.
func (e *Engine) CreateGroup(name, members string) (string, error) {
	if err := e.signedIn(); err != nil {
		return "", err
	}
	var names []string
	if err := json.Unmarshal([]byte(members), &names); err != nil {
		return "", codeError(codeBadRequest, "members must be a JSON array of usernames")
	}
	id, err := e.cl.CreateGroup(name, names)
	if err != nil {
		return "", wrap(err)
	}
	return hexID(id), nil
}

// GroupMembers returns a group's members as a JSON array of
// {"id","name","isAdmin","isMe"}, admins first.
func (e *Engine) GroupMembers(groupID string) (string, error) {
	if err := e.signedIn(); err != nil {
		return "", err
	}
	g, err := parseID(groupID)
	if err != nil {
		return "", err
	}
	ms, err := e.cl.GroupMembers(g)
	if err != nil {
		return "", wrap(err)
	}
	out := []member{}
	for _, m := range ms {
		out = append(out, member{ID: hexID(m.ID), Name: m.Name, IsAdmin: m.IsAdmin, IsMe: m.IsMe})
	}
	return mustJSON(out), nil
}

// GroupAction changes a group: action is one of "add", "remove", "makeAdmin",
// "removeAdmin" (each naming username) or "leave".
func (e *Engine) GroupAction(groupID, action, username string) error {
	if err := e.signedIn(); err != nil {
		return err
	}
	g, err := parseID(groupID)
	if err != nil {
		return err
	}
	switch action {
	case "add":
		return wrap(e.cl.AddMember(g, username))
	case "remove":
		return wrap(e.cl.RemoveMember(g, username))
	case "makeAdmin":
		return wrap(e.cl.MakeAdmin(g, username))
	case "removeAdmin":
		return wrap(e.cl.RemoveAdmin(g, username))
	case "leave":
		return wrap(e.cl.LeaveGroup(g))
	}
	return codeError(codeBadRequest, "unknown group action "+action)
}

// SafetyNumber returns the number two people compare for a private chat.
func (e *Engine) SafetyNumber(convID string) (string, error) {
	if err := e.signedIn(); err != nil {
		return "", err
	}
	conv, err := parseID(convID)
	if err != nil {
		return "", err
	}
	n, err := e.cl.SafetyNumber(conv)
	return n, wrap(err)
}

// ExportMedia writes a kept file, decrypted, into dir and returns its path.
func (e *Engine) ExportMedia(accountID, mediaID, fileName, dir string) (string, error) {
	if err := e.usable(); err != nil {
		return "", err
	}
	acct, err := parseID(accountID)
	if err != nil {
		return "", err
	}
	p, err := e.cl.ExportMedia(acct, mediaID, fileName, dir)
	return p, wrap(err)
}

// DeleteHistory deletes an account's history from this device.
func (e *Engine) DeleteHistory(accountID string) error {
	if err := e.usable(); err != nil {
		return err
	}
	acct, err := parseID(accountID)
	if err != nil {
		return err
	}
	return wrap(e.cl.DeleteHistory(acct))
}

// --- JSON shapes ---

type account struct {
	ID       string `json:"userID"`
	Username string `json:"username"`
}

type serverCheck struct {
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
	Groups      string `json:"fingerprintGroups"`
	Pinned      bool   `json:"pinned"`
}

type conversation struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IsGroup bool   `json:"isGroup"`
	IsAdmin bool   `json:"isAdmin"`
}

type member struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IsAdmin bool   `json:"isAdmin"`
	IsMe    bool   `json:"isMe"`
}

type historyAccount struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Current  bool   `json:"current"`
}

type historyConversation struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IsGroup       bool   `json:"isGroup"`
	Messages      int64  `json:"messages"`
	LastTime      int64  `json:"lastTime"`
	Preview       string `json:"preview,omitempty"`
	PreviewIsFile bool   `json:"previewIsFile,omitempty"`
	PreviewFromMe bool   `json:"previewFromMe,omitempty"`
}

type chatSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IsGroup       bool   `json:"isGroup"`
	IsAdmin       bool   `json:"isAdmin"`
	LastTime      int64  `json:"lastTime"`
	Preview       string `json:"preview"`
	PreviewIsFile bool   `json:"previewIsFile"`
	PreviewFromMe bool   `json:"previewFromMe"`
	// How far the last message has got, when it is the account's own.
	PreviewDelivery string `json:"previewDelivery,omitempty"`
	Unread          int64  `json:"unread"`
	ReadOnly        bool   `json:"readOnly"`
}

type media struct {
	FileName  string `json:"fileName"`
	FileType  string `json:"fileType,omitempty"`
	Size      int64  `json:"size"`
	MediaID   string `json:"mediaID,omitempty"`
	Thumbnail []byte `json:"thumbnail,omitempty"` // a small JPEG, base64 in the JSON
}

type message struct {
	Seq        int64  `json:"seq"`
	ConvID     string `json:"convID"`
	Sender     string `json:"sender,omitempty"`
	SenderName string `json:"senderName,omitempty"`
	Outgoing   bool   `json:"outgoing"`
	Time       int64  `json:"time"`
	Text       string `json:"text,omitempty"`
	Media      *media `json:"media,omitempty"`
	System     bool   `json:"system,omitempty"`
	Status     string `json:"status"`
	// For an outgoing message: how far it has got ("pending", "accepted",
	// "delivered" or "read") and how many of its Total recipients have it and
	// have read it.
	Delivery       string `json:"delivery,omitempty"`
	DeliveredCount int    `json:"deliveredCount,omitempty"`
	ReadCount      int    `json:"readCount,omitempty"`
	Total          int    `json:"total,omitempty"`
}

func encodeMessage(m core.HistoryMessage) message {
	out := message{
		Seq: m.Seq, ConvID: hexID(m.ConvID), SenderName: m.SenderName,
		Outgoing: m.Outgoing, Time: millis(m.Time), Text: m.Text,
		System: m.System, Status: m.Status.String(),
	}
	if m.Sender != ([16]byte{}) {
		out.Sender = hexID(m.Sender)
	}
	if m.Outgoing && !m.System {
		out.Delivery = m.Delivery.String()
		out.DeliveredCount, out.ReadCount, out.Total = m.DeliveredCount, m.ReadCount, m.Total
	}
	if m.Media != nil {
		out.Media = &media{FileName: m.Media.FileName, FileType: m.Media.FileType, Size: m.Media.Size,
			MediaID: m.Media.LocalID, Thumbnail: m.Media.Thumbnail}
	}
	return out
}

func hexID(id [16]byte) string { return hex.EncodeToString(id[:]) }

func parseID(s string) ([16]byte, error) {
	var id [16]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, codeError(codeBadRequest, "an ID is 32 hex characters")
	}
	copy(id[:], b)
	return id, nil
}

func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func groupFingerprint(fp string) string {
	var out []byte
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, fp[i:min(i+4, len(fp))]...)
	}
	return string(out)
}
