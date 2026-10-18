package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Chat history lives in one SQLite file per device, history.db, shared by every
// account that has used the device. Each account's rows are sealed with its own
// history key, which the vault holds and sign-out does not delete, so an
// earlier account's chats stay readable on the device, read-only, after another
// signs in. Deleting an account's history deletes its key too, so the rows are
// gone even where the storage does not really erase them.
//
// Nothing in the file is in the clear but a tag per conversation and a
// sequence number per message. The tag is an HMAC of the account and the
// conversation under the account's key: accounts A and B who chatted with each
// other on this device share a conversation ID, and still get different tags.
// Each row is sealed with its tag and sequence number as associated data, so
// rows cannot be swapped or reordered. Someone browsing the file sees how many
// chats there are and how many messages each holds; not who, when, or what.

const (
	historyFile       = "history.db"
	mediaDirName      = "media"
	vaultHistoryIndex = "history-accounts" // the accounts with history on this device
)

func historyKeyName(account [16]byte) string { return "history." + hex.EncodeToString(account[:]) }

// HistoryMessage is one message as the history keeps it.
type HistoryMessage struct {
	Seq        int64
	ConvID     [16]byte
	Sender     [16]byte
	SenderName string
	Outgoing   bool
	Time       time.Time
	Text       string
	Media      *MediaRef
	// System is a line the engine wrote into the chat, such as a safety
	// number changing, rather than a message someone sent.
	System bool
	// Status is how an outgoing message stands: sent, or for a group message
	// waiting on sessions, queued, and failed if it could not go after all.
	Status MessageStatus

	// MsgID is the ID the message travelled under, which is how a receipt names
	// it. Zero for a row written before receipts existed, and for system lines.
	MsgID [16]byte
	// What an outgoing message has been told, kept as sets of user IDs: who it
	// was for when it went out, which of them the server says have it, and
	// which of them say they have read it. Accepted is the server's word that
	// it took the message.
	Recipients [][16]byte
	Accepted   bool
	Delivered  [][16]byte
	Read       [][16]byte

	// Computed when history is read, from the above and who is in the chat
	// now; whatever is stored here is stale and ignored.
	Delivery       Delivery
	DeliveredCount int
	ReadCount      int
	Total          int
}

// MessageStatus is where an outgoing message stands. The zero value is sent,
// which is what every row written before it existed was.
type MessageStatus int

const (
	StatusSent MessageStatus = iota
	StatusQueued
	StatusFailed
)

func (s MessageStatus) String() string {
	switch s {
	case StatusQueued:
		return "queued"
	case StatusFailed:
		return "failed"
	default:
		return "sent"
	}
}

// MediaRef is a file in the history: what it was, and the sealed copy this
// device keeps of it, if it has one.
type MediaRef struct {
	FileName  string
	FileType  string
	Size      int64
	LocalID   string
	Thumbnail []byte
}

// HistoryConversation is a chat as the history knows it.
type HistoryConversation struct {
	ConvID   [16]byte
	Name     string
	IsGroup  bool
	Messages int64
	LastTime time.Time
	// The last message anyone sent, and how many from others are unread.
	Preview       string
	PreviewIsFile bool
	PreviewFromMe bool
	Unread        int64

	queued []int64 // messages still waiting to go, by seq

	readWanted, readSent int64 // see convRecord
}

// directPrefix is how the engine names a private chat internally. Hosts are
// given the person's name alone.
const directPrefix = "Private Chat: "

func displayName(name string) string { return strings.TrimPrefix(name, directPrefix) }

// HistoryAccount is an account that has history on this device.
type HistoryAccount struct {
	ID       [16]byte
	Username string
}

type history struct {
	db *sql.DB
}

func openHistory(path string) (*history, error) {
	db, err := sql.Open("sqlite", "file:"+path+
		"?_pragma=busy_timeout(5000)&_pragma=secure_delete(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS conversations (tag BLOB PRIMARY KEY, sealed BLOB NOT NULL);
		CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
		CREATE TABLE IF NOT EXISTS messages (
			tag    BLOB NOT NULL,
			seq    INTEGER NOT NULL,
			sealed BLOB NOT NULL,
			PRIMARY KEY (tag, seq)
		);`); err != nil {
		db.Close()
		return nil, err
	}
	if err := addMessageIDColumn(db); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return &history{db: db}, nil
}

func (h *history) Close() error { return h.db.Close() }

// addMessageIDColumn gives a history made before receipts the column they look
// messages up by: a keyed hash of the message ID, since the rows themselves
// are sealed. Rows already there keep it empty, and so are never found.
func addMessageIDColumn(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(messages)`)
	if err != nil {
		return err
	}
	has := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		has = has || name == "mid"
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE messages ADD COLUMN mid BLOB`); err != nil {
			return err
		}
	}
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS messages_by_mid ON messages(mid) WHERE mid IS NOT NULL`)
	return err
}

// accountHistory is one account's view of the history.
type accountHistory struct {
	h        *history
	account  [16]byte
	rowKey   [32]byte
	tagKey   [32]byte
	mediaKey [32]byte
	mediaDir string
}

// historyFor returns an account's history, making its key if create is set
// and it has none. As with every vault read, an error that is not "not found"
// is not taken for "none".
func historyFor(h *history, v Vault, mediaDir string, account [16]byte, username string, create bool) (*accountHistory, error) {
	var key [32]byte
	b, err := v.Get(historyKeyName(account))
	switch {
	case err == nil && len(b) == len(key):
		copy(key[:], b)
	case err == nil:
		return nil, fmt.Errorf("the history key in the vault is %d bytes", len(b))
	case !errors.Is(err, ErrNotInVault):
		return nil, fmt.Errorf("reading the vault: %w", err)
	case !create:
		return nil, fmt.Errorf("no history on this device for %x", account[:4])
	default:
		if key, err = randomKey(); err != nil {
			return nil, err
		}
		if err := v.Put(historyKeyName(account), key[:]); err != nil {
			return nil, fmt.Errorf("saving the history key: %w", err)
		}
	}
	if create {
		if err := noteHistoryAccount(v, account, username); err != nil {
			return nil, err
		}
	}
	return &accountHistory{
		h: h, account: account, mediaDir: mediaDir,
		rowKey:   deriveKey(key, "history-rows-v1"),
		tagKey:   deriveKey(key, "history-tags-v1"),
		mediaKey: deriveKey(key, "media-v1"),
	}, nil
}

func historyAccounts(v Vault) ([]HistoryAccount, error) {
	b, err := v.Get(vaultHistoryIndex)
	if errors.Is(err, ErrNotInVault) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the vault: %w", err)
	}
	var out []HistoryAccount
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func noteHistoryAccount(v Vault, account [16]byte, username string) error {
	accts, err := historyAccounts(v)
	if err != nil {
		return err
	}
	for i := range accts {
		if accts[i].ID == account {
			if accts[i].Username == username {
				return nil
			}
			accts[i].Username = username
			return putHistoryAccounts(v, accts)
		}
	}
	return putHistoryAccounts(v, append(accts, HistoryAccount{ID: account, Username: username}))
}

func putHistoryAccounts(v Vault, accts []HistoryAccount) error {
	b, err := json.Marshal(accts)
	if err != nil {
		return err
	}
	return v.Put(vaultHistoryIndex, b)
}

func (a *accountHistory) tag(convID [16]byte) []byte {
	m := hmac.New(sha256.New, a.tagKey[:])
	m.Write(a.account[:])
	m.Write(convID[:])
	return m.Sum(nil)[:16]
}

// messageKey is what the messages table is searched by: a keyed hash of a
// message ID, so the table says nothing about the IDs it holds.
func (a *accountHistory) messageKey(id [16]byte) []byte {
	m := hmac.New(sha256.New, a.tagKey[:])
	m.Write([]byte("message-id|"))
	m.Write(a.account[:])
	m.Write(id[:])
	return m.Sum(nil)[:16]
}

func rowAAD(tag []byte, seq int64) []byte {
	aad := append([]byte("GoMesh-history-v1|"), tag...)
	return binary.BigEndian.AppendUint64(aad, uint64(seq))
}

func convAAD(tag []byte) []byte { return append([]byte("GoMesh-history-conv-v1|"), tag...) }

// convRecord is what a conversation row holds, sealed. The fields after
// LastTime were added later; a record written before them decodes with them
// empty.
type convRecord struct {
	Account  [16]byte
	ConvID   [16]byte
	Name     string
	IsGroup  bool
	Last     int64
	LastTime time.Time
	// Preview is the last message someone sent: its text, or a file's name.
	Preview       string
	PreviewIsFile bool
	PreviewFromMe bool
	// Unread counts messages from others since the chat was last read. System
	// lines do not count: they are about the chat, not from anyone in it.
	Unread int64
	// Queued lists the messages still waiting to go. They wait in memory, so
	// the next start finds any left here and marks them failed.
	Queued []int64
	// ReadWanted is the newest message the person has read here, and ReadSent
	// the newest one whose senders have been told. A gap is a read receipt that
	// could not go yet, because the client was offline.
	ReadWanted, ReadSent int64
}

// previewRunes bounds what a conversation row keeps of its last message.
const previewRunes = 120

func previewOf(m HistoryMessage) (text string, isFile bool) {
	if m.Media != nil {
		return m.Media.FileName, true
	}
	r := []rune(m.Text)
	if len(r) > previewRunes {
		r = r[:previewRunes]
	}
	return string(r), false
}

func gobDecode(b []byte, v any) error { return gob.NewDecoder(bytes.NewReader(b)).Decode(v) }

func gobBytes(v any) ([]byte, error) {
	var b bytes.Buffer
	err := gob.NewEncoder(&b).Encode(v)
	return b.Bytes(), err
}

// append adds a message to a conversation and returns its sequence number.
func (a *accountHistory) append(convID [16]byte, name string, isGroup bool, m HistoryMessage) (int64, error) {
	tag := a.tag(convID)
	tx, err := a.h.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var seq int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE tag = ?`, tag).Scan(&seq); err != nil {
		return 0, err
	}
	m.Seq, m.ConvID = seq, convID
	plain, err := gobBytes(m)
	if err != nil {
		return 0, err
	}
	sealed, err := sealBytes(a.rowKey, plain, rowAAD(tag, seq))
	if err != nil {
		return 0, err
	}
	var mid []byte
	if m.MsgID != ([16]byte{}) {
		mid = a.messageKey(m.MsgID)
	}
	if _, err := tx.Exec(`INSERT INTO messages (tag, seq, sealed, mid) VALUES (?, ?, ?, ?)`, tag, seq, sealed, mid); err != nil {
		return 0, err
	}

	rec, err := a.recordIn(tx, tag)
	if err != nil {
		return 0, err
	}
	rec.Account, rec.ConvID, rec.Name, rec.IsGroup, rec.Last, rec.LastTime = a.account, convID, name, isGroup, seq, m.Time
	if m.Status == StatusQueued {
		rec.Queued = append(rec.Queued, seq)
	}
	switch {
	case m.System:
	case m.Outgoing:
		rec.Preview, rec.PreviewIsFile = previewOf(m)
		rec.PreviewFromMe = true
		rec.Unread = 0 // sending reads the chat
	default:
		rec.Preview, rec.PreviewIsFile = previewOf(m)
		rec.PreviewFromMe = false
		rec.Unread++
	}
	if err := a.putRecord(tx, tag, rec); err != nil {
		return 0, err
	}
	return seq, tx.Commit()
}

// recordIn reads a conversation's record inside tx, or an empty one if the
// conversation has none yet.
func (a *accountHistory) recordIn(tx *sql.Tx, tag []byte) (convRecord, error) {
	var rec convRecord
	var sealed []byte
	err := tx.QueryRow(`SELECT sealed FROM conversations WHERE tag = ?`, tag).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return rec, nil
	}
	if err != nil {
		return rec, err
	}
	plain, err := unsealBytes(a.rowKey, sealed, convAAD(tag))
	if err != nil {
		return rec, fmt.Errorf("a conversation record does not open: %w", err)
	}
	err = gob.NewDecoder(bytes.NewReader(plain)).Decode(&rec)
	return rec, err
}

func (a *accountHistory) putRecord(tx *sql.Tx, tag []byte, rec convRecord) error {
	plain, err := gobBytes(rec)
	if err != nil {
		return err
	}
	sealed, err := sealBytes(a.rowKey, plain, convAAD(tag))
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO conversations (tag, sealed) VALUES (?, ?)
		ON CONFLICT(tag) DO UPDATE SET sealed = excluded.sealed`, tag, sealed)
	return err
}

// setStatus changes where a kept outgoing message stands.
func (a *accountHistory) setStatus(convID [16]byte, seq int64, status MessageStatus) error {
	tag := a.tag(convID)
	tx, err := a.h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sealed []byte
	if err := tx.QueryRow(`SELECT sealed FROM messages WHERE tag = ? AND seq = ?`, tag, seq).Scan(&sealed); err != nil {
		return err
	}
	plain, err := unsealBytes(a.rowKey, sealed, rowAAD(tag, seq))
	if err != nil {
		return err
	}
	var m HistoryMessage
	if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(&m); err != nil {
		return err
	}
	m.Status = status
	if plain, err = gobBytes(m); err != nil {
		return err
	}
	if sealed, err = sealBytes(a.rowKey, plain, rowAAD(tag, seq)); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE messages SET sealed = ? WHERE tag = ? AND seq = ?`, sealed, tag, seq); err != nil {
		return err
	}
	if status != StatusQueued {
		rec, err := a.recordIn(tx, tag)
		if err != nil {
			return err
		}
		if i := slices.Index(rec.Queued, seq); i >= 0 {
			rec.Queued = slices.Delete(rec.Queued, i, i+1)
			if err := a.putRecord(tx, tag, rec); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// failQueued marks failed every message still queued from before this start:
// what waits to go is held in memory only, so none of it is coming. It returns
// the chats and messages it changed.
func (a *accountHistory) failQueued() (map[[16]byte][]int64, error) {
	convs, err := a.conversations()
	if err != nil {
		return nil, err
	}
	stale := map[[16]byte][]int64{}
	for _, c := range convs {
		if len(c.queued) > 0 {
			stale[c.ConvID] = c.queued
		}
	}
	for conv, seqs := range stale {
		for _, seq := range slices.Clone(seqs) {
			if err := a.setStatus(conv, seq, StatusFailed); err != nil {
				return stale, err
			}
		}
	}
	return stale, nil
}

// conversation returns what the history knows of one chat, if anything.
func (a *accountHistory) conversation(convID [16]byte) (HistoryConversation, bool) {
	var sealed []byte
	tag := a.tag(convID)
	if err := a.h.db.QueryRow(`SELECT sealed FROM conversations WHERE tag = ?`, tag).Scan(&sealed); err != nil {
		return HistoryConversation{}, false
	}
	plain, err := unsealBytes(a.rowKey, sealed, convAAD(tag))
	if err != nil {
		return HistoryConversation{}, false
	}
	var rec convRecord
	if gob.NewDecoder(bytes.NewReader(plain)).Decode(&rec) != nil || rec.Account != a.account {
		return HistoryConversation{}, false
	}
	return HistoryConversation{ConvID: rec.ConvID, Name: displayName(rec.Name), IsGroup: rec.IsGroup}, true
}

// markRead clears a conversation's unread count and notes that everything in it
// has now been read, which is what the senders will be told.
func (a *accountHistory) markRead(convID [16]byte) error {
	tag := a.tag(convID)
	tx, err := a.h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rec, err := a.recordIn(tx, tag)
	if err != nil || rec.Last == 0 || (rec.Unread == 0 && rec.ReadWanted >= rec.Last) {
		return err
	}
	rec.Unread = 0
	rec.ReadWanted = rec.Last
	if err := a.putRecord(tx, tag, rec); err != nil {
		return err
	}
	return tx.Commit()
}

// messages returns up to limit messages of a conversation before the sequence
// number before (0 for the newest), oldest first.
func (a *accountHistory) messages(convID [16]byte, before int64, limit int) ([]HistoryMessage, error) {
	if before <= 0 {
		before = 1<<62 - 1
	}
	tag := a.tag(convID)
	rows, err := a.h.db.Query(`SELECT seq, sealed FROM messages WHERE tag = ? AND seq < ? ORDER BY seq DESC LIMIT ?`,
		tag, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryMessage
	for rows.Next() {
		var seq int64
		var sealed []byte
		if err := rows.Scan(&seq, &sealed); err != nil {
			return nil, err
		}
		plain, err := unsealBytes(a.rowKey, sealed, rowAAD(tag, seq))
		if err != nil {
			return nil, fmt.Errorf("message %d does not open: %w", seq, err)
		}
		var m HistoryMessage
		if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	slices.Reverse(out)
	return out, rows.Err()
}

// conversations lists this account's chats. Tags say nothing about whose a row
// is, so every conversation row is tried; the account's own are the ones that
// open under its key.
func (a *accountHistory) conversations() ([]HistoryConversation, error) {
	rows, err := a.h.db.Query(`SELECT tag, sealed FROM conversations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryConversation
	for rows.Next() {
		var tag, sealed []byte
		if err := rows.Scan(&tag, &sealed); err != nil {
			return nil, err
		}
		plain, err := unsealBytes(a.rowKey, sealed, convAAD(tag))
		if err != nil {
			continue // another account's
		}
		var rec convRecord
		if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(&rec); err != nil || rec.Account != a.account {
			continue
		}
		out = append(out, HistoryConversation{
			ConvID: rec.ConvID, Name: displayName(rec.Name), IsGroup: rec.IsGroup, Messages: rec.Last, LastTime: rec.LastTime,
			Preview: rec.Preview, PreviewIsFile: rec.PreviewIsFile, PreviewFromMe: rec.PreviewFromMe, Unread: rec.Unread,
			queued: rec.Queued, readWanted: rec.ReadWanted, readSent: rec.ReadSent,
		})
	}
	slices.SortFunc(out, func(x, y HistoryConversation) int { return y.LastTime.Compare(x.LastTime) })
	return out, rows.Err()
}

// deleteAll removes every row of this account's, and its sealed files.
func (a *accountHistory) deleteAll() error {
	convs, err := a.conversations()
	if err != nil {
		return err
	}
	for _, c := range convs {
		msgs, err := a.messages(c.ConvID, 0, 1<<30)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Media != nil && m.Media.LocalID != "" {
				os.Remove(filepath.Join(a.mediaDir, m.Media.LocalID))
			}
		}
		tag := a.tag(c.ConvID)
		if _, err := a.h.db.Exec(`DELETE FROM messages WHERE tag = ?`, tag); err != nil {
			return err
		}
		if _, err := a.h.db.Exec(`DELETE FROM conversations WHERE tag = ?`, tag); err != nil {
			return err
		}
	}
	// A file can be kept without a row naming it, if recording it failed. Every
	// file that opens under this account's key is its own, so all of them go.
	entries, err := os.ReadDir(a.mediaDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := a.openMedia(e.Name()); err == nil {
			if err := os.Remove(filepath.Join(a.mediaDir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- media at rest ---

func mediaAAD(id string) []byte { return []byte("GoMesh-media-v1|" + id) }

// storeMedia keeps a sealed copy of a file under a random name and returns it.
func (a *accountHistory) storeMedia(data []byte) (string, error) {
	var raw [16]byte
	k, err := randomKey()
	if err != nil {
		return "", err
	}
	copy(raw[:], k[:16])
	id := hex.EncodeToString(raw[:])
	sealed, err := sealBytes(a.mediaKey, data, mediaAAD(id))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(a.mediaDir, 0o700); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(a.mediaDir, id), sealed, 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// openMedia returns a sealed file's contents.
func (a *accountHistory) openMedia(id string) ([]byte, error) {
	if len(id) != 32 {
		return nil, errors.New("not a media ID")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return nil, errors.New("not a media ID")
	}
	sealed, err := os.ReadFile(filepath.Join(a.mediaDir, id))
	if err != nil {
		return nil, err
	}
	return unsealBytes(a.mediaKey, sealed, mediaAAD(id))
}
