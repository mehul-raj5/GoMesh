package main

import (
	"bytes"
	common "common"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store keeps the server's state in SQLite so a restart loses nothing:
// accounts and devices, conversations and their members, each group's signed
// change log, and the packets queued for devices that are offline.
//
// A device is the keys an account currently signs in with. An account has one
// current device. Signing in with new keys replaces it: the old device's row
// stays, revoked as "replaced", so an old device that was offline at the time
// learns why its token stopped working.
type Store struct {
	db *sql.DB
}

// revokeReason records why a device's token no longer works.
type revokeReason int

const (
	notRevoked      revokeReason = 0
	revokedLogout   revokeReason = 1
	revokedReplaced revokeReason = 2
)

var errUsernameTaken = errors.New("username already taken")

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id             BLOB PRIMARY KEY,
	username       TEXT NOT NULL UNIQUE,
	password_hash  TEXT NOT NULL,
	bundle         BLOB NOT NULL,
	current_device BLOB NOT NULL,
	created_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
	id             BLOB PRIMARY KEY,
	user_id        BLOB NOT NULL REFERENCES users(id),
	name           TEXT NOT NULL,
	token_hash     BLOB UNIQUE,
	created_at     INTEGER NOT NULL,
	last_seen      INTEGER NOT NULL,
	revoked_reason INTEGER NOT NULL DEFAULT 0,
	revoked_at     INTEGER
);
CREATE INDEX IF NOT EXISTS devices_by_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS conversations (
	id       BLOB PRIMARY KEY,
	name     TEXT NOT NULL,
	is_group INTEGER NOT NULL
);
-- Members of a direct (two-party) conversation. A group's members are whatever
-- its log says, so they are not stored separately.
CREATE TABLE IF NOT EXISTS conv_members (
	conv_id BLOB NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
	user_id BLOB NOT NULL,
	PRIMARY KEY (conv_id, user_id)
);
CREATE TABLE IF NOT EXISTS group_log (
	group_id BLOB NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
	version  INTEGER NOT NULL,
	change   BLOB NOT NULL,
	PRIMARY KEY (group_id, version)
);
-- Packets waiting for a device that is offline, in the order they arrived.
CREATE TABLE IF NOT EXISTS queue (
	seq       INTEGER PRIMARY KEY AUTOINCREMENT,
	device_id BLOB NOT NULL,
	packet    BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS queue_by_device ON queue(device_id, seq);
-- What the server knows of each message it took: who sent it, to whom, and when
-- each recipient's device handled it. Kept for receiptRetention, so a sender
-- that missed a receipt can ask for it again, and so a packet delivered twice
-- is reported once.
CREATE TABLE IF NOT EXISTS msg_receipts (
	msg_id       BLOB NOT NULL,
	recipient    BLOB NOT NULL,
	conv_id      BLOB NOT NULL,
	sender       BLOB NOT NULL,
	accepted_at  INTEGER NOT NULL,
	delivered_at INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (msg_id, recipient)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS msg_receipts_by_sender ON msg_receipts(sender, accepted_at);
`

// OpenStore opens or creates the database at path. ":memory:" gives a private
// database that lasts as long as the Store, for tests.
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)"
	if path != ":memory:" {
		// WAL with synchronous=NORMAL survives the process crashing or being
		// killed; only a power cut can lose the last few commits. FULL would add
		// an fsync to every queued packet, taken while routing waits on the lock.
		dsn += "&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serializes writes anyway, the hot paths read from
	// memory, and a ":memory:" database exists only on the connection that made it.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (st *Store) Close() error { return st.db.Close() }

func tokenHash(token [common.SessionTokenSize]byte) []byte {
	sum := sha256.Sum256(token[:])
	return sum[:]
}

// userRecord is one account and its current device, as loaded at startup.
type userRecord struct {
	ID           [common.IDSize]byte
	Username     string
	PasswordHash string
	Bundle       common.PreKeyBundle
	DeviceID     [common.IDSize]byte
	DeviceName   string
}

func (st *Store) LoadUsers() ([]userRecord, error) {
	rows, err := st.db.Query(`
		SELECT u.id, u.username, u.password_hash, u.bundle, d.id, d.name
		FROM users u JOIN devices d ON d.id = u.current_device`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []userRecord
	for rows.Next() {
		var r userRecord
		var id, bundle, dev []byte
		if err := rows.Scan(&id, &r.Username, &r.PasswordHash, &bundle, &dev, &r.DeviceName); err != nil {
			return nil, err
		}
		if len(id) != common.IDSize || len(dev) != common.IDSize {
			return nil, fmt.Errorf("user %q has a malformed ID", r.Username)
		}
		copy(r.ID[:], id)
		copy(r.DeviceID[:], dev)
		if r.Bundle, err = common.DecodePreKeyBundle(bundle); err != nil {
			return nil, fmt.Errorf("user %q: %w", r.Username, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateUser registers an account with its first device. A name that is already
// taken fails with errUsernameTaken, which is how two registrations racing for
// one name are settled.
func (st *Store) CreateUser(r userRecord, token [common.SessionTokenSize]byte, now time.Time) error {
	return st.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO users (id, username, password_hash, bundle, current_device, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			r.ID[:], r.Username, r.PasswordHash, r.Bundle.Encode(), r.DeviceID[:], now.Unix()); err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed: users.username") {
				return errUsernameTaken
			}
			return err
		}
		_, err := tx.Exec(`INSERT INTO devices (id, user_id, name, token_hash, created_at, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)`,
			r.DeviceID[:], r.ID[:], r.DeviceName, tokenHash(token), now.Unix(), now.Unix())
		return err
	})
}

// ReplaceDevice moves an account to a new device in one transaction: the old
// device is revoked as replaced, the new one is inserted with its token, and
// the account's bundle and current device point at it.
func (st *Store) ReplaceDevice(userID, oldDev, newDev [common.IDSize]byte, name string,
	bundle common.PreKeyBundle, token [common.SessionTokenSize]byte, now time.Time) error {
	return st.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE devices SET revoked_reason = ?, revoked_at = ? WHERE id = ?`,
			revokedReplaced, now.Unix(), oldDev[:]); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO devices (id, user_id, name, token_hash, created_at, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)`,
			newDev[:], userID[:], name, tokenHash(token), now.Unix(), now.Unix()); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE users SET bundle = ?, current_device = ? WHERE id = ?`,
			bundle.Encode(), newDev[:], userID[:]); err != nil {
			return err
		}
		// Everything queued for the old device was encrypted to its keys.
		_, err := tx.Exec(`DELETE FROM queue WHERE device_id = ?`, oldDev[:])
		return err
	})
}

// ReissueToken gives the current device a new token after a password login with
// its existing keys, which also lifts a logout. The old token stops working.
func (st *Store) ReissueToken(userID, dev [common.IDSize]byte, bundle common.PreKeyBundle,
	token [common.SessionTokenSize]byte, now time.Time) error {
	return st.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE devices SET token_hash = ?, last_seen = ?, revoked_reason = 0, revoked_at = NULL
			WHERE id = ?`, tokenHash(token), now.Unix(), dev[:]); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE users SET bundle = ? WHERE id = ?`, bundle.Encode(), userID[:])
		return err
	})
}

// LookupToken finds the device a session token belongs to, and whether it has
// been revoked and why.
func (st *Store) LookupToken(token [common.SessionTokenSize]byte) (userID, dev [common.IDSize]byte, reason revokeReason, found bool, err error) {
	var u, d []byte
	err = st.db.QueryRow(`SELECT user_id, id, revoked_reason FROM devices WHERE token_hash = ?`, tokenHash(token)).
		Scan(&u, &d, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return userID, dev, 0, false, nil
	}
	if err != nil {
		return userID, dev, 0, false, err
	}
	copy(userID[:], u)
	copy(dev[:], d)
	return userID, dev, reason, true, nil
}

// Resumed records a resume: the device was seen, and its signed prekey may have rotated.
func (st *Store) Resumed(userID, dev [common.IDSize]byte, bundle common.PreKeyBundle, now time.Time) error {
	return st.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE devices SET last_seen = ? WHERE id = ?`, now.Unix(), dev[:]); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE users SET bundle = ? WHERE id = ?`, bundle.Encode(), userID[:])
		return err
	})
}

// Revoke ends a device's session.
func (st *Store) Revoke(dev [common.IDSize]byte, reason revokeReason, now time.Time) error {
	_, err := st.db.Exec(`UPDATE devices SET revoked_reason = ?, revoked_at = ? WHERE id = ?`,
		reason, now.Unix(), dev[:])
	return err
}

func (st *Store) tx(fn func(*sql.Tx) error) error {
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// --- conversations ---

// convRecord is a conversation as stored. Members is set for a direct
// conversation; a group's comes from replaying Log.
type convRecord struct {
	ID      [common.IDSize]byte
	Name    string
	IsGroup bool
	Members [][common.IDSize]byte
	Log     []common.SignedChange
}

// SaveDirect records a two-party conversation. It is idempotent: the same pair
// always has the same ID, whether it was made by a /dm or for a group.
func (st *Store) SaveDirect(id [common.IDSize]byte, members [][common.IDSize]byte) error {
	return st.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO conversations (id, name, is_group) VALUES (?, '', 0)`, id[:]); err != nil {
			return err
		}
		for _, m := range members {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO conv_members (conv_id, user_id) VALUES (?, ?)`, id[:], m[:]); err != nil {
				return err
			}
		}
		return nil
	})
}

// CreateGroup records a new group and the signed create that founded it.
func (st *Store) CreateGroup(id [common.IDSize]byte, name string, create common.SignedChange) error {
	return st.tx(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO conversations (id, name, is_group) VALUES (?, ?, 1)`, id[:], name); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO group_log (group_id, version, change) VALUES (?, ?, ?)`,
			id[:], create.Change.Version, create.Encode())
		return err
	})
}

// AppendGroupChange records an accepted change at the end of a group's log.
func (st *Store) AppendGroupChange(id [common.IDSize]byte, sc common.SignedChange) error {
	_, err := st.db.Exec(`INSERT INTO group_log (group_id, version, change) VALUES (?, ?, ?)`,
		id[:], sc.Change.Version, sc.Encode())
	return err
}

// DeleteConversation forgets a conversation, its members and its log.
func (st *Store) DeleteConversation(id [common.IDSize]byte) error {
	_, err := st.db.Exec(`DELETE FROM conversations WHERE id = ?`, id[:])
	return err
}

func (st *Store) LoadConversations() ([]convRecord, error) {
	rows, err := st.db.Query(`SELECT id, name, is_group FROM conversations`)
	if err != nil {
		return nil, err
	}
	var out []convRecord
	for rows.Next() {
		var r convRecord
		var id []byte
		if err := rows.Scan(&id, &r.Name, &r.IsGroup); err != nil {
			rows.Close()
			return nil, err
		}
		if len(id) != common.IDSize {
			rows.Close()
			return nil, errors.New("a conversation has a malformed ID")
		}
		copy(r.ID[:], id)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		r := &out[i]
		if r.IsGroup {
			if r.Log, err = st.loadGroupLog(r.ID); err != nil {
				return nil, fmt.Errorf("group %x: %w", r.ID[:4], err)
			}
			continue
		}
		mrows, err := st.db.Query(`SELECT user_id FROM conv_members WHERE conv_id = ? ORDER BY rowid`, r.ID[:])
		if err != nil {
			return nil, err
		}
		for mrows.Next() {
			var m []byte
			if err := mrows.Scan(&m); err != nil || len(m) != common.IDSize {
				mrows.Close()
				return nil, fmt.Errorf("conversation %x has a malformed member", r.ID[:4])
			}
			var id [common.IDSize]byte
			copy(id[:], m)
			r.Members = append(r.Members, id)
		}
		mrows.Close()
	}
	return out, nil
}

func (st *Store) loadGroupLog(id [common.IDSize]byte) ([]common.SignedChange, error) {
	rows, err := st.db.Query(`SELECT change FROM group_log WHERE group_id = ? ORDER BY version`, id[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var log []common.SignedChange
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		sc, n, err := common.DecodeSignedChange(b)
		if err != nil || n != len(b) {
			return nil, fmt.Errorf("stored change is malformed: %v", err)
		}
		log = append(log, sc)
	}
	return log, rows.Err()
}

// --- offline queues ---

// queued is a packet waiting for a device, with the row that holds it.
type queued struct {
	seq int64
	pkt common.Packet
	enc []byte // the packet as encoded, which is what is stored and counted
}

func encodePacket(p common.Packet) []byte {
	var buf bytes.Buffer
	p.Encode(&buf)
	return buf.Bytes()
}

// Enqueue stores a packet for a device and returns its row.
func (st *Store) Enqueue(device [common.IDSize]byte, enc []byte) (int64, error) {
	res, err := st.db.Exec(`INSERT INTO queue (device_id, packet) VALUES (?, ?)`, device[:], enc)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Dequeue deletes exactly the given rows: the packets that were written. Rows
// are named one by one, never as a range, because a connection that is going
// away can put older, unwritten packets back after a newer one was written.
func (st *Store) Dequeue(seqs []int64) error {
	if len(seqs) == 0 {
		return nil
	}
	return st.tx(func(tx *sql.Tx) error {
		for _, seq := range seqs {
			if _, err := tx.Exec(`DELETE FROM queue WHERE seq = ?`, seq); err != nil {
				return err
			}
		}
		return nil
	})
}

// LoadQueue returns what is waiting for a device, oldest first.
func (st *Store) LoadQueue(device [common.IDSize]byte) ([]queued, error) {
	rows, err := st.db.Query(`SELECT seq, packet FROM queue WHERE device_id = ? ORDER BY seq`, device[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []queued
	for rows.Next() {
		var q queued
		if err := rows.Scan(&q.seq, &q.enc); err != nil {
			return nil, err
		}
		p, err := common.Decode(bytes.NewReader(q.enc))
		if err != nil {
			return nil, fmt.Errorf("queued packet %d is malformed: %w", q.seq, err)
		}
		q.pkt = p
		out = append(out, q)
	}
	return out, rows.Err()
}

// DropStaleQueues deletes rows for devices that are no longer any account's
// current device. A move deletes them as it happens; this catches anything left
// from before that, so the table cannot grow without bound.
func (st *Store) DropStaleQueues() (int64, error) {
	res, err := st.db.Exec(`DELETE FROM queue WHERE device_id NOT IN (SELECT current_device FROM users)`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
