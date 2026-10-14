package main

import (
	"errors"
	"sync"
	"time"
)

// Failures that mean "not yet" rather than "never". The caller holds a packet
// that returns one of these and replays it once the missing key arrives;
// everything else is a genuine reject and gets dropped.
var (
	ErrNoSession      = errors.New("no session for this conversation")
	ErrNoGroupSession = errors.New("no group session")
	ErrNoSenderKey    = errors.New("no sender key for this member yet")
)

// Recoverable reports whether a decrypt failure means "not yet" rather than
// "never": the key is expected to arrive, so the packet is worth holding.
func Recoverable(err error) bool {
	return errors.Is(err, ErrNoSession) ||
		errors.Is(err, ErrNoGroupSession) ||
		errors.Is(err, ErrNoSenderKey) ||
		errors.Is(err, ErrMembershipBehind) ||
		errors.Is(err, ErrEpochGap)
}

type SessionManager struct {
	sessions map[[16]byte]*Session
	aux      map[[16]byte][]*auxSession
	groups   map[[16]byte]*groupRec
	mu       sync.RWMutex
	identity *IdentityManager

	// store holds saved direct sessions. It is the identity's store unless a
	// caller replaces it, and nothing is saved while it is nil.
	store *StateStore

	// selfID decides which direction this client owns. It is assigned by the
	// server at login, so it is not available on IdentityManager.
	selfID [16]byte

	// KnownKey looks up the identity key the server's directory holds for a
	// user. A first message carries the sender's key in its own header, and this
	// is how that claim is checked, if the directory has been consulted yet.
	KnownKey func(id [16]byte) ([32]byte, bool)

	// SigningPin looks up a signing key learned somewhere other than a membership
	// change, such as a prekey bundle. A change that contradicts it is refused.
	SigningPin func(id [16]byte) ([32]byte, bool)

	// OnReplaced is called, with no lock held, after a message's handshake
	// replaces a session that was already in place. Whatever was held for the old
	// session can never be read now.
	OnReplaced func(convID [16]byte)

	now func() time.Time
}

func NewSessionManager(idMgr *IdentityManager, selfID [16]byte) *SessionManager {
	var store *StateStore
	if idMgr != nil {
		store = idMgr.store
	}
	return &SessionManager{
		store:    store,
		sessions: make(map[[16]byte]*Session),
		aux:      make(map[[16]byte][]*auxSession),
		groups:   make(map[[16]byte]*groupRec),
		identity: idMgr,
		selfID:   selfID,
		now:      time.Now,
	}
}
