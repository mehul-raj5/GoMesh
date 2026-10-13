package main

import (
	common "common"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// maxSkip bounds how far ahead of the expected counter a message may claim to
// be. Without it, a single forged sequence number would cost the receiver an
// unbounded number of ratchet steps.
const maxSkip = 2000

// groupPrefixLen is the plaintext preamble on a group message body: the
// sender's epoch then their counter, both covered by the associated data.
const groupPrefixLen = 8

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
		errors.Is(err, ErrEpochGap)
}

// chainState is one receiving ratchet: the key for the next expected message,
// how far the chain has advanced, and the keys for messages that arrived out of
// order and were stepped over. Both the direct and the group paths use it, so
// the skipped-key handling exists once.
type chainState struct {
	Key     [32]byte
	Count   uint32
	Skipped map[uint32][32]byte
}

func newChainState(key [32]byte) chainState {
	return chainState{Key: key, Skipped: make(map[uint32][32]byte)}
}

// senderChain is one member's sending ratchet as a receiver sees it, tagged
// with the epoch of the key it was built from.
type senderChain struct {
	chainState
	Epoch uint32
}

// GroupSession holds this client's own sending chain for a group plus one
// receiving chain per other member. There is no shared group key and no
// privileged member: everyone ratchets their own chain forward and hands the
// starting point to each peer over the direct channel they share.
type GroupSession struct {
	GroupID [16]byte

	// Our own sending chain. Epoch is bumped by RotateSenderKey on every
	// membership change; each member keeps its own epoch counter, so no
	// agreement between members is needed.
	Epoch     uint32
	SendChain [32]byte
	SendCount uint32

	// recv holds the current chain per member, prev the one it replaced.
	// Keeping exactly one generation back means messages already in flight when
	// a member rekeyed still decrypt, without the timer the old shared-key
	// scheme needed.
	recv map[[16]byte]*senderChain
	prev map[[16]byte]*senderChain

	mu sync.Mutex
}

type SessionManager struct {
	sessions      map[[16]byte]*Session
	aux           map[[16]byte][]*auxSession
	groupSessions map[[16]byte]*GroupSession
	mu            sync.RWMutex
	identity      *IdentityManager

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
		store:         store,
		sessions:      make(map[[16]byte]*Session),
		aux:           make(map[[16]byte][]*auxSession),
		groupSessions: make(map[[16]byte]*GroupSession),
		identity:      idMgr,
		selfID:        selfID,
		now:           time.Now,
	}
}

// aadFor binds a packet's header and the plaintext counters in its body to the
// ciphertext. Those counters sit outside the header, so they have to be
// appended explicitly to be covered by the tag: one for a direct message, the
// epoch and then the sequence number for a group message.
func aadFor(h *common.Header, counters ...uint32) []byte {
	aad := h.Bytes()
	var buf [4]byte
	for _, c := range counters {
		binary.BigEndian.PutUint32(buf[:], c)
		aad = append(aad, buf[:]...)
	}
	return aad
}

// chainAdvance is everything that must change for a message to be accepted at
// some sequence number, computed but not yet applied.
type chainAdvance struct {
	MsgKey [32]byte

	nextKey   [32]byte
	nextCount uint32

	// newSkipped holds keys for messages stepped over to reach a future seq.
	newSkipped map[uint32][32]byte

	// usedSkipped names a previously stored key that this message consumed.
	usedSkipped uint32
	fromSkipped bool
}

// commit applies the advance. Call it only once the ciphertext has been
// authenticated.
func (a chainAdvance) commit(c *chainState) {
	if a.fromSkipped {
		delete(c.Skipped, a.usedSkipped)
		return
	}
	for seq, k := range a.newSkipped {
		c.Skipped[seq] = k
	}
	c.Key = a.nextKey
	c.Count = a.nextCount
}

// advanceChain derives the message key for seq without touching c.
//
// Nothing is applied here because the caller cannot yet know whether the
// message is genuine. Ratcheting first is what makes the old code exploitable:
// a forged sequence number pushes the chain somewhere the real messages can
// never reach, permanently rejecting everything that follows, and a replayed
// sequence number consumes a stored key that a genuine late message still
// needs. Both cost an attacker nothing but a well-formed header.
func advanceChain(c *chainState, seq uint32) (chainAdvance, error) {
	if key, ok := c.Skipped[seq]; ok {
		return chainAdvance{MsgKey: key, usedSkipped: seq, fromSkipped: true}, nil
	}
	if seq < c.Count {
		return chainAdvance{}, fmt.Errorf("duplicate or old message: seq %d, expecting %d", seq, c.Count)
	}
	if seq-c.Count > maxSkip {
		return chainAdvance{}, fmt.Errorf("message too far in future: seq %d, expecting %d", seq, c.Count)
	}

	a := chainAdvance{nextKey: c.Key, nextCount: seq + 1}
	if seq > c.Count {
		a.newSkipped = make(map[uint32][32]byte, seq-c.Count)
		for i := c.Count; i < seq; i++ {
			var mk [32]byte
			mk, a.nextKey = common.RatchetStep(a.nextKey)
			a.newSkipped[i] = mk
		}
	}
	a.MsgKey, a.nextKey = common.RatchetStep(a.nextKey)
	return a, nil
}

func (sm *SessionManager) GetGroupSession(groupID [16]byte) (*GroupSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.groupSessions[groupID]
	return sess, ok
}

// DeleteGroupSession discards all key material for a group the user has left,
// so a stale key cannot decrypt anything relayed afterwards.
func (sm *SessionManager) DeleteGroupSession(groupID [16]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.groupSessions, groupID)
}

// EnsureGroupSession returns the session for a group, creating an empty one if
// this client has not keyed it yet. An empty session can already receive: a
// member's chain is installed the moment their CtrlSenderKey arrives, whether
// or not we have generated our own yet.
func (sm *SessionManager) EnsureGroupSession(groupID [16]byte) *GroupSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sess, ok := sm.groupSessions[groupID]; ok {
		return sess
	}
	sess := &GroupSession{
		GroupID: groupID,
		recv:    make(map[[16]byte]*senderChain),
		prev:    make(map[[16]byte]*senderChain),
	}
	sm.groupSessions[groupID] = sess
	return sess
}

// RotateSenderKey generates this client's sending chain for a group and returns
// the chain key to distribute along with the epoch it belongs to. It is called
// once when the group is first keyed and again on every membership change.
//
// Distribute the key this returns, and nothing else. GroupSession.SendChain
// ratchets forward on every message sent, so reading it later hands peers a key
// that cannot open anything already sent in this epoch. Holding on to the
// epoch's starting key here instead would let anyone who obtained it read the
// whole epoch, which is exactly what ratcheting forward is meant to prevent.
//
// The epoch is this member's own counter, not a group-wide one. Nothing has to
// agree on its value: a receiver only ever compares it against the epoch it
// already holds from this same sender.
func (sm *SessionManager) RotateSenderKey(groupID [16]byte) ([32]byte, uint32, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, 0, fmt.Errorf("generating sender key: %w", err)
	}

	gs := sm.EnsureGroupSession(groupID)
	gs.mu.Lock()
	defer gs.mu.Unlock()

	gs.Epoch++
	gs.SendChain = key
	gs.SendCount = 0
	return key, gs.Epoch, nil
}

// SetPeerSenderKey installs a member's sending chain, retiring the one it
// replaces. A key at an epoch we have already moved past is ignored, so a
// replayed distribution cannot wind a chain backwards.
func (sm *SessionManager) SetPeerSenderKey(groupID, senderID [16]byte, chainKey [32]byte, epoch uint32) error {
	gs := sm.EnsureGroupSession(groupID)
	gs.mu.Lock()
	defer gs.mu.Unlock()

	if cur, ok := gs.recv[senderID]; ok {
		if epoch <= cur.Epoch {
			return fmt.Errorf("stale sender key from %x: epoch %d, already holding %d",
				senderID[:4], epoch, cur.Epoch)
		}
		gs.prev[senderID] = cur
	}
	gs.recv[senderID] = &senderChain{chainState: newChainState(chainKey), Epoch: epoch}
	return nil
}

// ForgetSender drops all chain material for a member who has left the group.
func (sm *SessionManager) ForgetSender(groupID, senderID [16]byte) {
	gs, ok := sm.GetGroupSession(groupID)
	if !ok {
		return
	}
	gs.mu.Lock()
	defer gs.mu.Unlock()
	delete(gs.recv, senderID)
	delete(gs.prev, senderID)
}

// HasSenderKey reports whether a member's chain is installed.
func (sm *SessionManager) HasSenderKey(groupID, senderID [16]byte) bool {
	gs, ok := sm.GetGroupSession(groupID)
	if !ok {
		return false
	}
	gs.mu.Lock()
	defer gs.mu.Unlock()
	_, held := gs.recv[senderID]
	return held
}

// chainForLocked picks the chain a message should be read with. Caller holds gs.mu.
func (gs *GroupSession) chainForLocked(senderID [16]byte, epoch uint32) (*senderChain, error) {
	cur, ok := gs.recv[senderID]
	if !ok {
		return nil, fmt.Errorf("%w: nothing held for %x in group %x",
			ErrNoSenderKey, senderID[:4], gs.GroupID[:4])
	}

	switch {
	case epoch == cur.Epoch:
		return cur, nil

	case epoch > cur.Epoch:
		// They have rekeyed and the distribution has not reached us yet. This is
		// recoverable, so it reports as ErrNoSenderKey and the caller holds the
		// message rather than discarding it.
		return nil, fmt.Errorf("%w: %x is at epoch %d, holding %d",
			ErrNoSenderKey, senderID[:4], epoch, cur.Epoch)
	}

	if old, ok := gs.prev[senderID]; ok && epoch == old.Epoch {
		return old, nil
	}
	return nil, fmt.Errorf("message from %x at retired epoch %d", senderID[:4], epoch)
}

func (sm *SessionManager) EncryptGroupPacket(pkt *common.Packet) error {
	session, ok := sm.GetGroupSession(pkt.Header.ConversationID)
	if !ok {
		return fmt.Errorf("%w: %x", ErrNoGroupSession, pkt.Header.ConversationID[:4])
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.Epoch == 0 {
		return fmt.Errorf("no sending chain for group %x yet", pkt.Header.ConversationID[:4])
	}

	msgKey, nextChain := common.RatchetStep(session.SendChain)
	epoch, seq := session.Epoch, session.SendCount

	expectedEncryptedLen := len(pkt.Body) + common.NonceSize + 16
	pkt.Header.BodyLen = uint32(groupPrefixLen + expectedEncryptedLen)
	pkt.Header.Flags |= common.FlagEncrypted

	encryptedBody, err := common.Encrypt(msgKey, pkt.Body, aadFor(&pkt.Header, epoch, seq))
	if err != nil {
		return err
	}

	body := make([]byte, groupPrefixLen+len(encryptedBody))
	binary.BigEndian.PutUint32(body[0:], epoch)
	binary.BigEndian.PutUint32(body[4:], seq)
	copy(body[groupPrefixLen:], encryptedBody)
	pkt.Body = body

	session.SendChain = nextChain
	session.SendCount++
	return nil
}

func (sm *SessionManager) DecryptGroupPacket(pkt *common.Packet) error {
	if pkt.Header.Flags&common.FlagEncrypted == 0 {
		return nil
	}

	session, ok := sm.GetGroupSession(pkt.Header.ConversationID)
	if !ok {
		return fmt.Errorf("%w: %x", ErrNoGroupSession, pkt.Header.ConversationID[:4])
	}

	if len(pkt.Body) < groupPrefixLen+common.NonceSize {
		return fmt.Errorf("group packet too short")
	}
	epoch := binary.BigEndian.Uint32(pkt.Body[0:4])
	seq := binary.BigEndian.Uint32(pkt.Body[4:8])
	ciphertext := pkt.Body[groupPrefixLen:]

	session.mu.Lock()
	defer session.mu.Unlock()

	// SenderID is stamped by the server and covered by the associated data, so a
	// forged one fails the tag rather than selecting somebody else's chain.
	chain, err := session.chainForLocked(pkt.Header.SenderID, epoch)
	if err != nil {
		return err
	}

	adv, err := advanceChain(&chain.chainState, seq)
	if err != nil {
		return err
	}

	decrypted, err := common.Decrypt(adv.MsgKey, ciphertext, aadFor(&pkt.Header, epoch, seq))
	if err != nil {
		return fmt.Errorf("group decryption failed for %x seq %d: %v", pkt.Header.SenderID[:4], seq, err)
	}
	adv.commit(&chain.chainState)

	pkt.Body = decrypted
	pkt.Header.BodyLen = uint32(len(decrypted))
	pkt.Header.Flags &^= common.FlagEncrypted
	return nil
}
