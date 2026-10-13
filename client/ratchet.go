package main

import (
	common "common"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"sync"
	"time"
)

// Policy for the direct ratchet.
const (
	// RotateEvery is how many messages one party sends in an epoch before it
	// mixes in a fresh ephemeral key. The count is the sender's own, so the two
	// sides rotate independently and nothing has to be agreed.
	RotateEvery = 50

	// MaxSkipDirect bounds how far past the expected index a message may claim
	// to be, so one forged index cannot cost an unbounded number of ratchet steps.
	MaxSkipDirect = 1000

	// maxSkippedTotal bounds the skipped keys held across all epochs.
	maxSkippedTotal = 4 * MaxSkipDirect

	// MaxUnackedEpochs stops DH rotation when the peer has not used any of our
	// recent keys. Past it we keep ratcheting symmetrically and stop retaining a
	// new private key for every fifty messages sent into the void.
	MaxUnackedEpochs = 20

	// SkippedKeyTTL is how long a key for a message that never arrived is kept.
	SkippedKeyTTL = 7 * 24 * time.Hour

	// maxRetiredInits bounds the superseded handshakes remembered per conversation.
	maxRetiredInits = 16

	// A losing simultaneous handshake is kept receive-only for a while, so the
	// messages its owner sent before switching can still be read.
	auxIdle        = 5 * time.Minute
	auxMaxMessages = 100

	sessionRecordPrefix = "session-"
)

var (
	// ErrEpochGap means a message belongs to an epoch whose predecessor has not
	// arrived, so its keys cannot be derived yet. It is recoverable: the message
	// is held and replayed once the missing one lands.
	ErrEpochGap = errors.New("message is ahead of an epoch that has not arrived")

	// ErrPeerKeyMismatch means a peer presented an identity key that differs from
	// the one the server vouches for.
	ErrPeerKeyMismatch = errors.New("peer identity key does not match the directory")
)

type ratchetPair struct {
	Private [32]byte
	Public  [32]byte
}

type sendChain struct {
	RK, CK        [32]byte
	Epoch         uint32 // our ratchet key this chain was built from
	N             uint32 // messages sent in this epoch
	UsedPeerEpoch uint32 // which of the peer's keys it was built against
	PrevLen       uint32 // messages sent in the previous epoch
	Started       bool
}

type recvChain struct {
	RK, CK  [32]byte
	Epoch   uint32 // the peer's sending epoch; 0 until the first message
	N       uint32
	Started bool
}

type skippedID struct{ Epoch, N uint32 }

type skippedKey struct {
	Key [32]byte
	At  time.Time
}

// sessionState is everything about one direct conversation that has to survive
// a restart. It is plain data so it can be copied, saved and restored whole.
type sessionState struct {
	SelfID         [16]byte
	ConversationID [16]byte
	PeerID         [16]byte
	PeerName       string
	PeerIK         [32]byte
	PeerSigning    [32]byte

	// Unverified is set when the peer's identity key came from a message header
	// rather than the server's directory, and clears once the roster agrees.
	Unverified bool

	// Initiator marks the side that opened the handshake. Pending means it has
	// not yet received anything on this session; until it has, every message
	// repeats the handshake fields so the peer can build the session from any one
	// of them, and the session loses a simultaneous-handshake tie-break.
	Initiator bool
	Pending   bool
	InitIK    [32]byte // initiator's identity key
	InitEK    [32]byte // initiator's handshake ephemeral key
	SPKID     uint32   // the responder's signed prekey the handshake used

	// RetiredInits holds the handshake keys of peer sessions this one replaced,
	// so a captured first message cannot be replayed to roll the session back.
	RetiredInits [][32]byte

	DirSend common.Direction

	// Our own ratchet keys by epoch, kept until the peer has moved past them.
	// Epoch 0 is the responder's signed prekey and is held by the identity, not
	// here, since it is shared across sessions.
	MyKeys  map[uint32]ratchetPair
	MyEpoch uint32

	PeerPubLatest   [32]byte
	PeerEpochLatest uint32
	PeerAcked       uint32 // newest of our keys the peer has used

	Send    sendChain
	Recv    recvChain
	Skipped map[skippedID]skippedKey
}

func (st *sessionState) normalize() {
	if st.MyKeys == nil {
		st.MyKeys = make(map[uint32]ratchetPair)
	}
	if st.Skipped == nil {
		st.Skipped = make(map[skippedID]skippedKey)
	}
}

func (st *sessionState) clone() *sessionState {
	c := *st
	c.MyKeys = maps.Clone(st.MyKeys)
	c.Skipped = maps.Clone(st.Skipped)
	c.RetiredInits = slices.Clone(st.RetiredInits)
	c.normalize()
	return &c
}

func (st *sessionState) dirRecv() common.Direction { return st.DirSend.Opposite() }

func (st *sessionState) matchesInit(i *common.RatchetInit) bool {
	return st.InitIK == i.IdentityKey && st.InitEK == i.Ephemeral
}

// Session is one live direct conversation.
type Session struct {
	mu sync.Mutex
	st sessionState
}

// rootsFor splits a handshake secret into the roots for the direction this
// party sends on and the one it receives on.
func rootsFor(sk [32]byte, send common.Direction) (sendRK, recvRK [32]byte, err error) {
	lh, hl, err := common.DeriveDirectionRoots(sk)
	if err != nil {
		return
	}
	if send == common.LowToHigh {
		return lh, hl, nil
	}
	return hl, lh, nil
}

// --- sending ---

func (st *sessionState) shouldRotate() bool {
	if !st.Send.Started {
		return true
	}
	if st.MyEpoch-st.PeerAcked >= MaxUnackedEpochs {
		return false
	}
	if st.Send.N >= RotateEvery {
		return true
	}
	// The peer has published a key we have not yet used: use it at once, so a
	// compromise heals as soon as the other side has contributed fresh entropy.
	return st.PeerEpochLatest > st.Send.UsedPeerEpoch
}

func (st *sessionState) rotateSend() error {
	priv, pub, err := common.GenerateEphemeralKeys()
	if err != nil {
		return err
	}
	return st.rotateSendWith(ratchetPair{Private: priv, Public: pub})
}

// rotateSendWith starts a new sending epoch from kp, mixing the DH of kp against
// the newest peer key into this direction's root. The handshake's own ephemeral
// key is used as the first kp, which is why the key is a parameter.
func (st *sessionState) rotateSendWith(kp ratchetPair) error {
	if !common.IsValidKey(st.PeerPubLatest) {
		return errors.New("no peer ratchet key to rotate against yet")
	}
	dh, err := common.DeriveSharedSecret(kp.Private, st.PeerPubLatest)
	if err != nil {
		return err
	}
	rk, ck, err := common.KDFRootKey(st.Send.RK, dh, st.DirSend.RatchetInfo())
	if err != nil {
		return err
	}

	st.MyEpoch++
	st.MyKeys[st.MyEpoch] = kp
	prev := uint32(0)
	if st.Send.Started {
		prev = st.Send.N
	}
	st.Send = sendChain{
		RK: rk, CK: ck,
		Epoch: st.MyEpoch, UsedPeerEpoch: st.PeerEpochLatest,
		PrevLen: prev, Started: true,
	}
	return nil
}

// seal encrypts pkt.Body in place, rotating first if the policy calls for it.
func (st *sessionState) seal(pkt *common.Packet) error {
	if st.shouldRotate() {
		if err := st.rotateSend(); err != nil {
			return err
		}
	}

	hdr := common.RatchetHeader{
		SenderEpoch:   st.Send.Epoch,
		UsedPeerEpoch: st.Send.UsedPeerEpoch,
		N:             st.Send.N,
		PrevLen:       st.Send.PrevLen,
		RatchetPub:    st.MyKeys[st.Send.Epoch].Public,
	}
	if st.Initiator && st.Pending {
		hdr.Init = &common.RatchetInit{IdentityKey: st.InitIK, Ephemeral: st.InitEK, SPKID: st.SPKID}
	}
	hb := hdr.Encode()

	// BodyLen is fixed before sealing because the header is authenticated and
	// must carry the length the receiver will see.
	pkt.Header.BodyLen = uint32(len(hb) + common.NonceSize + len(pkt.Body) + 16)
	pkt.Header.Flags |= common.FlagEncrypted

	mk, next := common.RatchetStep(st.Send.CK)
	ct, err := common.Encrypt(mk, pkt.Body, append(pkt.Header.Bytes(), hb...))
	mk = [32]byte{}
	if err != nil {
		return err
	}

	st.Send.CK = next
	st.Send.N++
	pkt.Body = append(hb, ct...)
	return nil
}

// --- receiving ---

// open authenticates and decrypts one message. It works on a copy and returns
// the advanced state only if the tag verifies, so nothing a forger can send
// moves the real chain: not a far-future index, not a replayed one.
func (st *sessionState) open(hdr *common.RatchetHeader, ct, ad []byte,
	spk func(uint32) ([32]byte, bool), now time.Time) ([]byte, *sessionState, error) {

	w := st.clone()
	w.purgeSkipped(now)

	e := hdr.SenderEpoch
	if e == 0 {
		return nil, nil, errors.New("message claims epoch 0")
	}

	var mk [32]byte
	late := false

	if e < w.Recv.Epoch || (e == w.Recv.Epoch && hdr.N < w.Recv.N) {
		id := skippedID{e, hdr.N}
		held, ok := w.Skipped[id]
		if !ok {
			return nil, nil, fmt.Errorf("old or replayed message: epoch %d, n %d", e, hdr.N)
		}
		mk = held.Key
		delete(w.Skipped, id)
		late = true
	} else {
		if e > w.Recv.Epoch+1 {
			return nil, nil, fmt.Errorf("%w: epoch %d, at %d", ErrEpochGap, e, w.Recv.Epoch)
		}
		if e == w.Recv.Epoch+1 {
			if err := w.stepRecv(hdr, spk, now); err != nil {
				return nil, nil, err
			}
		}
		if err := w.skipTo(hdr.N, now); err != nil {
			return nil, nil, err
		}
		mk, w.Recv.CK = common.RatchetStep(w.Recv.CK)
		w.Recv.N++
	}

	pt, err := common.Decrypt(mk, ct, ad)
	mk = [32]byte{}
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed (epoch %d, n %d): %v", e, hdr.N, err)
	}

	if !late {
		if hdr.UsedPeerEpoch > w.PeerAcked {
			w.PeerAcked = hdr.UsedPeerEpoch
		}
		// The peer only moves forward, so keys older than the one it just used
		// can never be needed again. Deleting them is what makes the messages
		// they protected unrecoverable, which is the point of the exercise.
		for k := range w.MyKeys {
			if k < hdr.UsedPeerEpoch {
				delete(w.MyKeys, k)
			}
		}
	}
	w.Pending = false
	return pt, w, nil
}

// stepRecv moves the receiving chain to the peer's next epoch.
func (w *sessionState) stepRecv(hdr *common.RatchetHeader, spk func(uint32) ([32]byte, bool), now time.Time) error {
	// Messages the old epoch still owes us arrive late or never; their keys are
	// set aside before the chain is replaced.
	if w.Recv.Started {
		if err := w.skipTo(hdr.PrevLen, now); err != nil {
			return err
		}
	}

	priv, err := w.myKey(hdr.UsedPeerEpoch, spk)
	if err != nil {
		return err
	}
	dh, err := common.DeriveSharedSecret(priv, hdr.RatchetPub)
	if err != nil {
		return fmt.Errorf("bad ratchet key: %w", err)
	}
	rk, ck, err := common.KDFRootKey(w.Recv.RK, dh, w.dirRecv().RatchetInfo())
	if err != nil {
		return err
	}

	w.Recv = recvChain{RK: rk, CK: ck, Epoch: hdr.SenderEpoch, Started: true}
	w.PeerPubLatest = hdr.RatchetPub
	w.PeerEpochLatest = hdr.SenderEpoch
	return nil
}

// myKey finds the private key the peer says it used. Epoch 0 is the signed
// prekey, which only a responder can have been addressed through.
func (w *sessionState) myKey(epoch uint32, spk func(uint32) ([32]byte, bool)) ([32]byte, error) {
	if epoch == 0 {
		if w.Initiator {
			return [32]byte{}, errors.New("peer used a key we never published")
		}
		k, ok := spk(w.SPKID)
		if !ok {
			return [32]byte{}, fmt.Errorf("signed prekey %d is no longer held", w.SPKID)
		}
		return k, nil
	}
	kp, ok := w.MyKeys[epoch]
	if !ok {
		return [32]byte{}, fmt.Errorf("ratchet key for epoch %d is unknown or already deleted", epoch)
	}
	return kp.Private, nil
}

// skipTo advances the receiving chain to index until, keeping the key of every
// message stepped over so it can still be read if it turns up.
func (w *sessionState) skipTo(until uint32, now time.Time) error {
	if until <= w.Recv.N {
		return nil
	}
	gap := until - w.Recv.N
	if gap > MaxSkipDirect {
		return fmt.Errorf("message too far ahead: skips %d, limit %d", gap, MaxSkipDirect)
	}
	if len(w.Skipped)+int(gap) > maxSkippedTotal {
		return errors.New("too many skipped message keys held")
	}
	for w.Recv.N < until {
		var mk [32]byte
		mk, w.Recv.CK = common.RatchetStep(w.Recv.CK)
		w.Skipped[skippedID{w.Recv.Epoch, w.Recv.N}] = skippedKey{Key: mk, At: now}
		w.Recv.N++
	}
	return nil
}

func (w *sessionState) purgeSkipped(now time.Time) {
	for id, k := range w.Skipped {
		if now.Sub(k.At) > SkippedKeyTTL {
			delete(w.Skipped, id)
		}
	}
}

// --- session manager: direct conversations ---

// auxSession is a session kept only to read: the losing side of a simultaneous
// handshake, whose owner may have sent messages before it noticed.
type auxSession struct {
	sess      *Session
	expires   time.Time
	remaining int
}

// PeerInfo describes a restored conversation so the caller can show it again.
type PeerInfo struct {
	ConversationID [16]byte
	PeerID         [16]byte
	Name           string
	IdentityKey    [32]byte
	SigningKey     [32]byte

	// Unverified means the identity key came from a message header and the
	// server's roster has not yet confirmed it.
	Unverified bool
}

func recordName(convID [16]byte) string { return sessionRecordPrefix + hex.EncodeToString(convID[:]) }

func (sm *SessionManager) persist(st *sessionState) error {
	if sm.store == nil {
		return nil
	}
	return sm.store.Save(recordName(st.ConversationID), st)
}

func (sm *SessionManager) GetSession(convID [16]byte) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessions[convID]
	return sess, ok
}

// LoadSessions restores saved direct sessions. Records written under a different
// user ID are skipped: the conversation ID is derived from both IDs, so they
// belong to another account or server and could never match here.
func (sm *SessionManager) LoadSessions() ([]PeerInfo, error) {
	if sm.store == nil {
		return nil, nil
	}
	names, err := sm.store.List(sessionRecordPrefix)
	if err != nil {
		return nil, err
	}

	var restored []PeerInfo
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, name := range names {
		var st sessionState
		if ok, err := sm.store.Load(name, &st); err != nil {
			return restored, err
		} else if !ok || st.SelfID != sm.selfID {
			continue
		}
		st.normalize()
		sm.sessions[st.ConversationID] = &Session{st: st}
		restored = append(restored, PeerInfo{
			ConversationID: st.ConversationID, PeerID: st.PeerID, Name: st.PeerName,
			IdentityKey: st.PeerIK, SigningKey: st.PeerSigning, Unverified: st.Unverified,
		})
	}
	return restored, nil
}

// OpenResult says what OpenDirectSession did to a session that already existed.
type OpenResult struct {
	// Replaced is set when an existing session was discarded for a fresh one.
	Replaced bool

	// IdentityChanged is set when the peer's identity key differs from the one the
	// discarded session was built on.
	IdentityChanged bool
}

// OpenDirectSession starts a conversation with someone whose prekey bundle the
// server has just supplied. Nothing is sent: the first message carries the
// handshake, so the peer can be offline.
//
// An existing session is kept by default, since it holds ratchet state that
// cannot be rebuilt. Two things replace it: a bundle with a different identity
// key, and force, which is how a user abandons a session that has gone wrong. The
// ratchet cannot step past an epoch none of whose messages arrived, so a direction
// that lost one stays stuck, and starting over is the only way out. Either side
// can do it: the peer takes the new handshake for a restart.
func (sm *SessionManager) OpenDirectSession(convID, peerID [16]byte, peerName string, b common.PreKeyBundle, force bool) (OpenResult, error) {
	var res OpenResult
	if !b.Verify() {
		return res, errors.New("the peer's prekey bundle failed verification")
	}

	// Handshakes of the peer's that the session being replaced had already
	// superseded or was built on, so a captured copy cannot bring one back.
	var retired [][32]byte

	if sess, ok := sm.GetSession(convID); ok {
		sess.mu.Lock()
		same := sess.st.PeerIK == b.IdentityKey
		if same && !force {
			sess.st.PeerName, sess.st.PeerSigning, sess.st.Unverified = peerName, b.SigningKey, false
			sm.persist(&sess.st)
			sess.mu.Unlock()
			return res, nil
		}
		res.Replaced, res.IdentityChanged = true, !same
		retired = slices.Clone(sess.st.RetiredInits)
		if !sess.st.Initiator {
			retired = appendBounded(retired, sess.st.InitEK)
		}
		sess.mu.Unlock()
	}

	ekPriv, ekPub, err := common.GenerateEphemeralKeys()
	if err != nil {
		return res, err
	}
	sk, err := common.InitiatorSecret(sm.identity.PrivateKey, ekPriv, b.IdentityKey, b.SPK)
	if err != nil {
		return res, err
	}
	dir := common.SendDirection(sm.selfID, peerID)
	sendRK, recvRK, err := rootsFor(sk, dir)
	if err != nil {
		return res, err
	}

	st := sessionState{
		SelfID: sm.selfID, ConversationID: convID, PeerID: peerID, PeerName: peerName,
		PeerIK: b.IdentityKey, PeerSigning: b.SigningKey,
		Initiator: true, Pending: true,
		InitIK: sm.identity.PublicKey, InitEK: ekPub, SPKID: b.SPKID,
		RetiredInits: retired,
		DirSend:      dir,
		// The signed prekey stands in for the peer's epoch-0 ratchet key.
		PeerPubLatest: b.SPK, PeerEpochLatest: 0,
		Send: sendChain{RK: sendRK}, Recv: recvChain{RK: recvRK},
	}
	st.normalize()
	if err := st.rotateSendWith(ratchetPair{Private: ekPriv, Public: ekPub}); err != nil {
		return res, err
	}
	if err := sm.persist(&st); err != nil {
		return res, fmt.Errorf("saving session: %w", err)
	}

	sm.mu.Lock()
	sm.sessions[convID] = &Session{st: st}
	delete(sm.aux, convID) // anything kept to read the old session goes with it
	sm.mu.Unlock()
	return res, nil
}

// newResponderState builds the receiving side of a handshake from the fields a
// message carries. The peer's identity key arrives in that message, so it is
// checked against the directory if the directory is known and flagged for a
// later check if not.
func (sm *SessionManager) newResponderState(convID, peerID [16]byte, init *common.RatchetInit) (*sessionState, error) {
	if !common.IsValidKey(init.IdentityKey) || !common.IsValidKey(init.Ephemeral) {
		return nil, errors.New("handshake carries an empty key")
	}
	unverified := true
	if sm.KnownKey != nil {
		if known, ok := sm.KnownKey(peerID); ok {
			if known != init.IdentityKey {
				return nil, ErrPeerKeyMismatch
			}
			unverified = false
		}
	}

	spkPriv, ok := sm.identity.SPKPrivate(init.SPKID)
	if !ok {
		return nil, fmt.Errorf("handshake names signed prekey %d, which is not held", init.SPKID)
	}
	sk, err := common.ResponderSecret(sm.identity.PrivateKey, spkPriv, init.IdentityKey, init.Ephemeral)
	if err != nil {
		return nil, err
	}
	dir := common.SendDirection(sm.selfID, peerID)
	sendRK, recvRK, err := rootsFor(sk, dir)
	if err != nil {
		return nil, err
	}

	st := &sessionState{
		SelfID: sm.selfID, ConversationID: convID, PeerID: peerID,
		PeerIK: init.IdentityKey, Unverified: unverified,
		InitIK: init.IdentityKey, InitEK: init.Ephemeral, SPKID: init.SPKID,
		DirSend: dir,
		Send:    sendChain{RK: sendRK}, Recv: recvChain{RK: recvRK},
	}
	st.normalize()
	return st, nil
}

func (sm *SessionManager) EncryptPacket(pkt *common.Packet) error {
	sess, ok := sm.GetSession(pkt.Header.ConversationID)
	if !ok {
		return fmt.Errorf("%w: %x", ErrNoSession, pkt.Header.ConversationID[:4])
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if err := sess.st.seal(pkt); err != nil {
		return err
	}
	// The ratchet has moved on and must not be allowed to revisit this key, so
	// the new state is on disk before the ciphertext can leave the machine. If
	// the save fails the message is not sent; the skipped index is harmless,
	// since the receiver stores a key for it and simply never uses it.
	if err := sm.persist(&sess.st); err != nil {
		return fmt.Errorf("could not save session state, message not sent: %w", err)
	}
	return nil
}

func (sm *SessionManager) DecryptPacket(pkt *common.Packet) error {
	if pkt.Header.Flags&common.FlagEncrypted == 0 {
		return nil
	}

	hdr, hlen, err := common.DecodeRatchetHeader(pkt.Body)
	if err != nil {
		return fmt.Errorf("bad ratchet header: %w", err)
	}
	if len(pkt.Body) < hlen+common.NonceSize {
		return errors.New("packet too short for ratcheted E2EE")
	}
	// The header goes in as it was received, byte for byte, with the packet
	// header's length field still describing the ciphertext.
	ad := append(pkt.Header.Bytes(), pkt.Body[:hlen]...)
	ct := pkt.Body[hlen:]

	pt, err := sm.decryptDirect(pkt.Header.ConversationID, pkt.Header.SenderID, &hdr, ct, ad)
	if err != nil {
		return err
	}
	pkt.Body = pt
	pkt.Header.BodyLen = uint32(len(pt))
	pkt.Header.Flags &^= common.FlagEncrypted
	return nil
}

func (sm *SessionManager) decryptDirect(convID, from [16]byte, hdr *common.RatchetHeader, ct, ad []byte) ([]byte, error) {
	now := sm.now()

	sm.mu.Lock()
	primary := sm.sessions[convID]
	aux := sm.liveAuxLocked(convID, now)
	sm.mu.Unlock()

	if hdr.Init == nil {
		if primary == nil {
			return nil, fmt.Errorf("%w: %x", ErrNoSession, convID[:4])
		}
		return sm.openOn(primary, from, hdr, ct, ad, now)
	}

	if primary != nil && primary.matches(hdr.Init) {
		return sm.openOn(primary, from, hdr, ct, ad, now)
	}
	for _, a := range aux {
		if a.sess.matches(hdr.Init) {
			pt, err := sm.openOn(a.sess, from, hdr, ct, ad, now)
			if err == nil {
				sm.mu.Lock()
				a.expires, a.remaining = now.Add(auxIdle), a.remaining-1
				sm.mu.Unlock()
			}
			return pt, err
		}
	}
	pt, replaced, err := sm.openNewSession(convID, from, hdr, ct, ad, primary, now)
	if replaced && sm.OnReplaced != nil {
		// Called with no lock held, so the callback may use the manager.
		sm.OnReplaced(convID)
	}
	return pt, err
}

func (s *Session) matches(i *common.RatchetInit) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.matchesInit(i)
}

func (sm *SessionManager) openOn(s *Session, from [16]byte, hdr *common.RatchetHeader, ct, ad []byte, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if from != s.st.PeerID {
		return nil, errors.New("packet sender is not this conversation's peer")
	}
	pt, next, err := s.st.open(hdr, ct, ad, sm.identity.SPKPrivate, now)
	if err != nil {
		return nil, err
	}
	s.st = *next
	if err := sm.persist(&s.st); err != nil {
		log.Printf("[ERROR] could not save session %x: %v", s.st.ConversationID[:4], err)
	}
	return pt, nil
}

// openNewSession handles a message whose handshake fields match no session we
// hold: a first message, a restart by the peer, or the other half of a
// simultaneous handshake. The candidate is built and must authenticate before
// anything already held is touched, so an unauthenticated packet cannot evict
// a working session.
//
// replaced reports whether a session that was already in place gave way to the
// new one, which makes anything held for the old one permanently unreadable.
func (sm *SessionManager) openNewSession(convID, from [16]byte, hdr *common.RatchetHeader, ct, ad []byte,
	primary *Session, now time.Time) (pt []byte, replaced bool, err error) {

	if primary != nil {
		primary.mu.Lock()
		retired := slices.Contains(primary.st.RetiredInits, hdr.Init.Ephemeral)
		primary.mu.Unlock()
		if retired {
			return nil, false, errors.New("handshake belongs to a session that was already replaced")
		}
	}

	cand, err := sm.newResponderState(convID, from, hdr.Init)
	if err != nil {
		return nil, false, err
	}
	pt, next, err := cand.open(hdr, ct, ad, sm.identity.SPKPrivate, now)
	if err != nil {
		return nil, false, err
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	cur := sm.sessions[convID]
	if cur == nil {
		sm.install(convID, next)
		return pt, false, nil
	}

	cur.mu.Lock()
	defer cur.mu.Unlock()
	next.RetiredInits = slices.Clone(cur.st.RetiredInits)

	if cur.st.Initiator && cur.st.Pending {
		// Both sides opened a handshake at once. The one opened by the lower
		// user ID stands; each side reaches that verdict without a word to the
		// other.
		if common.LowerID(sm.selfID, from) {
			// Ours stands. Theirs is kept only to read what they sent before
			// they learn that.
			sm.aux[convID] = append(sm.aux[convID], &auxSession{
				sess: &Session{st: *next}, expires: now.Add(auxIdle), remaining: auxMaxMessages,
			})
			return pt, false, nil
		}
		// Theirs stands: adopt it and send on it from here. Anything we sent on
		// ours is still readable by them for a few minutes.
		sm.install(convID, next)
		return pt, true, nil
	}

	// We already heard from this peer on a session, so a handshake from them now
	// is a deliberate restart (a reinstall, say) and replaces it.
	if !cur.st.Initiator {
		next.RetiredInits = appendBounded(next.RetiredInits, cur.st.InitEK)
	}
	sm.install(convID, next)
	return pt, true, nil
}

// install makes st the session for its conversation. Caller holds sm.mu.
func (sm *SessionManager) install(convID [16]byte, st *sessionState) {
	if err := sm.persist(st); err != nil {
		log.Printf("[ERROR] could not save session %x: %v", convID[:4], err)
	}
	sm.sessions[convID] = &Session{st: *st}
}

func appendBounded(list [][32]byte, k [32]byte) [][32]byte {
	list = append(list, k)
	if len(list) > maxRetiredInits {
		list = list[len(list)-maxRetiredInits:]
	}
	return list
}

// liveAuxLocked returns the receive-only sessions for a conversation that have
// not expired, discarding those that have. An expired one leaves its handshake
// key behind in the primary session's retired list, so that a straggler carrying
// it cannot bring the session back to life. Caller holds sm.mu.
func (sm *SessionManager) liveAuxLocked(convID [16]byte, now time.Time) []*auxSession {
	var live []*auxSession
	for _, a := range sm.aux[convID] {
		if now.Before(a.expires) && a.remaining > 0 {
			live = append(live, a)
			continue
		}
		if primary := sm.sessions[convID]; primary != nil {
			primary.mu.Lock()
			primary.st.RetiredInits = appendBounded(primary.st.RetiredInits, a.sess.st.InitEK)
			primary.mu.Unlock()
		}
	}
	if len(live) == 0 {
		delete(sm.aux, convID)
	} else {
		sm.aux[convID] = live
	}
	return live
}

// NotePeerKeys records what the server's roster says about a peer. It reports
// ErrPeerKeyMismatch, and drops the session, if a session built from a message
// header named a different identity key than the directory does.
func (sm *SessionManager) NotePeerKeys(convID, peerID [16]byte, name string, ik, signing [32]byte) error {
	sess, ok := sm.GetSession(convID)
	if !ok {
		return nil
	}

	// The session lock is released before the manager's is taken: openNewSession
	// takes them the other way round, and holding both here would invite deadlock.
	sess.mu.Lock()
	if sess.st.PeerID != peerID {
		sess.mu.Unlock()
		return nil
	}
	if sess.st.PeerIK == ik {
		sess.st.Unverified = false
		sess.st.PeerName, sess.st.PeerSigning = name, signing
		err := sm.persist(&sess.st)
		sess.mu.Unlock()
		return err
	}
	sess.mu.Unlock()

	sm.mu.Lock()
	if sm.sessions[convID] == sess {
		delete(sm.sessions, convID)
	}
	delete(sm.aux, convID)
	sm.mu.Unlock()
	if sm.store != nil {
		sm.store.Delete(recordName(convID))
	}
	return ErrPeerKeyMismatch
}

// SafetyNumber is what the two people compare to confirm nobody substituted a
// key. It needs the peer's signing key, which a responder only learns from the
// roster.
func (sm *SessionManager) SafetyNumber(convID [16]byte) (string, error) {
	sess, ok := sm.GetSession(convID)
	if !ok {
		return "", ErrNoSession
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if !common.IsValidKey(sess.st.PeerSigning) {
		return "", errors.New("the peer's signing key is not known yet")
	}
	return sm.identity.SafetyNumber(sess.st.PeerIK, sess.st.PeerSigning), nil
}
