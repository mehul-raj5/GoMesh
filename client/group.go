package main

import (
	common "common"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Group encryption with sender keys.
//
// Every member owns a sender key for each group: a chain key that ratchets
// forward once per message and an Ed25519 key pair that signs what they send.
// A member hands that key to each other member separately, inside the 1:1
// ratchet session they share, so the server only ever carries sealed unicasts.
// Sending is then one encryption and one signature, fanned out by the server.
//
// Everyone who holds a member's sender key can derive their message keys, so the
// signature is what says who wrote a message. Membership comes from a signed log
// every client verifies (common.Membership); keys are only ever given to, and
// messages only ever accepted from, the members that log names.

// Policy for group sender keys.
const (
	// GroupRotateEvery is how many messages this member sends under one sender
	// key before replacing it, and GroupRotateMaxAge how old a key may get.
	GroupRotateEvery  = 100
	GroupRotateMaxAge = 7 * 24 * time.Hour

	// OldKeyGrace is how long a peer's previous sender key stays readable after
	// they rotate, for messages that were already in flight.
	OldKeyGrace = 24 * time.Hour

	// MaxSkipGroup bounds how far ahead of a chain a message may claim to be.
	MaxSkipGroup = 1000

	// GroupPendingTTL is how long a group message waits for the key or the
	// membership it depends on.
	GroupPendingTTL = 7 * 24 * time.Hour

	// maxGroupSkipped bounds the skipped keys held for one sender key.
	maxGroupSkipped = 4 * MaxSkipGroup

	// maxHeldSKDM bounds distributions held per group while membership catches up.
	maxHeldSKDM = 64

	// A group record is one of three kinds, each bounded on its own so that none
	// can crowd out the others. Verified groups are the ones this client belongs
	// to. A stub exists only because a sender key arrived for a group we have not
	// heard of, so anyone who can reach us over a 1:1 session can create one: they
	// are few and expire. A tombstone remembers a group we left; the oldest go
	// first, and forgetting one only means a late key for it is held, not refused.
	maxVerifiedGroups = 256
	maxStubRecords    = 32
	maxTombstones     = 512

	// maxBufferedChanges bounds membership changes held waiting for a gap.
	maxBufferedChanges = 64

	groupRecordPrefix = "group-"
)

var (
	// ErrMembershipBehind means a message comes from a membership version this
	// device has not yet verified. It is held until the log catches up.
	ErrMembershipBehind = errors.New("message is from a membership version not yet verified")

	// ErrNotInGroup means the sender, or this client, is not a member of the group.
	ErrNotInGroup = errors.New("not a member of this group")
)

// NeedSessionsError reports members this client cannot yet send a key to
// because it holds no 1:1 session with them and no prekey bundle to open one.
// Nothing was sent or consumed; retry once their bundles arrive.
type NeedSessionsError struct{ Peers [][16]byte }

func (e *NeedSessionsError) Error() string {
	return fmt.Sprintf("no secure session with %d group member(s) yet", len(e.Peers))
}

// ownSenderKey is this member's own sender key for a group.
type ownSenderKey struct {
	Have bool
	// KeyID counts rotations and is never reused, so it survives the key itself.
	KeyID     uint32
	Chain     [32]byte
	N         uint32
	SignSeed  [32]byte
	SignPub   [32]byte
	CreatedAt time.Time

	// DeliveredTo are the members who have been sent this key.
	DeliveredTo [][16]byte
	MustRotate  bool
}

func (o ownSenderKey) clone() ownSenderKey {
	o.DeliveredTo = slices.Clone(o.DeliveredTo)
	return o
}

// peerKey is a member's sender key as a receiver holds it.
type peerKey struct {
	KeyID   uint32
	Chain   [32]byte
	N       uint32
	SignPub [32]byte
	// Expires is set once the key has been replaced, and bounds how long it can
	// still read late messages.
	Expires time.Time
	Skipped map[uint32]skippedKey
}

func (k *peerKey) clone() *peerKey {
	if k == nil {
		return nil
	}
	c := *k
	c.Skipped = make(map[uint32]skippedKey, len(k.Skipped))
	for n, s := range k.Skipped {
		c.Skipped[n] = s
	}
	return &c
}

type peerKeys struct {
	Owner    [16]byte
	Current  *peerKey
	Previous *peerKey
}

// heldSKDM is a sender key that arrived before the membership that would admit
// it. The 1:1 message it came in has been consumed, so it cannot be replayed from
// the network and is kept until the log catches up.
type heldSKDM struct {
	Owner [16]byte
	Dist  common.SenderKeyDist
	At    time.Time
}

// hintRec is directory data about a member: a display name and the prekey bundle
// to open a session with. Bundles are stored only if they match the keys the
// signed log vouches for.
type hintRec struct {
	ID     [16]byte
	Name   string
	Bundle common.PreKeyBundle
}

// groupState is everything about one group that must survive a restart.
type groupState struct {
	GroupID [16]byte
	Name    string

	// Left is set once this client is no longer a member. Everything else is
	// cleared, but the record stays so a sender key for a group we are not in is
	// refused rather than held: LeftAt is the last membership version we saw, and
	// only a key from a later one could belong to a re-add.
	Left   bool
	LeftAt uint32

	Membership common.Membership
	Own        ownSenderKey
	Peers      []peerKeys
	Held       []heldSKDM
	Hints      []hintRec
}

type groupRec struct {
	mu     sync.Mutex
	st     groupState
	buffer map[uint32]common.SignedChange // changes that arrived ahead of the log

	// kind and stamp are read without the lock by the code that makes room for new
	// records, which must not take every group's lock to count them. stamp is when
	// the record became a stub or a tombstone, in unix nanoseconds.
	kind  atomic.Int32
	stamp atomic.Int64
}

const (
	kindStub int32 = iota
	kindVerified
	kindTombstone
)

func (r *groupRec) setKind(k int32, now time.Time) {
	r.kind.Store(k)
	r.stamp.Store(now.UnixNano())
}

func groupRecordName(id [16]byte) string { return groupRecordPrefix + hex.EncodeToString(id[:]) }

func (sm *SessionManager) lookupGroup(id [16]byte) *groupRec {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.groups[id]
}

// groupFor returns the record for a group, creating a stub if this client has
// not heard of it. A stub can hold sender keys that arrive early. Making room
// first keeps each kind of record within its bound.
func (sm *SessionManager) groupFor(id [16]byte) (*groupRec, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if r, ok := sm.groups[id]; ok {
		return r, nil
	}
	now := sm.now()
	sm.expireStubsLocked(now)
	sm.evictOldestLocked(kindStub, maxStubRecords-1)
	r := &groupRec{st: groupState{GroupID: id}, buffer: make(map[uint32]common.SignedChange)}
	r.st.Membership.GroupID = id
	r.setKind(kindStub, now)
	sm.groups[id] = r
	return r, nil
}

// countLocked reports how many records are of a kind. Caller holds sm.mu.
func (sm *SessionManager) countLocked(kind int32) int {
	n := 0
	for _, r := range sm.groups {
		if r.kind.Load() == kind {
			n++
		}
	}
	return n
}

// expireStubsLocked drops stubs that have waited longer than a held key may. Caller holds sm.mu.
func (sm *SessionManager) expireStubsLocked(now time.Time) {
	for id, r := range sm.groups {
		if r.kind.Load() == kindStub && now.Sub(time.Unix(0, r.stamp.Load())) > GroupPendingTTL {
			sm.forgetRecordLocked(id)
		}
	}
}

// evictOldestLocked removes the oldest records of a kind until at most keep
// remain. Caller holds sm.mu.
func (sm *SessionManager) evictOldestLocked(kind int32, keep int) {
	for sm.countLocked(kind) > keep {
		var oldest [16]byte
		var at int64
		found := false
		for id, r := range sm.groups {
			if r.kind.Load() != kind {
				continue
			}
			if st := r.stamp.Load(); !found || st < at {
				oldest, at, found = id, st, true
			}
		}
		if !found {
			return
		}
		sm.forgetRecordLocked(oldest)
	}
}

func (sm *SessionManager) forgetRecordLocked(id [16]byte) {
	delete(sm.groups, id)
	if sm.store != nil {
		if err := sm.store.Delete(groupRecordName(id)); err != nil {
			log.Printf("[ERROR] could not delete group record %x: %v", id[:4], err)
		}
	}
}

func (sm *SessionManager) persistGroup(st *groupState) error {
	if sm.store == nil {
		return nil
	}
	return sm.store.Save(groupRecordName(st.GroupID), st)
}

// GroupInfo is a read-only view of a group for the UI.
type GroupInfo struct {
	ID      [16]byte
	Name    string
	Version uint32
	Members []common.MemberKey
	Admins  [][16]byte
	Names   map[[16]byte]string
}

// Group returns what this client has verified about a group. ok is false until
// the group's create has been applied.
func (sm *SessionManager) Group(id [16]byte) (GroupInfo, bool) {
	r := sm.lookupGroup(id)
	if r == nil {
		return GroupInfo{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.st.Membership.Known() {
		return GroupInfo{}, false
	}
	m := r.st.Membership
	info := GroupInfo{
		ID: id, Name: r.st.Name, Version: m.Version,
		Members: slices.Clone(m.Members), Admins: slices.Clone(m.Admins),
		Names: make(map[[16]byte]string, len(r.st.Hints)),
	}
	for _, h := range r.st.Hints {
		info.Names[h.ID] = h.Name
	}
	return info, true
}

// GroupHead is the hash of the last membership change applied, which the next
// change names as its predecessor.
func (sm *SessionManager) GroupHead(id [16]byte) ([32]byte, bool) {
	r := sm.lookupGroup(id)
	if r == nil {
		return [32]byte{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.st.Membership.Head, r.st.Membership.Known()
}

// HasGroup reports whether this client holds a record for the group.
func (sm *SessionManager) HasGroup(id [16]byte) bool { return sm.lookupGroup(id) != nil }

// GroupVersion is the newest membership version verified for a group, or 0.
func (sm *SessionManager) GroupVersion(id [16]byte) uint32 {
	r := sm.lookupGroup(id)
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.st.Membership.Version
}

// LoadGroups restores saved groups.
func (sm *SessionManager) LoadGroups() ([]GroupInfo, error) {
	if sm.store == nil {
		return nil, nil
	}
	names, err := sm.store.List(groupRecordPrefix)
	if err != nil {
		return nil, err
	}
	var out []GroupInfo
	for _, name := range names {
		var st groupState
		if ok, err := sm.store.Load(name, &st); err != nil || !ok {
			if err != nil {
				log.Printf("[ERROR] could not restore %s: %v", name, err)
			}
			continue
		}
		rec := &groupRec{st: st, buffer: make(map[uint32]common.SignedChange)}
		now := sm.now()
		switch {
		case st.Left:
			rec.setKind(kindTombstone, now)
		case st.Membership.Known():
			rec.setKind(kindVerified, now)
		default:
			rec.setKind(kindStub, now)
		}
		prunePeerKeysLocked(rec, now)
		sm.mu.Lock()
		sm.groups[st.GroupID] = rec
		sm.mu.Unlock()
		if info, ok := sm.Group(st.GroupID); ok {
			out = append(out, info)
		}
	}
	sm.mu.Lock()
	sm.expireStubsLocked(sm.now())
	sm.evictOldestLocked(kindStub, maxStubRecords)
	sm.evictOldestLocked(kindTombstone, maxTombstones)
	sm.mu.Unlock()
	return out, nil
}

// --- membership ---

// GroupUpdate reports what applying a membership change did.
type GroupUpdate struct {
	GroupID [16]byte
	Name    string
	Version uint32
	Effects []common.ChangeEffect

	// Progressed is true if the verified membership moved forward.
	Progressed bool
	// Left is true if this client is no longer a member; the group has been dropped.
	Left bool
	// Behind is true if a change arrived ahead of the log. Ask the server for the gap.
	Behind bool
	// Installed lists owners whose held sender keys were admitted by this change.
	Installed [][16]byte
}

// pinFor returns the signing key this client knows for a user from outside the
// log, such as a prekey bundle it opened a session with.
func (sm *SessionManager) pinFor(id [16]byte) ([32]byte, bool) {
	if sm.SigningPin != nil {
		if k, ok := sm.SigningPin(id); ok {
			return k, true
		}
	}
	if sess, ok := sm.GetSession(common.HashIDs(sm.selfID, id)); ok {
		sess.mu.Lock()
		defer sess.mu.Unlock()
		if sess.st.PeerSigning != ([32]byte{}) && sess.st.PeerID == id {
			return sess.st.PeerSigning, true
		}
	}
	return [32]byte{}, false
}

// ApplyGroupChange verifies and applies one membership change from the server.
// Changes apply strictly in version order; one that arrives early is buffered
// and applied when its predecessors do, and one that fails verification is
// refused with the membership untouched.
func (sm *SessionManager) ApplyGroupChange(body *common.GroupChangeBody) (GroupUpdate, error) {
	sc := body.Change
	upd := GroupUpdate{GroupID: sc.Change.GroupID}

	rec, err := sm.groupFor(sc.Change.GroupID)
	if err != nil {
		return upd, err
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()

	if rec.kind.Load() != kindVerified {
		sm.mu.RLock()
		full := sm.countLocked(kindVerified) >= maxVerifiedGroups
		sm.mu.RUnlock()
		if full {
			return upd, fmt.Errorf("this client already belongs to %d groups", maxVerifiedGroups)
		}
	}
	prunePeerKeysLocked(rec, sm.now())

	if rec.st.Name == "" && body.Name != "" {
		rec.st.Name = body.Name
	}

	err = sm.applyOneLocked(rec, &sc, &upd)
	switch {
	case errors.Is(err, common.ErrChangeStale):
		err = nil
	case errors.Is(err, common.ErrChangeGap):
		if len(rec.buffer) < maxBufferedChanges {
			rec.buffer[sc.Change.Version] = sc
		}
		upd.Behind = true
		err = nil
	case err == nil:
		// Drain whatever was waiting on this one.
		for !upd.Left {
			next, ok := rec.buffer[rec.st.Membership.Version+1]
			if !ok {
				break
			}
			delete(rec.buffer, next.Change.Version)
			if e := sm.applyOneLocked(rec, &next, &upd); e != nil {
				log.Printf("[WARN] buffered change %d for group %x refused: %v", next.Change.Version, upd.GroupID[:4], e)
				break
			}
		}
	}

	if upd.Left {
		return upd, err
	}
	sm.noteHintsLocked(rec, body.Hints)
	if upd.Progressed {
		upd.Installed = sm.processHeldLocked(rec, sm.now())
		if perr := sm.persistGroup(&rec.st); perr != nil {
			log.Printf("[ERROR] could not save group %x: %v", upd.GroupID[:4], perr)
		}
	}
	upd.Name, upd.Version = rec.st.Name, rec.st.Membership.Version
	return upd, err
}

// applyOneLocked applies a single change and acts on its effects. Caller holds rec.mu.
func (sm *SessionManager) applyOneLocked(rec *groupRec, sc *common.SignedChange, upd *GroupUpdate) error {
	eff, err := rec.st.Membership.Apply(sc, sm.pinFor)
	if err != nil {
		return err
	}
	upd.Progressed = true
	upd.Effects = append(upd.Effects, eff)
	rec.kind.Store(kindVerified)
	// A group we had left is ours again once a log that includes us replays.
	rec.st.Left, rec.st.LeftAt = false, 0

	for _, k := range eff.Added {
		// A member who was removed and added back starts from nothing. Keys of
		// theirs that arrived ahead of this change are kept: they are for the
		// membership this change creates, and are admitted below.
		rec.st.Peers = slices.DeleteFunc(rec.st.Peers, func(p peerKeys) bool { return p.Owner == k.ID })
		rec.st.Own.DeliveredTo = slices.DeleteFunc(rec.st.Own.DeliveredTo, func(m [16]byte) bool { return m == k.ID })
	}
	for _, id := range eff.Removed {
		if id == sm.selfID {
			upd.Left = true
			continue
		}
		sm.forgetPeerLocked(rec, id)
		rec.st.Hints = slices.DeleteFunc(rec.st.Hints, func(h hintRec) bool { return h.ID == id })
		// Whoever was removed holds our current sender key and a chain only moves
		// forward, so the key has to be replaced before it is used again.
		rec.st.Own.MustRotate = true
	}
	if upd.Left {
		sm.tombstoneLocked(rec, sc.Change.Version)
	}
	return nil
}

// tombstoneLocked clears a group this client has left, keeping only enough to
// recognise it. Caller holds rec.mu.
func (sm *SessionManager) tombstoneLocked(rec *groupRec, version uint32) {
	id, name := rec.st.GroupID, rec.st.Name
	rec.st = groupState{GroupID: id, Name: name, Left: true, LeftAt: version}
	rec.st.Membership.GroupID = id
	rec.buffer = make(map[uint32]common.SignedChange)
	rec.setKind(kindTombstone, sm.now())
	if err := sm.persistGroup(&rec.st); err != nil {
		log.Printf("[ERROR] could not save group %x: %v", id[:4], err)
	}
	// The manager's lock is taken after the group's, as everywhere else.
	sm.mu.Lock()
	sm.evictOldestLocked(kindTombstone, maxTombstones)
	sm.mu.Unlock()
}

// forgetPeerLocked removes everything held about a member's sender key, and the
// fact that they were ever sent ours. Caller holds rec.mu.
func (sm *SessionManager) forgetPeerLocked(rec *groupRec, id [16]byte) {
	rec.st.Peers = slices.DeleteFunc(rec.st.Peers, func(p peerKeys) bool { return p.Owner == id })
	rec.st.Held = slices.DeleteFunc(rec.st.Held, func(h heldSKDM) bool { return h.Owner == id })
	rec.st.Own.DeliveredTo = slices.DeleteFunc(rec.st.Own.DeliveredTo, func(m [16]byte) bool { return m == id })
}

// noteHintsLocked keeps the directory data that matches the signed log and
// ignores the rest. Caller holds rec.mu.
func (sm *SessionManager) noteHintsLocked(rec *groupRec, hints []common.GroupHint) {
	for _, h := range hints {
		k, ok := rec.st.Membership.Key(h.ID)
		if !ok || !h.Bundle.Verify() || h.Bundle.IdentityKey != k.IdentityKey || h.Bundle.SigningKey != k.SigningKey {
			continue
		}
		rec.st.Hints = slices.DeleteFunc(rec.st.Hints, func(x hintRec) bool { return x.ID == h.ID })
		rec.st.Hints = append(rec.st.Hints, hintRec{ID: h.ID, Name: h.Name, Bundle: h.Bundle})
	}
}

// ApplyGroupHints records fresh directory data for a group's members.
func (sm *SessionManager) ApplyGroupHints(groupID [16]byte, hints []common.GroupHint) {
	rec := sm.lookupGroup(groupID)
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	sm.noteHintsLocked(rec, hints)
	if err := sm.persistGroup(&rec.st); err != nil {
		log.Printf("[ERROR] could not save group %x: %v", groupID[:4], err)
	}
}

// PeerKeysChanged is called when a member's 1:1 session was replaced, which
// means their device started over or their identity key changed. Whatever they
// held of ours and we held of theirs is gone: it is treated as a removal and an
// add, so every group we share with them rotates our key and redistributes it.
func (sm *SessionManager) PeerKeysChanged(peer [16]byte) []([16]byte) {
	sm.mu.RLock()
	recs := make([]*groupRec, 0, len(sm.groups))
	for _, r := range sm.groups {
		recs = append(recs, r)
	}
	sm.mu.RUnlock()

	var affected [][16]byte
	for _, rec := range recs {
		rec.mu.Lock()
		if rec.st.Membership.IsMember(peer) {
			sm.forgetPeerLocked(rec, peer)
			rec.st.Own.MustRotate = true
			affected = append(affected, rec.st.GroupID)
			if err := sm.persistGroup(&rec.st); err != nil {
				log.Printf("[ERROR] could not save group %x: %v", rec.st.GroupID[:4], err)
			}
		}
		rec.mu.Unlock()
	}
	return affected
}

// --- receiving sender keys ---

// ReceiveSenderKey handles a CtrlSenderKey packet that has already been opened
// by its 1:1 session. The owner is the session's peer, taken from the packet the
// server stamped and the conversation the ratchet authenticated, never from the
// payload.
func (sm *SessionManager) ReceiveSenderKey(pkt *common.Packet) (GroupUpdate, error) {
	owner := pkt.Header.SenderID
	var upd GroupUpdate
	if pkt.Header.ConversationID != common.HashIDs(sm.selfID, owner) || owner == sm.selfID {
		return upd, errors.New("sender key did not arrive over its owner's direct session")
	}
	d, err := common.DecodeSenderKeyDist(pkt.Body)
	if err != nil {
		return upd, err
	}
	upd.GroupID = d.GroupID
	rec, err := sm.groupFor(d.GroupID)
	if err != nil {
		return upd, err
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()

	now := sm.now()
	m := &rec.st.Membership

	if rec.st.Left && d.MembershipVersion <= rec.st.LeftAt {
		return upd, fmt.Errorf("%w: sender key for a group this client left", ErrNotInGroup)
	}

	// A key can outrun the membership change that admits its owner, and the 1:1
	// message it came in cannot be fetched again. Hold it until the log catches up.
	if !m.Known() || d.MembershipVersion > m.Version {
		rec.st.Held = append(rec.st.Held, heldSKDM{Owner: owner, Dist: d, At: now})
		if len(rec.st.Held) > maxHeldSKDM {
			rec.st.Held = rec.st.Held[len(rec.st.Held)-maxHeldSKDM:]
		}
		upd.Behind = true
		if err := sm.persistGroup(&rec.st); err != nil {
			log.Printf("[ERROR] could not save group %x: %v", d.GroupID[:4], err)
		}
		return upd, nil
	}

	installed, err := sm.installPeerKeyLocked(rec, owner, d, now)
	if err != nil {
		return upd, err
	}
	if installed {
		upd.Installed = [][16]byte{owner}
		if err := sm.persistGroup(&rec.st); err != nil {
			log.Printf("[ERROR] could not save group %x: %v", d.GroupID[:4], err)
		}
	}
	return upd, nil
}

// processHeldLocked admits held sender keys the membership now covers. It
// returns the owners whose keys were installed. Caller holds rec.mu.
func (sm *SessionManager) processHeldLocked(rec *groupRec, now time.Time) [][16]byte {
	var owners [][16]byte
	var keep []heldSKDM
	for _, h := range rec.st.Held {
		if now.Sub(h.At) > GroupPendingTTL {
			continue
		}
		if h.Dist.MembershipVersion > rec.st.Membership.Version {
			keep = append(keep, h)
			continue
		}
		if ok, err := sm.installPeerKeyLocked(rec, h.Owner, h.Dist, now); err != nil {
			log.Printf("[INFO] dropping held sender key from %x: %v", h.Owner[:4], err)
		} else if ok {
			owners = append(owners, h.Owner)
		}
	}
	rec.st.Held = keep
	return owners
}

// installPeerKeyLocked applies the receive rules for a sender key distribution.
// It reports whether a key was installed. Caller holds rec.mu.
func (sm *SessionManager) installPeerKeyLocked(rec *groupRec, owner [16]byte, d common.SenderKeyDist, now time.Time) (bool, error) {
	m := &rec.st.Membership
	if !m.IsMember(sm.selfID) || !m.IsMember(owner) {
		return false, fmt.Errorf("%w: %x", ErrNotInGroup, owner[:4])
	}
	if !common.IsValidKey(d.SignPub) || d.KeyID == 0 {
		return false, errors.New("sender key distribution carries no key")
	}

	var pk *peerKeys
	for i := range rec.st.Peers {
		if rec.st.Peers[i].Owner == owner {
			pk = &rec.st.Peers[i]
		}
	}
	fresh := &peerKey{
		KeyID: d.KeyID, Chain: d.ChainKey, N: d.N, SignPub: d.SignPub,
		Skipped: make(map[uint32]skippedKey),
	}
	if pk == nil {
		rec.st.Peers = append(rec.st.Peers, peerKeys{Owner: owner, Current: fresh})
		return true, nil
	}

	cur := pk.Current
	switch {
	case cur == nil:
		pk.Current = fresh
	case d.KeyID < cur.KeyID:
		return false, nil // stale
	case d.KeyID > cur.KeyID:
		cur.Expires = now.Add(OldKeyGrace)
		pk.Previous = cur
		pk.Current = fresh
	default:
		// The same key sent again. An earlier starting point is harmless; anything
		// else is ignored, and a different signing key under the same ID never wins.
		if d.SignPub != cur.SignPub || d.N >= cur.N {
			return false, nil
		}
		fresh.Skipped = cur.Skipped
		pk.Current = fresh
	}
	return true, nil
}

// --- reading group messages ---

// prunePeerKeysLocked drops expired previous keys and skipped message keys.
func prunePeerKeysLocked(rec *groupRec, now time.Time) {
	rec.st.Held = slices.DeleteFunc(rec.st.Held, func(h heldSKDM) bool { return now.Sub(h.At) > GroupPendingTTL })
	for i := range rec.st.Peers {
		p := &rec.st.Peers[i]
		if p.Previous != nil && !now.Before(p.Previous.Expires) {
			p.Previous = nil
		}
		for _, k := range []*peerKey{p.Current, p.Previous} {
			if k == nil {
				continue
			}
			for n, s := range k.Skipped {
				if now.Sub(s.At) > SkippedKeyTTL {
					delete(k.Skipped, n)
				}
			}
		}
	}
}

// DecryptGroupPacket opens a group message. The packet is changed only if the
// signature verifies and the ciphertext authenticates; any failure leaves every
// chain exactly where it was.
func (sm *SessionManager) DecryptGroupPacket(pkt *common.Packet) error {
	if pkt.Header.Flags&common.FlagEncrypted == 0 {
		return nil
	}
	w, err := common.DecodeGroupWire(pkt.Body)
	if err != nil {
		return err
	}
	h := w.Header
	if h.GroupID != pkt.Header.ConversationID || h.SenderID != pkt.Header.SenderID || h.MsgType != pkt.Header.MsgType {
		return errors.New("group message header disagrees with its packet")
	}
	headerBytes := pkt.Body[:common.GroupHeaderLen]

	rec := sm.lookupGroup(h.GroupID)
	if rec == nil {
		return fmt.Errorf("%w: %x", ErrNoGroupSession, h.GroupID[:4])
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.st.Left {
		return ErrNotInGroup
	}
	if !rec.st.Membership.Known() {
		return fmt.Errorf("%w: %x", ErrNoGroupSession, h.GroupID[:4])
	}

	// Verified membership decides who may speak. A message from a later version
	// than ours is held until we have caught up, since the sender may have joined
	// in a change we have not seen.
	m := &rec.st.Membership
	if h.MembershipVersion > m.Version {
		return fmt.Errorf("%w: message at %d, verified %d", ErrMembershipBehind, h.MembershipVersion, m.Version)
	}
	if !m.IsMember(sm.selfID) {
		return ErrNotInGroup
	}
	if !m.IsMember(h.SenderID) {
		return fmt.Errorf("%w: %x is not a member", ErrNotInGroup, h.SenderID[:4])
	}

	now := sm.now()
	prunePeerKeysLocked(rec, now)

	var pk *peerKeys
	for i := range rec.st.Peers {
		if rec.st.Peers[i].Owner == h.SenderID {
			pk = &rec.st.Peers[i]
		}
	}
	var key *peerKey
	var isCurrent bool
	switch {
	case pk != nil && pk.Current != nil && pk.Current.KeyID == h.KeyID:
		key, isCurrent = pk.Current, true
	case pk != nil && pk.Previous != nil && pk.Previous.KeyID == h.KeyID:
		key = pk.Previous
	case pk == nil || pk.Current == nil || h.KeyID > pk.Current.KeyID:
		// Their distribution may still be on its way.
		return fmt.Errorf("%w: %x key %d", ErrNoSenderKey, h.SenderID[:4], h.KeyID)
	default:
		return fmt.Errorf("message from %x under retired key %d", h.SenderID[:4], h.KeyID)
	}

	if !common.VerifyGroupMessage(key.SignPub, headerBytes, w.Ciphertext, w.Signature) {
		return fmt.Errorf("bad signature on group message from %x", h.SenderID[:4])
	}

	// Work on a copy and commit only once the ciphertext has authenticated.
	work := key.clone()
	var msgKey [32]byte
	switch {
	case h.N < work.N:
		s, ok := work.Skipped[h.N]
		if !ok {
			return fmt.Errorf("duplicate or old group message from %x: n=%d, expecting %d", h.SenderID[:4], h.N, work.N)
		}
		msgKey = s.Key
		delete(work.Skipped, h.N)
	default:
		gap := h.N - work.N
		if gap > MaxSkipGroup || len(work.Skipped)+int(gap) > maxGroupSkipped {
			return fmt.Errorf("group message from %x is too far ahead: n=%d, expecting %d", h.SenderID[:4], h.N, work.N)
		}
		for work.N < h.N {
			var mk [32]byte
			mk, work.Chain = common.RatchetStep(work.Chain)
			work.Skipped[work.N] = skippedKey{Key: mk, At: now}
			work.N++
		}
		msgKey, work.Chain = common.RatchetStep(work.Chain)
		work.N = h.N + 1
	}

	plain, err := common.Decrypt(msgKey, w.Ciphertext, headerBytes)
	msgKey = [32]byte{}
	if err != nil {
		return fmt.Errorf("group decryption failed for %x n=%d: %v", h.SenderID[:4], h.N, err)
	}

	if isCurrent {
		pk.Current = work
	} else {
		pk.Previous = work
	}
	if err := sm.persistGroup(&rec.st); err != nil {
		log.Printf("[ERROR] could not save group %x: %v", h.GroupID[:4], err)
	}

	pkt.Body = plain
	pkt.Header.BodyLen = uint32(len(plain))
	pkt.Header.Flags &^= common.FlagEncrypted
	return nil
}

// --- sending group messages ---

// needsRotation reports whether the next send must use a new sender key.
func (o *ownSenderKey) needsRotation(now time.Time) bool {
	return !o.Have || o.MustRotate || o.N >= GroupRotateEvery || now.Sub(o.CreatedAt) > GroupRotateMaxAge
}

// rotate replaces the sender key. The old chain key and signing seed are
// overwritten and not kept anywhere.
func (o *ownSenderKey) rotate(now time.Time) error {
	var chain [32]byte
	if _, err := rand.Read(chain[:]); err != nil {
		return fmt.Errorf("generating sender key: %w", err)
	}
	seed, pub, err := common.GenerateSigningKeys()
	if err != nil {
		return fmt.Errorf("generating sender signing key: %w", err)
	}
	o.KeyID++
	o.Chain, o.N = chain, 0
	o.SignSeed, o.SignPub = seed, pub
	o.CreatedAt = now
	o.DeliveredTo = nil
	o.MustRotate = false
	o.Have = true
	return nil
}

// sessionFor makes sure a 1:1 session exists with a member, opening one from the
// prekey bundle the log-checked directory data holds. ok is false if there is no
// session and no bundle to make one.
func (sm *SessionManager) sessionFor(rec *groupRec, peer common.MemberKey) (ok bool, err error) {
	convID := common.HashIDs(sm.selfID, peer.ID)
	if sess, have := sm.GetSession(convID); have {
		sess.mu.Lock()
		same := sess.st.PeerIK == peer.IdentityKey
		sess.mu.Unlock()
		if !same {
			return false, fmt.Errorf("the session with %x holds a different identity key than the group vouches for", peer.ID[:4])
		}
		return true, nil
	}
	for _, h := range rec.st.Hints {
		if h.ID == peer.ID {
			if _, err := sm.OpenDirectSession(convID, peer.ID, h.Name, h.Bundle, false); err != nil {
				return false, fmt.Errorf("opening a session with %x: %w", peer.ID[:4], err)
			}
			return true, nil
		}
	}
	return false, nil
}

// EncryptGroupPacket seals pkt for its group. It returns the sender key
// distributions that must be transmitted before pkt, each already sealed in its
// recipient's 1:1 session.
//
// Everything here is one choke point, for text and media alike: rotate if the
// key is due or a member has left, give the key to each member who lacks it,
// advance the chain, and save before anything is returned. A crash can lose a
// message but cannot make a chain position be used twice.
func (sm *SessionManager) EncryptGroupPacket(pkt *common.Packet) ([]common.Packet, error) {
	gid := pkt.Header.ConversationID
	rec := sm.lookupGroup(gid)
	if rec == nil {
		return nil, fmt.Errorf("%w: %x", ErrNoGroupSession, gid[:4])
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()

	m := &rec.st.Membership
	if rec.st.Left {
		return nil, ErrNotInGroup
	}
	if !m.Known() {
		return nil, fmt.Errorf("%w: %x", ErrNoGroupSession, gid[:4])
	}
	if !m.IsMember(sm.selfID) {
		return nil, ErrNotInGroup
	}

	now := sm.now()
	prunePeerKeysLocked(rec, now)
	own := rec.st.Own.clone()
	if own.needsRotation(now) {
		if err := own.rotate(now); err != nil {
			return nil, err
		}
	}

	// Find who still needs the key, and make sure we can reach each of them
	// before anything is consumed: a member who cannot be reached would otherwise
	// miss every message sent before they could be.
	var targets []common.MemberKey
	var missing [][16]byte
	for _, k := range m.Members {
		if k.ID == sm.selfID || slices.Contains(own.DeliveredTo, k.ID) {
			continue
		}
		ok, err := sm.sessionFor(rec, k)
		if err != nil {
			return nil, err
		}
		if !ok {
			missing = append(missing, k.ID)
			continue
		}
		targets = append(targets, k)
	}
	if len(missing) > 0 {
		return nil, &NeedSessionsError{Peers: missing}
	}

	// The key goes out at the position the chain has reached, so each recipient
	// can read this message and everything after it.
	dist := common.SenderKeyDist{
		GroupID: gid, KeyID: own.KeyID, ChainKey: own.Chain, N: own.N,
		SignPub: own.SignPub, MembershipVersion: m.Version,
	}
	payload := dist.Encode()
	pre := make([]common.Packet, 0, len(targets))
	for _, k := range targets {
		sk := common.Packet{
			Header: common.Header{
				MessageID: newMessageID(), ConversationID: common.HashIDs(sm.selfID, k.ID),
				SenderID: sm.selfID, MsgType: common.CtrlSenderKey, BodyLen: uint32(len(payload)),
			},
			Body: append([]byte(nil), payload...),
		}
		if err := sm.EncryptPacket(&sk); err != nil {
			return nil, fmt.Errorf("sealing sender key for %x: %w", k.ID[:4], err)
		}
		pre = append(pre, sk)
		own.DeliveredTo = append(own.DeliveredTo, k.ID)
	}

	msgKey, next := common.RatchetStep(own.Chain)
	header := common.GroupHeader{
		Version: common.GroupMsgVersion, GroupID: gid, SenderID: sm.selfID,
		KeyID: own.KeyID, N: own.N, MembershipVersion: m.Version, MsgType: pkt.Header.MsgType,
	}
	hb := header.Encode()
	ct, err := common.Encrypt(msgKey, pkt.Body, hb)
	msgKey = [32]byte{}
	if err != nil {
		return nil, err
	}
	wire := common.GroupWire{Header: header, Ciphertext: ct, Signature: common.SignGroupMessage(own.SignSeed, hb, ct)}
	own.Chain = next
	own.N++

	// Saved before the packet leaves. If this fails nothing is sent and the
	// in-memory chain does not move, so the position is not consumed.
	saved := rec.st
	saved.Own = own
	if err := sm.persistGroup(&saved); err != nil {
		return nil, fmt.Errorf("could not save group state, message not sent: %w", err)
	}
	rec.st.Own = own

	pkt.Body = wire.Encode()
	pkt.Header.BodyLen = uint32(len(pkt.Body))
	pkt.Header.Flags |= common.FlagEncrypted
	return pre, nil
}

func newMessageID() (id [16]byte) {
	rand.Read(id[:])
	return
}
