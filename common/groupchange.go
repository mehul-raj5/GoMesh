package common

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// --- Signed membership changes ---
//
// The server orders membership changes and fans messages out to whoever it
// believes is a member, so on its own it could quietly add itself. Every change
// is therefore signed by the member who made it, chained to the one before by
// hash, and checked by every client. The server only assigns the order.

// GroupAction is what a membership change does.
type GroupAction uint8

const (
	ActionCreate  GroupAction = 1
	ActionAdd     GroupAction = 2
	ActionRemove  GroupAction = 3
	ActionLeave   GroupAction = 4
	ActionPromote GroupAction = 5
	ActionDemote  GroupAction = 6
)

func (a GroupAction) String() string {
	switch a {
	case ActionCreate:
		return "create"
	case ActionAdd:
		return "add"
	case ActionRemove:
		return "remove"
	case ActionLeave:
		return "leave"
	case ActionPromote:
		return "promote"
	case ActionDemote:
		return "demote"
	}
	return fmt.Sprintf("action(%d)", uint8(a))
}

// MaxGroupMembers bounds a group. Removal costs about one direct message per
// pair of members, so very large groups are outside what this scheme is for.
const MaxGroupMembers = 256

// MemberKey names a member together with the two public keys that identify them.
// A change that introduces a member carries both, signed by the admin who vouches
// for them, so the chain of changes is self-contained: the server cannot swap a
// later member's keys without breaking a signature.
type MemberKey struct {
	ID          [IDSize]byte
	IdentityKey [32]byte // X25519, anchors the direct sessions sender keys travel over
	SigningKey  [32]byte // Ed25519, verifies the changes this member signs
}

const memberKeyLen = IDSize + 32 + 32

// GroupChange is one entry of a group's membership log.
type GroupChange struct {
	GroupID   [IDSize]byte
	Version   uint32   // previous version + 1; the first change is version 1
	PrevHash  [32]byte // hash of the previous signed change, zero for the first
	Action    GroupAction
	Actor     [IDSize]byte
	Timestamp int64 // unix seconds; informational, covered by the signature
	// Targets are who the change is about. For a create it is every initial
	// member including the creator.
	Targets []MemberKey
}

const (
	groupChangeVersion = 1
	groupChangeFixed   = 1 + IDSize + 4 + 32 + 1 + IDSize + 8 + 2
)

func (c *GroupChange) Encode() []byte {
	buf := make([]byte, 0, groupChangeFixed+len(c.Targets)*memberKeyLen)
	buf = append(buf, groupChangeVersion)
	buf = append(buf, c.GroupID[:]...)
	buf = binary.BigEndian.AppendUint32(buf, c.Version)
	buf = append(buf, c.PrevHash[:]...)
	buf = append(buf, byte(c.Action))
	buf = append(buf, c.Actor[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(c.Timestamp))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.Targets)))
	for _, t := range c.Targets {
		buf = append(buf, t.ID[:]...)
		buf = append(buf, t.IdentityKey[:]...)
		buf = append(buf, t.SigningKey[:]...)
	}
	return buf
}

// DecodeGroupChange reads a change from the front of data and returns how many
// bytes it occupied.
func DecodeGroupChange(data []byte) (GroupChange, int, error) {
	var c GroupChange
	if len(data) < groupChangeFixed {
		return c, 0, fmt.Errorf("group change too short: %d", len(data))
	}
	if data[0] != groupChangeVersion {
		return c, 0, fmt.Errorf("unsupported group change version %d", data[0])
	}
	o := 1
	o += copy(c.GroupID[:], data[o:])
	c.Version = binary.BigEndian.Uint32(data[o:])
	o += 4
	o += copy(c.PrevHash[:], data[o:])
	c.Action = GroupAction(data[o])
	o++
	o += copy(c.Actor[:], data[o:])
	c.Timestamp = int64(binary.BigEndian.Uint64(data[o:]))
	o += 8
	count := int(binary.BigEndian.Uint16(data[o:]))
	o += 2
	if count > MaxGroupMembers {
		return c, 0, fmt.Errorf("group change names %d targets, limit %d", count, MaxGroupMembers)
	}
	if len(data) < o+count*memberKeyLen {
		return c, 0, fmt.Errorf("group change truncated: %d targets need %d bytes", count, count*memberKeyLen)
	}
	c.Targets = make([]MemberKey, count)
	for i := range c.Targets {
		o += copy(c.Targets[i].ID[:], data[o:])
		o += copy(c.Targets[i].IdentityKey[:], data[o:])
		o += copy(c.Targets[i].SigningKey[:], data[o:])
	}
	return c, o, nil
}

// SignedChange is a change and the actor's signature over it.
type SignedChange struct {
	Change GroupChange
	Sig    [SignatureSize]byte
}

func changeMessage(c *GroupChange) []byte {
	return append([]byte("GoMesh-GroupChange-v1"), c.Encode()...)
}

// SignChange signs a change with the actor's Ed25519 identity signing seed.
func SignChange(seed [KeySize]byte, c GroupChange) SignedChange {
	sc := SignedChange{Change: c}
	priv := ed25519.NewKeyFromSeed(seed[:])
	copy(sc.Sig[:], ed25519.Sign(priv, changeMessage(&sc.Change)))
	return sc
}

// Verify reports whether sig is a valid signature by signingPub over the change.
func (sc *SignedChange) Verify(signingPub [KeySize]byte) bool {
	return ed25519.Verify(signingPub[:], changeMessage(&sc.Change), sc.Sig[:])
}

func (sc *SignedChange) Encode() []byte {
	return append(sc.Change.Encode(), sc.Sig[:]...)
}

// DecodeSignedChange reads a signed change from the front of data.
func DecodeSignedChange(data []byte) (SignedChange, int, error) {
	var sc SignedChange
	c, n, err := DecodeGroupChange(data)
	if err != nil {
		return sc, 0, err
	}
	if len(data) < n+SignatureSize {
		return sc, 0, errors.New("signed group change missing its signature")
	}
	sc.Change = c
	copy(sc.Sig[:], data[n:])
	return sc, n + SignatureSize, nil
}

// Hash is what the next change names as its PrevHash. It covers the signature, so
// the chain commits to exactly the records that were accepted.
func (sc *SignedChange) Hash() [32]byte {
	h := sha256.New()
	h.Write([]byte("GoMesh-GroupChangeHash-v1"))
	h.Write(sc.Encode())
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// --- Membership state machine ---

// Reasons a change is not applied. ErrChangeStale and ErrChangeGap are not
// verdicts on the change itself: the first means it was already applied, the
// second that an earlier one has not arrived yet.
var (
	ErrChangeStale = errors.New("membership change already applied")
	ErrChangeGap   = errors.New("membership change is ahead of the log")
	ErrBadChange   = errors.New("invalid membership change")
)

// KeyPin returns the signing key a client independently knows for a user, such
// as one it saw in a prekey bundle. A change that contradicts a pinned key is
// refused.
type KeyPin func(id [IDSize]byte) (signing [KeySize]byte, known bool)

// Membership is the group as the signed log defines it. The zero value is a
// group not yet heard of; the first accepted change must be a create.
type Membership struct {
	GroupID [IDSize]byte
	Version uint32
	Head    [32]byte // hash of the last applied change
	Members []MemberKey
	Admins  [][IDSize]byte
}

// Known reports whether any change has been applied.
func (m *Membership) Known() bool { return m.Version > 0 }

func (m *Membership) Key(id [IDSize]byte) (MemberKey, bool) {
	for _, k := range m.Members {
		if k.ID == id {
			return k, true
		}
	}
	return MemberKey{}, false
}

func (m *Membership) IsMember(id [IDSize]byte) bool {
	_, ok := m.Key(id)
	return ok
}

func (m *Membership) IsAdmin(id [IDSize]byte) bool {
	for _, a := range m.Admins {
		if a == id {
			return true
		}
	}
	return false
}

// MemberIDs lists the members in the order they joined.
func (m *Membership) MemberIDs() [][IDSize]byte {
	ids := make([][IDSize]byte, len(m.Members))
	for i, k := range m.Members {
		ids[i] = k.ID
	}
	return ids
}

// Clone returns a copy that shares no memory with m.
func (m *Membership) Clone() Membership {
	c := *m
	c.Members = append([]MemberKey(nil), m.Members...)
	c.Admins = append([][IDSize]byte(nil), m.Admins...)
	return c
}

// ChangeEffect is what an applied change did, for the caller to act on.
type ChangeEffect struct {
	Action   GroupAction
	Actor    [IDSize]byte
	Added    []MemberKey
	Removed  [][IDSize]byte // removed or left
	Promoted [][IDSize]byte
	Demoted  [][IDSize]byte
}

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadChange, fmt.Sprintf(format, args...))
}

func validMemberKey(k MemberKey) bool {
	return k.ID != ([IDSize]byte{}) && IsValidKey(k.IdentityKey) && IsValidKey(k.SigningKey)
}

// checkTargets confirms targets are unique and fully keyed.
func checkTargets(targets []MemberKey) error {
	if len(targets) == 0 {
		return bad("no targets")
	}
	seen := make(map[[IDSize]byte]struct{}, len(targets))
	for _, t := range targets {
		if !validMemberKey(t) {
			return bad("target %x has a missing key", t.ID[:4])
		}
		if _, dup := seen[t.ID]; dup {
			return bad("target %x listed twice", t.ID[:4])
		}
		seen[t.ID] = struct{}{}
	}
	return nil
}

// Check decides whether sc is the next valid change without applying it.
func (m *Membership) Check(sc *SignedChange, pin KeyPin) error {
	c := &sc.Change

	if !m.Known() {
		if c.Action != ActionCreate {
			return fmt.Errorf("%w: first change is %v, not a create", ErrChangeGap, c.Action)
		}
		if c.Version != 1 {
			return fmt.Errorf("%w: create at version %d", ErrChangeGap, c.Version)
		}
		if c.PrevHash != ([32]byte{}) {
			return bad("create names a previous change")
		}
	} else {
		if c.GroupID != m.GroupID {
			return bad("change is for another group")
		}
		if c.Version <= m.Version {
			return ErrChangeStale
		}
		if c.Version > m.Version+1 {
			return fmt.Errorf("%w: have %d, got %d", ErrChangeGap, m.Version, c.Version)
		}
		if c.PrevHash != m.Head {
			return bad("change does not follow the log head")
		}
		if c.Action == ActionCreate {
			return bad("group already exists")
		}
	}

	var actorKey [KeySize]byte
	if c.Action == ActionCreate {
		if err := checkTargets(c.Targets); err != nil {
			return err
		}
		if len(c.Targets) > MaxGroupMembers {
			return bad("%d members, limit %d", len(c.Targets), MaxGroupMembers)
		}
		found := false
		for _, t := range c.Targets {
			if t.ID == c.Actor {
				found, actorKey = true, t.SigningKey
			}
		}
		if !found {
			return bad("creator is not among the members")
		}
	} else {
		k, ok := m.Key(c.Actor)
		if !ok {
			return bad("actor %x is not a member", c.Actor[:4])
		}
		actorKey = k.SigningKey
	}

	if pin != nil {
		if pinned, ok := pin(c.Actor); ok && pinned != actorKey {
			return bad("actor %x signing key contradicts the directory", c.Actor[:4])
		}
		if c.Action == ActionCreate || c.Action == ActionAdd {
			for _, t := range c.Targets {
				if pinned, ok := pin(t.ID); ok && pinned != t.SigningKey {
					return bad("target %x signing key contradicts the directory", t.ID[:4])
				}
			}
		}
	}
	if !sc.Verify(actorKey) {
		return bad("signature does not verify")
	}

	return m.authorize(c)
}

// authorize applies the per-action rules to an authenticated change.
func (m *Membership) authorize(c *GroupChange) error {
	switch c.Action {
	case ActionCreate:
		return nil

	case ActionAdd:
		if !m.IsAdmin(c.Actor) {
			return bad("%x is not an admin", c.Actor[:4])
		}
		if err := checkTargets(c.Targets); err != nil {
			return err
		}
		for _, t := range c.Targets {
			if m.IsMember(t.ID) {
				return bad("%x is already a member", t.ID[:4])
			}
		}
		if len(m.Members)+len(c.Targets) > MaxGroupMembers {
			return bad("group would exceed %d members", MaxGroupMembers)
		}

	case ActionRemove:
		if !m.IsAdmin(c.Actor) {
			return bad("%x is not an admin", c.Actor[:4])
		}
		if len(c.Targets) == 0 {
			return bad("no targets")
		}
		for _, t := range c.Targets {
			if t.ID == c.Actor {
				return bad("an admin leaves with a leave, not a remove")
			}
			if !m.IsMember(t.ID) {
				return bad("%x is not a member", t.ID[:4])
			}
		}

	case ActionLeave:
		if len(c.Targets) != 1 || c.Targets[0].ID != c.Actor {
			return bad("a leave names only the one leaving")
		}
		// Admin-less groups cannot be managed. The leaving client promotes a
		// successor first, so this only refuses a leave that skipped that step.
		if m.IsAdmin(c.Actor) && len(m.Admins) == 1 && len(m.Members) > 1 {
			return bad("the last admin must promote someone before leaving")
		}

	case ActionPromote:
		if !m.IsAdmin(c.Actor) {
			return bad("%x is not an admin", c.Actor[:4])
		}
		if len(c.Targets) == 0 {
			return bad("no targets")
		}
		for _, t := range c.Targets {
			if !m.IsMember(t.ID) {
				return bad("%x is not a member", t.ID[:4])
			}
			if m.IsAdmin(t.ID) {
				return bad("%x is already an admin", t.ID[:4])
			}
		}

	case ActionDemote:
		if !m.IsAdmin(c.Actor) {
			return bad("%x is not an admin", c.Actor[:4])
		}
		if len(c.Targets) == 0 {
			return bad("no targets")
		}
		demoted := 0
		for _, t := range c.Targets {
			if !m.IsAdmin(t.ID) {
				return bad("%x is not an admin", t.ID[:4])
			}
			demoted++
		}
		if len(m.Admins)-demoted < 1 {
			return bad("that would leave the group with no admin")
		}

	default:
		return bad("unknown action %d", uint8(c.Action))
	}
	return nil
}

// Apply checks sc and, if it is the next valid change, applies it.
func (m *Membership) Apply(sc *SignedChange, pin KeyPin) (ChangeEffect, error) {
	var eff ChangeEffect
	if err := m.Check(sc, pin); err != nil {
		return eff, err
	}
	c := &sc.Change
	eff.Action, eff.Actor = c.Action, c.Actor

	switch c.Action {
	case ActionCreate:
		m.GroupID = c.GroupID
		m.Members = append([]MemberKey(nil), c.Targets...)
		m.Admins = [][IDSize]byte{c.Actor}
		eff.Added = append(eff.Added, c.Targets...)

	case ActionAdd:
		m.Members = append(m.Members, c.Targets...)
		eff.Added = append(eff.Added, c.Targets...)

	case ActionRemove, ActionLeave:
		for _, t := range c.Targets {
			m.removeMember(t.ID)
			eff.Removed = append(eff.Removed, t.ID)
		}

	case ActionPromote:
		for _, t := range c.Targets {
			m.Admins = append(m.Admins, t.ID)
			eff.Promoted = append(eff.Promoted, t.ID)
		}

	case ActionDemote:
		for _, t := range c.Targets {
			m.removeAdmin(t.ID)
			eff.Demoted = append(eff.Demoted, t.ID)
		}
	}

	m.Version = c.Version
	m.Head = sc.Hash()
	return eff, nil
}

func (m *Membership) removeMember(id [IDSize]byte) {
	for i, k := range m.Members {
		if k.ID == id {
			m.Members = append(m.Members[:i], m.Members[i+1:]...)
			break
		}
	}
	m.removeAdmin(id)
}

func (m *Membership) removeAdmin(id [IDSize]byte) {
	for i, a := range m.Admins {
		if a == id {
			m.Admins = append(m.Admins[:i], m.Admins[i+1:]...)
			return
		}
	}
}

// --- Roster hints ---

// GroupHint is directory data the server sends alongside membership changes: a
// member's name and current prekey bundle, so direct sessions to them can be
// opened without a further round trip. It is not signed. A receiver checks the
// bundle against the keys the signed log vouches for and ignores one that
// disagrees.
type GroupHint struct {
	ID     [IDSize]byte
	Name   string
	Bundle PreKeyBundle
}

func EncodeHints(hints []GroupHint) []byte {
	buf := binary.BigEndian.AppendUint16(nil, uint16(len(hints)))
	for _, h := range hints {
		buf = append(buf, h.ID[:]...)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(h.Name)))
		buf = append(buf, h.Name...)
		buf = append(buf, h.Bundle.Encode()...)
	}
	return buf
}

// DecodeHints reads a hint list from the front of data and returns the bytes used.
func DecodeHints(data []byte) ([]GroupHint, int, error) {
	if len(data) < 2 {
		return nil, 0, errors.New("hint list truncated before its count")
	}
	count := int(binary.BigEndian.Uint16(data))
	o := 2
	if count > MaxGroupMembers {
		return nil, 0, fmt.Errorf("hint list claims %d entries, limit %d", count, MaxGroupMembers)
	}
	hints := make([]GroupHint, 0, count)
	for i := 0; i < count; i++ {
		if len(data) < o+IDSize+2 {
			return nil, 0, fmt.Errorf("hint %d truncated", i)
		}
		var h GroupHint
		o += copy(h.ID[:], data[o:])
		n := int(binary.BigEndian.Uint16(data[o:]))
		o += 2
		if len(data) < o+n+PreKeyBundleSize {
			return nil, 0, fmt.Errorf("hint %d truncated", i)
		}
		h.Name = string(data[o : o+n])
		o += n
		b, err := DecodePreKeyBundle(data[o:])
		if err != nil {
			return nil, 0, err
		}
		h.Bundle = b
		o += PreKeyBundleSize
		hints = append(hints, h)
	}
	return hints, o, nil
}

// --- Wire bodies for the membership packets ---

// GroupChangeBody is the body of a CtrlGroupChange: the group's name, the signed
// change, and hints about the members it introduced.
type GroupChangeBody struct {
	Name   string
	Change SignedChange
	Hints  []GroupHint
}

func (b *GroupChangeBody) Encode() []byte {
	buf := binary.BigEndian.AppendUint16(nil, uint16(len(b.Name)))
	buf = append(buf, b.Name...)
	buf = append(buf, b.Change.Encode()...)
	return append(buf, EncodeHints(b.Hints)...)
}

func DecodeGroupChangeBody(data []byte) (GroupChangeBody, error) {
	var b GroupChangeBody
	name, o, err := getString(data, 0)
	if err != nil {
		return b, fmt.Errorf("group change name: %w", err)
	}
	b.Name = name
	sc, n, err := DecodeSignedChange(data[o:])
	if err != nil {
		return b, err
	}
	b.Change = sc
	o += n
	hints, _, err := DecodeHints(data[o:])
	if err != nil {
		return b, err
	}
	b.Hints = hints
	return b, nil
}

// GroupChangeReject tells a submitter its change was not accepted and where the
// log stands, so it can catch up and decide whether to try again.
type GroupChangeReject struct {
	GroupID     [IDSize]byte
	ChangeHash  [32]byte // hash of the rejected change
	HeadVersion uint32
	Reason      string
}

func (r *GroupChangeReject) Encode() []byte {
	buf := append([]byte(nil), r.GroupID[:]...)
	buf = append(buf, r.ChangeHash[:]...)
	buf = binary.BigEndian.AppendUint32(buf, r.HeadVersion)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Reason)))
	return append(buf, r.Reason...)
}

func DecodeGroupChangeReject(data []byte) (GroupChangeReject, error) {
	var r GroupChangeReject
	if len(data) < IDSize+32+4+2 {
		return r, errors.New("group change reject too short")
	}
	o := copy(r.GroupID[:], data)
	o += copy(r.ChangeHash[:], data[o:])
	r.HeadVersion = binary.BigEndian.Uint32(data[o:])
	o += 4
	reason, _, err := getString(data, o)
	if err != nil {
		return r, err
	}
	r.Reason = reason
	return r, nil
}

// GroupLogRequest asks for every change after FromVersion, plus fresh hints.
type GroupLogRequest struct {
	GroupID     [IDSize]byte
	FromVersion uint32
}

func (r *GroupLogRequest) Encode() []byte {
	buf := append([]byte(nil), r.GroupID[:]...)
	return binary.BigEndian.AppendUint32(buf, r.FromVersion)
}

func DecodeGroupLogRequest(data []byte) (GroupLogRequest, error) {
	var r GroupLogRequest
	if len(data) < IDSize+4 {
		return r, errors.New("group log request too short")
	}
	copy(r.GroupID[:], data)
	r.FromVersion = binary.BigEndian.Uint32(data[IDSize:])
	return r, nil
}

// GroupHintsBody is the body of a CtrlGroupHints: current directory data for
// every member of a group.
func EncodeGroupHints(groupID [IDSize]byte, hints []GroupHint) []byte {
	return append(append([]byte(nil), groupID[:]...), EncodeHints(hints)...)
}

func DecodeGroupHints(data []byte) ([IDSize]byte, []GroupHint, error) {
	var id [IDSize]byte
	if len(data) < IDSize {
		return id, nil, errors.New("group hints too short")
	}
	copy(id[:], data)
	hints, _, err := DecodeHints(data[IDSize:])
	return id, hints, err
}

// --- User lookup ---

// UserLookup is the answer to a CtrlUserLookupRq: who a username is and the
// bundle to open a session with them. An empty body from the server means the
// name is unknown.
type UserLookup struct {
	ID     [IDSize]byte
	Name   string
	Bundle PreKeyBundle
}

func (u *UserLookup) Encode() []byte {
	buf := append([]byte(nil), u.ID[:]...)
	buf = append(buf, u.Bundle.Encode()...)
	return append(buf, u.Name...)
}

func DecodeUserLookup(data []byte) (UserLookup, error) {
	var u UserLookup
	if len(data) < IDSize+PreKeyBundleSize {
		return u, errors.New("user lookup too short")
	}
	copy(u.ID[:], data)
	b, err := DecodePreKeyBundle(data[IDSize:])
	if err != nil {
		return u, err
	}
	u.Bundle = b
	u.Name = string(data[IDSize+PreKeyBundleSize:])
	return u, nil
}
