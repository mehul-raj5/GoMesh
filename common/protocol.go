package common

import (
	"encoding/binary"
	"fmt"
	"io"
)

const IDSize = 16

const HeaderSize = 16 + 16 + 16 + 1 + 2 + 4

const (
	MsgText      uint8 = 0x01
	MsgMediaMeta uint8 = 0x04 // E2E-encrypted media metadata envelope (Supabase direct-upload)
	// MsgReadReceipt tells the sender of messages that the sender of this packet
	// has read them. Its body, the IDs of the messages read, is encrypted over
	// the 1:1 channel the two share, so the server relays it without knowing
	// which messages it is about. It is never sent to a group.
	MsgReadReceipt uint8 = 0x05

	CtrlLogin      uint8 = 0x10
	CtrlLoginAck   uint8 = 0x11
	CtrlDirectInit uint8 = 0x15
	CtrlDirectAck  uint8 = 0x16

	// Group membership is a signed log the server orders and every client
	// verifies. A client submits a signed change (CtrlGroupCreate for the first,
	// CtrlGroupChange for the rest); the server answers the submitter with a
	// CtrlGroupChangeReject if it cannot take it and otherwise broadcasts the
	// accepted change to the members as a CtrlGroupChange.
	CtrlGroupCreate       uint8 = 0x12
	CtrlGroupChange       uint8 = 0x13
	CtrlGroupChangeReject uint8 = 0x14
	// Login is a three-step exchange: CtrlLogin names the account, the server
	// answers with a random challenge, and the client proves it holds the
	// account's signing key by signing it. Without the proof a public bundle,
	// which the server hands to anyone, would be enough to log in as its owner.
	CtrlLoginChallenge uint8 = 0x17 // server -> client: body is a LoginNonceSize nonce
	CtrlLoginProof     uint8 = 0x18 // client -> server: body is a signature over the nonce
	// CtrlGroupLogRq asks for the changes after a version; the server answers
	// with those as CtrlGroupChange packets and then a CtrlGroupHints.
	CtrlGroupLogRq uint8 = 0x1B
	CtrlGroupHints uint8 = 0x1C
	// Sender-key group messaging: every member generates their own sending
	// key and hands it to each other member over the 1-1 channel they share,
	// so a CtrlSenderKey packet is always carried inside an encrypted unicast.
	CtrlSenderKey uint8 = 0x1D

	// Conversation lookup. A client that receives traffic for a conversation it
	// has never heard of asks the server who is in it; the server answers only
	// if the asker is a member.
	CtrlConvInfoRq  uint8 = 0x1E // client -> server: body is convID
	CtrlConvInfoAck uint8 = 0x1F // server -> client: body is an encoded ConvInfo

	// Media direct-upload signed-URL exchange (client <-> chat server).
	CtrlUploadRq    uint8 = 0x20 // client -> server: request a signed upload URL
	CtrlUploadAck   uint8 = 0x21 // server -> client: signed upload URL + object path
	CtrlDownloadRq  uint8 = 0x22 // client -> server: request a signed download URL
	CtrlDownloadAck uint8 = 0x23 // server -> client: signed download URL

	// Username lookup: who a name is and the bundle to open a session with them.
	// Needed to sign a membership change that names someone by ID and keys.
	CtrlUserLookupRq  uint8 = 0x24 // client -> server: body is the username
	CtrlUserLookupAck uint8 = 0x25 // server -> client: an encoded UserLookup, or empty

	// Accounts. CtrlRegister and CtrlLogin carry Credentials, CtrlResume a
	// session token; each is then followed by the signed challenge, and answered
	// with a CtrlLoginAck carrying the user ID and the session token. CtrlLogout
	// ends the session its connection belongs to.
	CtrlRegister uint8 = 0x26
	CtrlResume   uint8 = 0x27
	CtrlLogout   uint8 = 0x28

	// Moving an account to a new device. CtrlKeyChange tells everyone who shares
	// a conversation with the account that it now has new keys; its body is an
	// encoded UserLookup. CtrlMyGroups lists, at every login, the groups the
	// account belongs to, so a new device can find and rekey them. A client that
	// cannot read a peer sends CtrlSessionReset over their 1:1 conversation, with
	// an empty body, asking the peer to start a new session.
	CtrlKeyChange    uint8 = 0x29
	CtrlMyGroups     uint8 = 0x2A
	CtrlSessionReset uint8 = 0x2B

	// Delivery. A packet the server has written may still be lost: a phone can
	// be suspended, or change networks, with it unread. So the client says how
	// many packets it has handled on this connection since signing in, a count
	// that only grows, and the server keeps each written packet until a count
	// covers it. What is not covered when the connection ends is delivered again
	// on the next one; clients ignore what they have already read.
	CtrlDelivered uint8 = 0x2C // client -> server: body is an 8-byte count

	// Receipts. The server tells a message's sender that it took the message
	// (CtrlMsgAccepted) and, for each recipient, that the recipient's device has
	// handled it (CtrlMsgDelivered). Both name the message in MessageID and its
	// conversation in ConversationID. A sender that has been away asks for what
	// it missed with CtrlReceiptsRq, whose answer is those packets again.
	CtrlMsgAccepted  uint8 = 0x2D // server -> sender: body is the time, in unix milliseconds
	CtrlMsgDelivered uint8 = 0x2E // server -> sender: body is the recipient's ID, then the time
	CtrlReceiptsRq   uint8 = 0x2F // client -> server: body is a time, in unix milliseconds

	CtrlError uint8 = 0xFF

	FlagEncrypted uint16 = 1 << 0
)

// IsReply reports whether a server packet answers a request on the connection
// that made it. A reply that a connection did not acknowledge is not delivered
// again on the next one: whoever was waiting for it has given up, and the
// request can be made again.
func IsReply(msgType uint8) bool {
	switch msgType {
	case CtrlDirectAck, CtrlConvInfoAck, CtrlUploadAck, CtrlDownloadAck, CtrlUserLookupAck,
		CtrlGroupChangeReject, CtrlGroupHints, CtrlMyGroups, CtrlMsgAccepted, CtrlError:
		return true
	}
	return false
}

// DeliveredPacket is a client's acknowledgement that it has handled n packets
// on this connection.
func DeliveredPacket(n uint64) Packet {
	body := binary.BigEndian.AppendUint64(nil, n)
	return Packet{Header: Header{MsgType: CtrlDelivered, BodyLen: uint32(len(body))}, Body: body}
}

// DecodeDelivered reads the count from a CtrlDelivered body.
func DecodeDelivered(body []byte) (uint64, error) {
	if len(body) != 8 {
		return 0, fmt.Errorf("delivered: %d-byte body", len(body))
	}
	return binary.BigEndian.Uint64(body), nil
}

type Header struct {
	MessageID      [IDSize]byte
	ConversationID [IDSize]byte
	SenderID       [IDSize]byte
	MsgType        uint8
	Flags          uint16
	BodyLen        uint32
}

type Packet struct {
	Header Header
	Body   []byte
}

func (h *Header) Bytes() []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[0:16], h.MessageID[:])
	copy(buf[16:32], h.ConversationID[:])
	copy(buf[32:48], h.SenderID[:])
	buf[48] = h.MsgType
	binary.BigEndian.PutUint16(buf[49:], h.Flags)
	binary.BigEndian.PutUint32(buf[51:], h.BodyLen)
	return buf
}

func (p *Packet) Encode(w io.Writer) error {
	buf := make([]byte, HeaderSize)
	copy(buf[0:16], p.Header.MessageID[:])
	copy(buf[16:32], p.Header.ConversationID[:])
	copy(buf[32:48], p.Header.SenderID[:])
	buf[48] = p.Header.MsgType
	binary.BigEndian.PutUint16(buf[49:], p.Header.Flags)
	binary.BigEndian.PutUint32(buf[51:], p.Header.BodyLen)

	if _, err := w.Write(buf); err != nil {
		return err
	}
	if p.Header.BodyLen > 0 {
		if _, err := w.Write(p.Body); err != nil {
			return err
		}
	}
	return nil
}

// MaxBody is the largest body Decode accepts.
const MaxBody = 100 * 1024 * 1024

func Decode(r io.Reader) (Packet, error) {
	return DecodeMax(r, MaxBody)
}

// DecodeMax reads one packet whose body may be at most max bytes. The server
// uses a small max for everything it reads before a login completes, so an
// unauthenticated peer cannot make it allocate a large body.
func DecodeMax(r io.Reader, max uint32) (Packet, error) {
	var p Packet
	buf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, buf); err != nil {
		return p, err
	}

	copy(p.Header.MessageID[:], buf[0:16])
	copy(p.Header.ConversationID[:], buf[16:32])
	copy(p.Header.SenderID[:], buf[32:48])
	p.Header.MsgType = buf[48]
	p.Header.Flags = binary.BigEndian.Uint16(buf[49:])
	p.Header.BodyLen = binary.BigEndian.Uint32(buf[51:])

	if p.Header.BodyLen > max {
		return p, fmt.Errorf("body too large: %d", p.Header.BodyLen)
	}

	if p.Header.BodyLen > 0 {
		p.Body = make([]byte, p.Header.BodyLen)
		if _, err := io.ReadFull(r, p.Body); err != nil {
			return p, err
		}
	}
	return p, nil
}

// --- Media direct-upload payloads ---

// MediaMetadata is the lightweight envelope sent in a MsgMediaMeta packet after
// the encrypted blob has been uploaded to Supabase Storage. The whole packet body
// is itself E2E-encrypted (EncryptPacket/EncryptGroupPacket), so the DecryptKey
// and Thumbnail travel confidentially.
type MediaMetadata struct {
	FileName   string   // original file name
	FileType   string   // detected MIME type
	FileSize   int64    // plaintext size in bytes
	ObjectPath string   // Supabase Storage object key
	DecryptKey [32]byte // XChaCha20-Poly1305 key for the uploaded blob
	FileHash   [32]byte // SHA-256 of the plaintext, for integrity verification
	Thumbnail  []byte   // small compressed JPEG preview (may be empty)
}

// putString writes a uint16 length prefix followed by the bytes of s.
func putString(buf []byte, s string) int {
	binary.BigEndian.PutUint16(buf, uint16(len(s)))
	copy(buf[2:], s)
	return 2 + len(s)
}

// getString reads a uint16-prefixed string starting at offset. Returns the
// string and the new offset, or an error if the data is truncated.
func getString(data []byte, offset int) (string, int, error) {
	if len(data) < offset+2 {
		return "", offset, fmt.Errorf("data too short for string length")
	}
	n := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+n {
		return "", offset, fmt.Errorf("data too short for string body")
	}
	return string(data[offset : offset+n]), offset + n, nil
}

func (m *MediaMetadata) Encode() []byte {
	size := 2 + len(m.FileName) +
		2 + len(m.FileType) +
		8 + // FileSize
		2 + len(m.ObjectPath) +
		32 + // DecryptKey
		32 + // FileHash
		4 + len(m.Thumbnail) // uint32 length + thumbnail bytes
	buf := make([]byte, size)

	offset := 0
	offset += putString(buf[offset:], m.FileName)
	offset += putString(buf[offset:], m.FileType)

	binary.BigEndian.PutUint64(buf[offset:], uint64(m.FileSize))
	offset += 8

	offset += putString(buf[offset:], m.ObjectPath)

	copy(buf[offset:], m.DecryptKey[:])
	offset += 32
	copy(buf[offset:], m.FileHash[:])
	offset += 32

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(m.Thumbnail)))
	offset += 4
	copy(buf[offset:], m.Thumbnail)

	return buf
}

func DecodeMediaMetadata(data []byte) (MediaMetadata, error) {
	var m MediaMetadata
	var err error
	offset := 0

	if m.FileName, offset, err = getString(data, offset); err != nil {
		return m, err
	}
	if m.FileType, offset, err = getString(data, offset); err != nil {
		return m, err
	}

	if len(data) < offset+8 {
		return m, fmt.Errorf("data too short for file size")
	}
	m.FileSize = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	if m.ObjectPath, offset, err = getString(data, offset); err != nil {
		return m, err
	}

	if len(data) < offset+32+32+4 {
		return m, fmt.Errorf("data too short for keys/hash")
	}
	copy(m.DecryptKey[:], data[offset:offset+32])
	offset += 32
	copy(m.FileHash[:], data[offset:offset+32])
	offset += 32

	thumbLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if len(data) < offset+thumbLen {
		return m, fmt.Errorf("data too short for thumbnail")
	}
	m.Thumbnail = make([]byte, thumbLen)
	copy(m.Thumbnail, data[offset:offset+thumbLen])

	return m, nil
}

// --- Conversation lookup ---

// ConvMember is one participant in a ConvInfo roster.
type ConvMember struct {
	UserID [IDSize]byte
	PubKey [32]byte
	Name   string

	// SigningKey is the member's Ed25519 key. Only conversation lookups carry
	// it, since the safety number of a direct chat covers it; group rosters
	// leave it zero.
	SigningKey [32]byte
}

// memberMinSize is what one member occupies on the wire with an empty name.
const memberMinSize = IDSize + 32 + 32 + 2

// ConvInfo is the body of a CtrlConvInfoAck: everything a client needs to take
// part in a conversation it has just heard of for the first time. Carrying the
// identity key of every member means direct sessions can be derived on the spot
// rather than costing a lookup each.
type ConvInfo struct {
	ConvID [IDSize]byte

	IsGroup bool

	// Name is the group's name, and empty for a direct conversation, which the
	// client titles after the peer instead. Without it, a group first learned
	// about through this lookup would have nothing to display but its ID.
	Name string

	Members []ConvMember
}

func (c *ConvInfo) Encode() []byte {
	size := IDSize + 1 + 2 + len(c.Name) + 2
	for _, m := range c.Members {
		size += memberMinSize + len(m.Name)
	}
	buf := make([]byte, size)

	offset := 0
	copy(buf[offset:], c.ConvID[:])
	offset += IDSize

	if c.IsGroup {
		buf[offset] = 1
	}
	offset++

	offset += putString(buf[offset:], c.Name)

	binary.BigEndian.PutUint16(buf[offset:], uint16(len(c.Members)))
	offset += 2

	for _, m := range c.Members {
		copy(buf[offset:], m.UserID[:])
		offset += IDSize
		copy(buf[offset:], m.PubKey[:])
		offset += 32
		copy(buf[offset:], m.SigningKey[:])
		offset += 32
		offset += putString(buf[offset:], m.Name)
	}
	return buf
}

func DecodeConvInfo(data []byte) (ConvInfo, error) {
	var c ConvInfo
	if len(data) < IDSize+1+2 {
		return c, fmt.Errorf("conv info too short: %d", len(data))
	}

	offset := 0
	copy(c.ConvID[:], data[offset:offset+IDSize])
	offset += IDSize

	c.IsGroup = data[offset] != 0
	offset++

	var err error
	if c.Name, offset, err = getString(data, offset); err != nil {
		return c, fmt.Errorf("conv info name: %w", err)
	}

	if len(data) < offset+2 {
		return c, fmt.Errorf("conv info truncated before member count")
	}
	count := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2

	// The count is attacker-controlled, so refuse one the remaining body could
	// not possibly hold rather than preallocating for it. This bounds the
	// allocation only: it assumes every member costs the minimum, so a member
	// with a long name leaves less behind than the check assumed and each
	// iteration still has to bounds-check for itself.
	if max := (len(data) - offset) / memberMinSize; count > max {
		return c, fmt.Errorf("conv info claims %d members, body holds at most %d", count, max)
	}

	c.Members = make([]ConvMember, 0, count)
	for i := 0; i < count; i++ {
		if len(data) < offset+IDSize+32+32 {
			return c, fmt.Errorf("conv info truncated at member %d", i)
		}
		var m ConvMember
		copy(m.UserID[:], data[offset:offset+IDSize])
		offset += IDSize
		copy(m.PubKey[:], data[offset:offset+32])
		offset += 32
		copy(m.SigningKey[:], data[offset:offset+32])
		offset += 32

		if m.Name, offset, err = getString(data, offset); err != nil {
			return c, fmt.Errorf("conv info member %d: %w", i, err)
		}
		c.Members = append(c.Members, m)
	}
	return c, nil
}

// EncodeSignedURLPayload / DecodeSignedURLPayload carry one or two length-prefixed
// strings, used for the CtrlUpload/CtrlDownload ack bodies (objectPath, signedURL).
func EncodeSignedURLPayload(strs ...string) []byte {
	size := 0
	for _, s := range strs {
		size += 2 + len(s)
	}
	buf := make([]byte, size)
	offset := 0
	for _, s := range strs {
		offset += putString(buf[offset:], s)
	}
	return buf
}

func DecodeSignedURLPayload(data []byte, count int) ([]string, error) {
	out := make([]string, 0, count)
	offset := 0
	for i := 0; i < count; i++ {
		s, next, err := getString(data, offset)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		offset = next
	}
	return out, nil
}

// --- Prekey bundle and login ---

// PreKeyBundle is the public key material the server keeps for each user and
// hands to anyone opening a chat with them. The identity key is X25519 and
// anchors the DH handshake; the signing key is Ed25519 and exists only to
// vouch for the signed prekey, so a bundle can be checked for internal
// consistency without trusting the server for it.
type PreKeyBundle struct {
	IdentityKey [32]byte
	SigningKey  [32]byte
	SPKID       uint32
	SPK         [32]byte
	SPKSig      [SignatureSize]byte
}

const PreKeyBundleSize = 32 + 32 + 4 + 32 + SignatureSize

func (b *PreKeyBundle) Encode() []byte {
	buf := make([]byte, PreKeyBundleSize)
	offset := copy(buf, b.IdentityKey[:])
	offset += copy(buf[offset:], b.SigningKey[:])
	binary.BigEndian.PutUint32(buf[offset:], b.SPKID)
	offset += 4
	offset += copy(buf[offset:], b.SPK[:])
	copy(buf[offset:], b.SPKSig[:])
	return buf
}

// DecodePreKeyBundle reads a bundle from the front of data. Trailing bytes are
// left for the caller, which is how a login body carries the username after it.
func DecodePreKeyBundle(data []byte) (PreKeyBundle, error) {
	var b PreKeyBundle
	if len(data) < PreKeyBundleSize {
		return b, fmt.Errorf("prekey bundle too short: %d", len(data))
	}
	offset := copy(b.IdentityKey[:], data)
	offset += copy(b.SigningKey[:], data[offset:])
	b.SPKID = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	offset += copy(b.SPK[:], data[offset:])
	copy(b.SPKSig[:], data[offset:])
	return b, nil
}

// Verify reports whether the signed prekey really was signed by the bundle's
// own signing key, and that no key in it is the all-zero placeholder.
func (b *PreKeyBundle) Verify() bool {
	if !IsValidKey(b.IdentityKey) || !IsValidKey(b.SigningKey) || !IsValidKey(b.SPK) {
		return false
	}
	return VerifyPreKey(b.SigningKey, b.SPKID, b.SPK, b.SPKSig)
}

// --- Ratchet header ---

// RatchetVersion is carried in every direct-message header. A session built
// under any other version is refused rather than guessed at.
const RatchetVersion uint8 = 1

const ratchetFlagInit uint8 = 1 << 0

// RatchetInit is what the responder needs to build the session from a message
// alone. It repeats on every message until the initiator hears back, so losing
// the first packet does not strand the rest. The initiator's ephemeral key
// travels here explicitly because the header's ratchet key moves on at each
// rotation while the handshake still needs the original.
type RatchetInit struct {
	IdentityKey [32]byte // initiator's long-term X25519 key
	Ephemeral   [32]byte // initiator's handshake ephemeral key
	SPKID       uint32   // which of the responder's signed prekeys was used
}

// RatchetHeader precedes the ciphertext of a direct message. It is
// authenticated as associated data but not encrypted.
type RatchetHeader struct {
	SenderEpoch   uint32   // epoch of the sender's current ratchet key
	UsedPeerEpoch uint32   // which of the receiver's keys the sender's chain was built against
	N             uint32   // index within the sender's current epoch
	PrevLen       uint32   // how many messages the sender's previous epoch held
	RatchetPub    [32]byte // sender's ratchet public key for SenderEpoch
	Init          *RatchetInit
}

const (
	ratchetHeaderLen = 1 + 1 + 4 + 4 + 4 + 4 + 32
	ratchetInitLen   = 32 + 32 + 4
)

// Len is the encoded size, which differs with and without init.
func (h *RatchetHeader) Len() int {
	if h.Init != nil {
		return ratchetHeaderLen + ratchetInitLen
	}
	return ratchetHeaderLen
}

func (h *RatchetHeader) Encode() []byte {
	buf := make([]byte, 0, h.Len())
	var flags uint8
	if h.Init != nil {
		flags |= ratchetFlagInit
	}
	buf = append(buf, RatchetVersion, flags)
	buf = binary.BigEndian.AppendUint32(buf, h.SenderEpoch)
	buf = binary.BigEndian.AppendUint32(buf, h.UsedPeerEpoch)
	buf = binary.BigEndian.AppendUint32(buf, h.N)
	buf = binary.BigEndian.AppendUint32(buf, h.PrevLen)
	buf = append(buf, h.RatchetPub[:]...)
	if h.Init != nil {
		buf = append(buf, h.Init.IdentityKey[:]...)
		buf = append(buf, h.Init.Ephemeral[:]...)
		buf = binary.BigEndian.AppendUint32(buf, h.Init.SPKID)
	}
	return buf
}

// DecodeRatchetHeader reads a header from the front of data and returns it with
// the number of bytes it occupied, so the caller can split off the ciphertext.
func DecodeRatchetHeader(data []byte) (RatchetHeader, int, error) {
	var h RatchetHeader
	if len(data) < ratchetHeaderLen {
		return h, 0, fmt.Errorf("ratchet header too short: %d", len(data))
	}
	if data[0] != RatchetVersion {
		return h, 0, fmt.Errorf("unsupported ratchet version %d", data[0])
	}
	flags := data[1]
	if flags&^ratchetFlagInit != 0 {
		return h, 0, fmt.Errorf("unknown ratchet header flags %#x", flags)
	}

	h.SenderEpoch = binary.BigEndian.Uint32(data[2:])
	h.UsedPeerEpoch = binary.BigEndian.Uint32(data[6:])
	h.N = binary.BigEndian.Uint32(data[10:])
	h.PrevLen = binary.BigEndian.Uint32(data[14:])
	copy(h.RatchetPub[:], data[18:50])
	offset := ratchetHeaderLen

	if flags&ratchetFlagInit != 0 {
		if len(data) < offset+ratchetInitLen {
			return h, 0, fmt.Errorf("ratchet init fields truncated: %d", len(data))
		}
		init := &RatchetInit{}
		copy(init.IdentityKey[:], data[offset:])
		copy(init.Ephemeral[:], data[offset+32:])
		init.SPKID = binary.BigEndian.Uint32(data[offset+64:])
		h.Init = init
		offset += ratchetInitLen
	}
	return h, offset, nil
}
