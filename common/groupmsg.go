package common

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

// --- Group messages ---

// GroupMsgVersion is carried in every group message header. A message under any
// other version is refused.
const GroupMsgVersion uint8 = 1

// GroupHeader precedes the ciphertext of a group message. It is the associated
// data of the AEAD and is covered by the signature, so neither it nor the
// ciphertext can be altered or moved to another group, sender or message type.
//
// MsgType is not in the minimal header the design names. The packet header that
// carries it travels outside the signature, and without it a relay could present
// a text ciphertext as a media envelope or the reverse.
type GroupHeader struct {
	Version           uint8
	GroupID           [IDSize]byte
	SenderID          [IDSize]byte
	KeyID             uint32
	N                 uint32
	MembershipVersion uint32
	MsgType           uint8
}

// GroupHeaderLen is the encoded size of a GroupHeader.
const GroupHeaderLen = 1 + IDSize + IDSize + 4 + 4 + 4 + 1

func (h *GroupHeader) Encode() []byte {
	buf := make([]byte, 0, GroupHeaderLen)
	buf = append(buf, h.Version)
	buf = append(buf, h.GroupID[:]...)
	buf = append(buf, h.SenderID[:]...)
	buf = binary.BigEndian.AppendUint32(buf, h.KeyID)
	buf = binary.BigEndian.AppendUint32(buf, h.N)
	buf = binary.BigEndian.AppendUint32(buf, h.MembershipVersion)
	return append(buf, h.MsgType)
}

// GroupWire is the body of a group message: header, signature, ciphertext. The
// server fans the same bytes out to every member.
type GroupWire struct {
	Header     GroupHeader
	Signature  [SignatureSize]byte
	Ciphertext []byte
}

func (w *GroupWire) Encode() []byte {
	buf := make([]byte, 0, GroupHeaderLen+SignatureSize+len(w.Ciphertext))
	buf = append(buf, w.Header.Encode()...)
	buf = append(buf, w.Signature[:]...)
	return append(buf, w.Ciphertext...)
}

// DecodeGroupWire splits a body into its parts. The ciphertext aliases data.
func DecodeGroupWire(data []byte) (GroupWire, error) {
	var w GroupWire
	if len(data) < GroupHeaderLen+SignatureSize+NonceSize {
		return w, fmt.Errorf("group message too short: %d", len(data))
	}
	if data[0] != GroupMsgVersion {
		return w, fmt.Errorf("unsupported group message version %d", data[0])
	}
	o := 0
	w.Header.Version = data[o]
	o++
	o += copy(w.Header.GroupID[:], data[o:])
	o += copy(w.Header.SenderID[:], data[o:])
	w.Header.KeyID = binary.BigEndian.Uint32(data[o:])
	o += 4
	w.Header.N = binary.BigEndian.Uint32(data[o:])
	o += 4
	w.Header.MembershipVersion = binary.BigEndian.Uint32(data[o:])
	o += 4
	w.Header.MsgType = data[o]
	o++
	o += copy(w.Signature[:], data[o:])
	w.Ciphertext = data[o:]
	return w, nil
}

// groupSigned is what a group message signature covers: the encoded header and
// the ciphertext.
func groupSigned(header, ciphertext []byte) []byte {
	msg := make([]byte, 0, len("GoMesh-GroupMsg-v1")+len(header)+len(ciphertext))
	msg = append(msg, "GoMesh-GroupMsg-v1"...)
	msg = append(msg, header...)
	return append(msg, ciphertext...)
}

// SignGroupMessage signs header || ciphertext with a sender key's signing seed.
func SignGroupMessage(seed [KeySize]byte, header, ciphertext []byte) (sig [SignatureSize]byte) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	copy(sig[:], ed25519.Sign(priv, groupSigned(header, ciphertext)))
	return
}

// VerifyGroupMessage reports whether sig is a valid signature by pub.
func VerifyGroupMessage(pub [KeySize]byte, header, ciphertext []byte, sig [SignatureSize]byte) bool {
	return ed25519.Verify(pub[:], groupSigned(header, ciphertext), sig[:])
}

// --- Sender key distribution ---

// SenderKeyDist is the body of a CtrlSenderKey packet, which always travels
// inside a 1:1 ratchet session. The key's owner is the session's peer and is
// deliberately not a field here: a payload must never be able to name someone
// else as the owner.
type SenderKeyDist struct {
	GroupID           [IDSize]byte
	KeyID             uint32
	ChainKey          [32]byte // chain key at iteration N
	N                 uint32
	SignPub           [32]byte
	MembershipVersion uint32
}

const senderKeyDistVersion = 2
const senderKeyDistLen = 1 + IDSize + 4 + 32 + 4 + 32 + 4

func (s *SenderKeyDist) Encode() []byte {
	buf := make([]byte, 0, senderKeyDistLen)
	buf = append(buf, senderKeyDistVersion)
	buf = append(buf, s.GroupID[:]...)
	buf = binary.BigEndian.AppendUint32(buf, s.KeyID)
	buf = append(buf, s.ChainKey[:]...)
	buf = binary.BigEndian.AppendUint32(buf, s.N)
	buf = append(buf, s.SignPub[:]...)
	return binary.BigEndian.AppendUint32(buf, s.MembershipVersion)
}

func DecodeSenderKeyDist(data []byte) (SenderKeyDist, error) {
	var s SenderKeyDist
	if len(data) < senderKeyDistLen {
		return s, fmt.Errorf("sender key distribution too short: %d", len(data))
	}
	if data[0] != senderKeyDistVersion {
		return s, errors.New("unsupported sender key distribution version")
	}
	o := 1
	o += copy(s.GroupID[:], data[o:])
	s.KeyID = binary.BigEndian.Uint32(data[o:])
	o += 4
	o += copy(s.ChainKey[:], data[o:])
	s.N = binary.BigEndian.Uint32(data[o:])
	o += 4
	o += copy(s.SignPub[:], data[o:])
	s.MembershipVersion = binary.BigEndian.Uint32(data[o:])
	return s, nil
}
