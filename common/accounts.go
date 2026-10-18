package common

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Accounts are a username and a password. The password authenticates the
// account; the existing signed challenge still proves the device holds the
// keys it presents. A login answers with a session token, so a device can come
// back later without the password.
//
// Every body here is parsed before the sender has authenticated, so the
// decoders insist on exact lengths and the sizes are small and fixed.

const (
	SessionTokenSize = 32

	MinUsernameLen = 3
	MaxUsernameLen = 32
	// MaxPasswordBytes bounds the encoded password, which is why its length
	// field is two bytes wide. It is the one length rule passwords have while
	// GoMesh is being tested.
	MaxPasswordBytes = 512
	MaxDeviceNameLen = 64

	// MaxPreAuthBody caps any packet read before login completes. The largest
	// legitimate one is a credentials body, well under this.
	MaxPreAuthBody = 1024
)

// ErrorCode says why the server refused something. It is the first byte of a
// CtrlError body. A CtrlError with no body carries ErrUnknown.
type ErrorCode uint8

const (
	ErrUnknown          ErrorCode = 0
	ErrBadRequest       ErrorCode = 1
	ErrBadCredentials   ErrorCode = 2
	ErrUsernameTaken    ErrorCode = 3
	ErrInvalidUsername  ErrorCode = 4
	ErrWeakPassword     ErrorCode = 5
	ErrRateLimited      ErrorCode = 6
	ErrSessionRevoked   ErrorCode = 7
	ErrDeviceReplaced   ErrorCode = 8
	ErrPasswordRequired ErrorCode = 9
	ErrInternal         ErrorCode = 10
)

func (c ErrorCode) String() string {
	switch c {
	case ErrBadRequest:
		return "bad request"
	case ErrBadCredentials:
		return "wrong username or password"
	case ErrUsernameTaken:
		return "username already taken"
	case ErrInvalidUsername:
		return "invalid username"
	case ErrWeakPassword:
		return "password too weak"
	case ErrRateLimited:
		return "too many attempts, try again later"
	case ErrSessionRevoked:
		return "session ended, sign in again"
	case ErrDeviceReplaced:
		return "this account signed in on another device"
	case ErrPasswordRequired:
		return "password required"
	case ErrInternal:
		return "server error"
	default:
		return fmt.Sprintf("error %d", uint8(c))
	}
}

// ServerError is a CtrlError decoded on the client side.
type ServerError struct {
	Code    ErrorCode
	Message string
}

func (e *ServerError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code.String()
}

// EncodeError builds a CtrlError body: [Code 1][MsgLen 2][Msg].
func EncodeError(code ErrorCode, msg string) []byte {
	if len(msg) > 0xFFFF {
		msg = msg[:0xFFFF]
	}
	buf := make([]byte, 3, 3+len(msg))
	buf[0] = byte(code)
	binary.BigEndian.PutUint16(buf[1:], uint16(len(msg)))
	return append(buf, msg...)
}

// DecodeError reads a CtrlError body. An empty body is ErrUnknown, which is
// what servers before error codes sent.
func DecodeError(body []byte) (*ServerError, error) {
	if len(body) == 0 {
		return &ServerError{Code: ErrUnknown}, nil
	}
	if len(body) < 3 {
		return nil, errors.New("error body too short")
	}
	n := int(binary.BigEndian.Uint16(body[1:]))
	if len(body) != 3+n {
		return nil, fmt.Errorf("error body is %d bytes, header says %d", len(body), 3+n)
	}
	return &ServerError{Code: ErrorCode(body[0]), Message: string(body[3:])}, nil
}

// ErrorPacket wraps a code and message in a CtrlError packet.
func ErrorPacket(code ErrorCode, msg string) Packet {
	body := EncodeError(code, msg)
	return Packet{Header: Header{MsgType: CtrlError, BodyLen: uint32(len(body))}, Body: body}
}

// Credentials is the body of CtrlRegister and CtrlLogin:
// [ULen 1][Username][PLen 2][Password][PreKeyBundle 164][DLen 1][DeviceName].
type Credentials struct {
	Username   string
	Password   string
	Bundle     PreKeyBundle
	DeviceName string
}

func EncodeCredentials(c *Credentials) ([]byte, error) {
	switch {
	case len(c.Username) > 0xFF:
		return nil, errors.New("username too long")
	case len(c.Password) > MaxPasswordBytes:
		return nil, errors.New("password too long")
	case len(c.DeviceName) > MaxDeviceNameLen:
		return nil, errors.New("device name too long")
	}
	buf := make([]byte, 0, 1+len(c.Username)+2+len(c.Password)+PreKeyBundleSize+1+len(c.DeviceName))
	buf = append(buf, byte(len(c.Username)))
	buf = append(buf, c.Username...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(c.Password)))
	buf = append(buf, c.Password...)
	buf = append(buf, c.Bundle.Encode()...)
	buf = append(buf, byte(len(c.DeviceName)))
	return append(buf, c.DeviceName...), nil
}

func DecodeCredentials(body []byte) (Credentials, error) {
	var c Credentials
	o := 0
	take := func(n int) ([]byte, error) {
		if n < 0 || len(body)-o < n {
			return nil, errors.New("credentials truncated")
		}
		b := body[o : o+n]
		o += n
		return b, nil
	}

	l, err := take(1)
	if err != nil {
		return c, err
	}
	u, err := take(int(l[0]))
	if err != nil {
		return c, err
	}
	pl, err := take(2)
	if err != nil {
		return c, err
	}
	plen := int(binary.BigEndian.Uint16(pl))
	if plen > MaxPasswordBytes {
		return c, errors.New("password too long")
	}
	p, err := take(plen)
	if err != nil {
		return c, err
	}
	bb, err := take(PreKeyBundleSize)
	if err != nil {
		return c, err
	}
	if c.Bundle, err = DecodePreKeyBundle(bb); err != nil {
		return c, err
	}
	dl, err := take(1)
	if err != nil {
		return c, err
	}
	if int(dl[0]) > MaxDeviceNameLen {
		return c, errors.New("device name too long")
	}
	d, err := take(int(dl[0]))
	if err != nil {
		return c, err
	}
	if o != len(body) {
		return c, errors.New("trailing bytes after credentials")
	}
	c.Username, c.Password, c.DeviceName = string(u), string(p), string(d)
	return c, nil
}

// EncodeResume builds a CtrlResume body: [SessionToken 32][PreKeyBundle 164].
func EncodeResume(token [SessionTokenSize]byte, b *PreKeyBundle) []byte {
	return append(append(make([]byte, 0, SessionTokenSize+PreKeyBundleSize), token[:]...), b.Encode()...)
}

func DecodeResume(body []byte) ([SessionTokenSize]byte, PreKeyBundle, error) {
	var token [SessionTokenSize]byte
	if len(body) != SessionTokenSize+PreKeyBundleSize {
		return token, PreKeyBundle{}, fmt.Errorf("resume body is %d bytes", len(body))
	}
	copy(token[:], body)
	b, err := DecodePreKeyBundle(body[SessionTokenSize:])
	return token, b, err
}

// EncodeLoginAck builds a CtrlLoginAck body: [UserID 16][SessionToken 32].
func EncodeLoginAck(userID [IDSize]byte, token [SessionTokenSize]byte) []byte {
	return append(append(make([]byte, 0, IDSize+SessionTokenSize), userID[:]...), token[:]...)
}

func DecodeLoginAck(body []byte) ([IDSize]byte, [SessionTokenSize]byte, error) {
	var id [IDSize]byte
	var token [SessionTokenSize]byte
	if len(body) != IDSize+SessionTokenSize {
		return id, token, fmt.Errorf("login ack is %d bytes", len(body))
	}
	copy(id[:], body)
	copy(token[:], body[IDSize:])
	return id, token, nil
}

// --- Validation, shared by the server and every client ---

var usernamePattern = regexp.MustCompile(`^[a-z0-9_.]+$`)

// NormalizeUsername lowercases a username and checks it: 3 to 32 characters of
// a-z, 0-9, underscore and dot. Usernames are unique regardless of case, so
// they are stored and compared in this form.
func NormalizeUsername(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case len(s) < MinUsernameLen:
		return "", fmt.Errorf("username must be at least %d characters", MinUsernameLen)
	case len(s) > MaxUsernameLen:
		return "", fmt.Errorf("username must be at most %d characters", MaxUsernameLen)
	case !usernamePattern.MatchString(s):
		return "", errors.New("username may only use a-z, 0-9, _ and .")
	}
	return s, nil
}

// CheckPassword applies the password rules. While GoMesh is being tested there
// are almost none: any non-empty text that fits in the message is accepted.
// The username is kept in the signature for when real rules return.
func CheckPassword(password, _ string) error {
	switch {
	case password == "":
		return errors.New("enter a password")
	case !utf8.ValidString(password):
		return errors.New("password is not valid text")
	case len(password) > MaxPasswordBytes:
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordBytes)
	}
	return nil
}

// GroupRef names a group in a CtrlMyGroups list.
type GroupRef struct {
	ID   [IDSize]byte
	Name string
}

// MaxMyGroups bounds a CtrlMyGroups list.
const MaxMyGroups = 4096

// EncodeMyGroups builds a CtrlMyGroups body: [Count 2] then per group
// [GroupID 16] [NameLen 2] [Name].
func EncodeMyGroups(groups []GroupRef) []byte {
	buf := binary.BigEndian.AppendUint16(nil, uint16(len(groups)))
	for _, g := range groups {
		name := g.Name
		if len(name) > 0xFFFF {
			name = name[:0xFFFF]
		}
		buf = append(buf, g.ID[:]...)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(name)))
		buf = append(buf, name...)
	}
	return buf
}

func DecodeMyGroups(body []byte) ([]GroupRef, error) {
	if len(body) < 2 {
		return nil, errors.New("group list truncated before its count")
	}
	count := int(binary.BigEndian.Uint16(body))
	if count > MaxMyGroups {
		return nil, fmt.Errorf("group list claims %d groups, limit %d", count, MaxMyGroups)
	}
	o := 2
	out := make([]GroupRef, 0, count)
	for i := 0; i < count; i++ {
		if len(body)-o < IDSize+2 {
			return nil, fmt.Errorf("group %d truncated", i)
		}
		var g GroupRef
		o += copy(g.ID[:], body[o:])
		n := int(binary.BigEndian.Uint16(body[o:]))
		o += 2
		if len(body)-o < n {
			return nil, fmt.Errorf("group %d name truncated", i)
		}
		g.Name = string(body[o : o+n])
		o += n
		out = append(out, g)
	}
	if o != len(body) {
		return nil, errors.New("trailing bytes after the group list")
	}
	return out, nil
}
