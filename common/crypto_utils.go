package common

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	KeySize   = 32
	NonceSize = 24
)

func GenerateIdentityKeys() (private, public [KeySize]byte, err error) {
	return generateKeyPair()
}

func GenerateEphemeralKeys() (private, public [KeySize]byte, err error) {
	return generateKeyPair()
}

func generateKeyPair() (private, public [KeySize]byte, err error) {
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		return private, public, err
	}

	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	curve25519.ScalarBaseMult(&public, &private)
	return private, public, nil
}

func DeriveSharedSecret(private, peerPublic [KeySize]byte) ([KeySize]byte, error) {
	secretSlice, err := curve25519.X25519(private[:], peerPublic[:])
	if err != nil {
		return [KeySize]byte{}, err
	}
	var secret [KeySize]byte
	copy(secret[:], secretSlice)
	return secret, nil
}

func DeriveSessionKey(sharedSecret [KeySize]byte, salt, infoContext []byte) ([KeySize]byte, error) {
	hkdf := hkdf.New(sha256.New, sharedSecret[:], salt, infoContext)
	var sessionKey [KeySize]byte
	if _, err := io.ReadFull(hkdf, sessionKey[:]); err != nil {
		return sessionKey, err
	}
	return sessionKey, nil
}

func Encrypt(key [KeySize]byte, plaintext []byte, headerBytes []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, headerBytes), nil
}

func Decrypt(key [KeySize]byte, data []byte, headerBytes []byte) ([]byte, error) {
	if len(data) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	return aead.Open(nil, nonce, ciphertext, headerBytes)
}

// Sha256 returns the SHA-256 digest of data. Used for media file-integrity
// verification (the "File Hash" in the direct-upload protocol).
func Sha256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// LowerID reports whether id1 sorts before id2 in lexicographic byte order.
// Equal IDs report false.
//
// Both ends of a direct conversation evaluate this identically, which is what
// lets them agree on which half of the derived root each takes for sending and
// which for receiving, without exchanging a message to settle it.
func LowerID(id1, id2 [16]byte) bool {
	return bytes.Compare(id1[:], id2[:]) < 0
}

func HashIDs(id1, id2 [16]byte) [16]byte {
	first, second := id1, id2
	if !LowerID(id1, id2) {
		first, second = id2, id1
	}

	h := sha256.New()
	h.Write(first[:])
	h.Write(second[:])
	fullHash := h.Sum(nil)

	var convID [16]byte
	copy(convID[:], fullHash[:16])
	return convID
}

func IsValidKey(k [KeySize]byte) bool {
	zero := [KeySize]byte{}
	return k != zero
}

func RatchetStep(chainKey [KeySize]byte) (messageKey, nextChainKey [KeySize]byte) {
	macMsg := hmac.New(sha256.New, chainKey[:])
	macMsg.Write([]byte{0x01})
	copy(messageKey[:], macMsg.Sum(nil))

	macChain := hmac.New(sha256.New, chainKey[:])
	macChain.Write([]byte{0x02})
	copy(nextChainKey[:], macChain.Sum(nil))

	return
}

// --- Directional ratchet primitives ---

// SignatureSize is the length of an Ed25519 signature.
const SignatureSize = 64

// Direction names one of the two sending directions of a 1:1 conversation. The
// lower user ID owns LowToHigh and the higher owns HighToLow. Each direction has
// its own root key that only its owner ever advances, which is what keeps two
// people rotating at the same moment from desynchronising each other.
type Direction uint8

const (
	LowToHigh Direction = iota
	HighToLow
)

// SendDirection is the direction self owns when talking to peer.
func SendDirection(self, peer [16]byte) Direction {
	if LowerID(self, peer) {
		return LowToHigh
	}
	return HighToLow
}

func (d Direction) Opposite() Direction {
	if d == LowToHigh {
		return HighToLow
	}
	return LowToHigh
}

func (d Direction) label() string {
	if d == LowToHigh {
		return "low->high"
	}
	return "high->low"
}

// RootInfo is the HKDF context that separates this direction's initial root key.
func (d Direction) RootInfo() string { return "root:" + d.label() }

// RatchetInfo is the HKDF context for every DH step on this direction.
func (d Direction) RatchetInfo() string { return "ratchet:" + d.label() }

// GenerateSigningKeys returns an Ed25519 seed and its public key. The seed is
// the private half; it is expanded on each signing call.
func GenerateSigningKeys() (seed, public [KeySize]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, seed[:]); err != nil {
		return
	}
	return seed, SigningPublicFromSeed(seed), nil
}

func SigningPublicFromSeed(seed [KeySize]byte) (public [KeySize]byte) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	copy(public[:], priv.Public().(ed25519.PublicKey))
	return
}

// preKeyMessage is what a signed prekey signature covers. The ID is included so
// a signature cannot be replayed onto the same key under a different ID.
func preKeyMessage(spkID uint32, spk [KeySize]byte) []byte {
	msg := make([]byte, 0, 13+4+KeySize)
	msg = append(msg, "GoMesh-SPK-v1"...)
	msg = binary.BigEndian.AppendUint32(msg, spkID)
	return append(msg, spk[:]...)
}

func SignPreKey(seed [KeySize]byte, spkID uint32, spk [KeySize]byte) (sig [SignatureSize]byte) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	copy(sig[:], ed25519.Sign(priv, preKeyMessage(spkID, spk)))
	return
}

func VerifyPreKey(signingPub [KeySize]byte, spkID uint32, spk [KeySize]byte, sig [SignatureSize]byte) bool {
	return ed25519.Verify(signingPub[:], preKeyMessage(spkID, spk), sig[:])
}

// KDFRootKey advances a root key with one DH output. The old root is the HKDF
// salt and the DH output is the input keying material, so the result depends on
// every DH step that came before it as well as this one.
func KDFRootKey(rk, dhOut [KeySize]byte, info string) (newRK, newCK [KeySize]byte, err error) {
	r := hkdf.New(sha256.New, dhOut[:], rk[:], []byte(info))
	if _, err = io.ReadFull(r, newRK[:]); err != nil {
		return
	}
	_, err = io.ReadFull(r, newCK[:])
	return
}

// initSecret mixes the three DH outputs of the session handshake into one key.
func initSecret(d1, d2, d3 [KeySize]byte) ([KeySize]byte, error) {
	ikm := make([]byte, 0, 3*KeySize)
	ikm = append(ikm, d1[:]...)
	ikm = append(ikm, d2[:]...)
	ikm = append(ikm, d3[:]...)

	var sk [KeySize]byte
	salt := make([]byte, KeySize)
	_, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte("session-init-v1")), sk[:])
	return sk, err
}

// InitiatorSecret is the starting secret as the party opening a chat computes
// it: its identity key against the peer's signed prekey, its fresh ephemeral
// key against the peer's identity key, and the ephemeral against the prekey.
func InitiatorSecret(ikPriv, ekPriv, peerIK, peerSPK [KeySize]byte) ([KeySize]byte, error) {
	d1, err := DeriveSharedSecret(ikPriv, peerSPK)
	if err != nil {
		return [KeySize]byte{}, err
	}
	d2, err := DeriveSharedSecret(ekPriv, peerIK)
	if err != nil {
		return [KeySize]byte{}, err
	}
	d3, err := DeriveSharedSecret(ekPriv, peerSPK)
	if err != nil {
		return [KeySize]byte{}, err
	}
	return initSecret(d1, d2, d3)
}

// ResponderSecret mirrors InitiatorSecret from the other side, using the
// private half of the signed prekey the initiator named.
func ResponderSecret(ikPriv, spkPriv, peerIK, peerEK [KeySize]byte) ([KeySize]byte, error) {
	d1, err := DeriveSharedSecret(spkPriv, peerIK)
	if err != nil {
		return [KeySize]byte{}, err
	}
	d2, err := DeriveSharedSecret(ikPriv, peerEK)
	if err != nil {
		return [KeySize]byte{}, err
	}
	d3, err := DeriveSharedSecret(spkPriv, peerEK)
	if err != nil {
		return [KeySize]byte{}, err
	}
	return initSecret(d1, d2, d3)
}

// DeriveDirectionRoots splits the starting secret into one root key per
// sending direction.
func DeriveDirectionRoots(sk [KeySize]byte) (lowToHigh, highToLow [KeySize]byte, err error) {
	for _, d := range []struct {
		dir Direction
		out *[KeySize]byte
	}{{LowToHigh, &lowToHigh}, {HighToLow, &highToLow}} {
		if _, err = io.ReadFull(hkdf.New(sha256.New, sk[:], nil, []byte(d.dir.RootInfo())), d.out[:]); err != nil {
			return
		}
	}
	return
}

// SafetyNumber renders both parties' long-term keys as 12 groups of 5 digits.
// The two keys are sorted before hashing, so each side computes the same string
// and a mismatch read aloud means somebody was handed a substituted key.
func SafetyNumber(ikA, signA, ikB, signB [KeySize]byte) string {
	a := append(append([]byte{}, ikA[:]...), signA[:]...)
	b := append(append([]byte{}, ikB[:]...), signB[:]...)
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}

	h := sha512.New()
	h.Write([]byte("GoMesh-safety-v1"))
	h.Write(a)
	h.Write(b)
	sum := h.Sum(nil)

	out := make([]byte, 0, 12*6)
	for i := 0; i < 12; i++ {
		v := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, sum[i*5:i*5+5]...)) % 100000
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, fmt.Sprintf("%05d", v)...)
	}
	return string(out)
}

// --- Login proof ---

// LoginNonceSize is the length of the random challenge the server issues.
const LoginNonceSize = 32

// loginMessage is what a login proof signs. The identity key and username are
// included so a proof made for one account cannot be presented for another, and
// the nonce is fresh per connection so a captured proof cannot be replayed.
func loginMessage(nonce [LoginNonceSize]byte, ik [KeySize]byte, username string) []byte {
	msg := make([]byte, 0, 15+LoginNonceSize+KeySize+len(username))
	msg = append(msg, "GoMesh-login-v2"...)
	msg = append(msg, nonce[:]...)
	msg = append(msg, ik[:]...)
	return append(msg, username...)
}

func SignLogin(seed [KeySize]byte, nonce [LoginNonceSize]byte, ik [KeySize]byte, username string) (sig [SignatureSize]byte) {
	priv := ed25519.NewKeyFromSeed(seed[:])
	copy(sig[:], ed25519.Sign(priv, loginMessage(nonce, ik, username)))
	return
}

func VerifyLogin(signingPub [KeySize]byte, nonce [LoginNonceSize]byte, ik [KeySize]byte, username string, sig [SignatureSize]byte) bool {
	return ed25519.Verify(signingPub[:], loginMessage(nonce, ik, username), sig[:])
}
