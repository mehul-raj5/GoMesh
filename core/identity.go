package core

import (
	common "common"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	// Where this device keeps things, inside its data directory.
	stateDirName = "state" // sealed crypto records
	vaultDirName = "vault" // the terminal client's stand-in for the Keychain

	// What earlier versions kept in plaintext, migrated on first open.
	legacyKeyFile  = "identity.key"
	legacyStateDir = "gomesh-state"

	prekeyStateName = "prekeys"

	// SPKGrace is how long the private half of a retired signed prekey is kept.
	// A peer may have fetched the bundle just before the rotation and still be
	// about to open a chat with it, so the old key has to stay usable for a while.
	SPKGrace = 30 * 24 * time.Hour
)

// identity.key holds, in order: the X25519 private key, its public key, and the
// Ed25519 signing seed. Files written before signing keys existed hold only the
// first two and are upgraded in place on load.
const (
	legacyIdentityLen = 64
	identityLen       = 96
)

// SignedPreKey is a medium-term X25519 key pair whose public half the server
// hands out so that people can open a chat with us while we are offline. The
// signature, made with the identity signing key, lets them check the server did
// not substitute its own.
type SignedPreKey struct {
	ID        uint32
	Private   [32]byte
	Public    [32]byte
	Signature [common.SignatureSize]byte
	CreatedAt time.Time

	// RetiredAt is zero while this is the key being advertised.
	RetiredAt time.Time
}

type prekeyState struct {
	NextID uint32
	SPKs   []SignedPreKey
}

type IdentityManager struct {
	PrivateKey [32]byte
	PublicKey  [32]byte

	// SigningSeed is the private half of the Ed25519 key that vouches for signed
	// prekeys and proves ownership of the account at login.
	SigningSeed [32]byte
	SigningKey  [32]byte

	mu     sync.Mutex
	store  *StateStore
	spks   []SignedPreKey
	nextID uint32
	now    func() time.Time
}

func identityAAD() []byte { return []byte("GoMesh-identity-v1") }

// openIdentity loads the identity keys from the vault, sealed under the account
// key. A device without them takes them from an earlier version's plaintext
// identity.key if there is one, and makes new ones if not; either way they go
// into the vault before the plaintext file is deleted. A vault that cannot be
// read, or keys that will not open, are errors: new keys made over them would
// orphan every session the old ones hold.
func openIdentity(v Vault, accountKey [32]byte, legacyPath string) (*IdentityManager, error) {
	im := &IdentityManager{now: time.Now}

	sealed, err := v.Get(vaultIdentity)
	switch {
	case err == nil:
		plain, err := unsealBytes(accountKey, sealed, identityAAD())
		if err != nil {
			return nil, fmt.Errorf("the identity keys in the vault do not open: %w", err)
		}
		if len(plain) != identityLen {
			return nil, fmt.Errorf("the identity keys in the vault are %d bytes", len(plain))
		}
		im.setFrom(plain)
		// The vault's copy wins; a plaintext one left by an interrupted migration goes.
		if err := os.Remove(legacyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return im, nil

	case !errors.Is(err, ErrNotInVault):
		return nil, fmt.Errorf("reading the vault: %w", err)
	}

	data, err := os.ReadFile(legacyPath)
	switch {
	case err == nil:
		if len(data) != legacyIdentityLen && len(data) != identityLen {
			return nil, fmt.Errorf("%s has unexpected length %d", legacyPath, len(data))
		}
		copy(im.PrivateKey[:], data[:32])
		curve25519.ScalarBaseMult(&im.PublicKey, &im.PrivateKey)
		if len(data) == identityLen {
			copy(im.SigningSeed[:], data[64:96])
			im.SigningKey = common.SigningPublicFromSeed(im.SigningSeed)
		} else if im.SigningSeed, im.SigningKey, err = common.GenerateSigningKeys(); err != nil {
			return nil, err
		}
		log.Printf("Moving the identity keys from %s into the vault", legacyPath)

	case errors.Is(err, os.ErrNotExist):
		log.Println("Generating new Identity Keys...")
		if im.PrivateKey, im.PublicKey, err = common.GenerateIdentityKeys(); err != nil {
			return nil, err
		}
		if im.SigningSeed, im.SigningKey, err = common.GenerateSigningKeys(); err != nil {
			return nil, err
		}

	default:
		return nil, err
	}

	out := make([]byte, 0, identityLen)
	out = append(out, im.PrivateKey[:]...)
	out = append(out, im.PublicKey[:]...)
	out = append(out, im.SigningSeed[:]...)
	sealedOut, err := sealBytes(accountKey, out, identityAAD())
	if err != nil {
		return nil, err
	}
	if err := v.Put(vaultIdentity, sealedOut); err != nil {
		return nil, fmt.Errorf("saving the identity keys: %w", err)
	}
	if err := os.Remove(legacyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return im, nil
}

// setFrom loads the keys from their stored layout: private, public, signing seed.
func (im *IdentityManager) setFrom(b []byte) {
	copy(im.PrivateKey[:], b[:32])
	curve25519.ScalarBaseMult(&im.PublicKey, &im.PrivateKey)
	copy(im.SigningSeed[:], b[64:96])
	im.SigningKey = common.SigningPublicFromSeed(im.SigningSeed)
}

func (im *IdentityManager) GetPublicKey() [32]byte {
	return im.PublicKey
}

// LoadPreKeys attaches the state store and brings the signed prekeys up: the
// saved ones if there are any, otherwise a first one, which is saved before
// this returns. Retired keys past their grace period are dropped.
func (im *IdentityManager) LoadPreKeys(store *StateStore) error {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.store = store

	var st prekeyState
	ok, err := store.Load(prekeyStateName, &st)
	if err != nil {
		return err
	}
	if !ok {
		im.nextID = 1
		return im.rotateLocked()
	}

	for _, k := range st.SPKs {
		if !common.VerifyPreKey(im.SigningKey, k.ID, k.Public, k.Signature) {
			return fmt.Errorf("saved signed prekey %d was not signed by this identity", k.ID)
		}
	}
	im.spks, im.nextID = st.SPKs, st.NextID
	if im.currentLocked() == nil {
		return im.rotateLocked()
	}
	if pruned := im.pruneLocked(); pruned > 0 {
		return im.saveLocked()
	}
	return nil
}

func (im *IdentityManager) currentLocked() *SignedPreKey {
	for i := len(im.spks) - 1; i >= 0; i-- {
		if im.spks[i].RetiredAt.IsZero() {
			return &im.spks[i]
		}
	}
	return nil
}

// pruneLocked drops retired keys older than SPKGrace and reports how many.
func (im *IdentityManager) pruneLocked() int {
	cutoff := im.now().Add(-SPKGrace)
	kept := im.spks[:0]
	for _, k := range im.spks {
		if k.RetiredAt.IsZero() || k.RetiredAt.After(cutoff) {
			kept = append(kept, k)
		}
	}
	n := len(im.spks) - len(kept)
	im.spks = kept
	return n
}

func (im *IdentityManager) saveLocked() error {
	return im.store.Save(prekeyStateName, prekeyState{NextID: im.nextID, SPKs: im.spks})
}

// rotateLocked retires the current signed prekey, if any, and installs a new
// one. The change is saved before it takes effect in memory, so a failed write
// leaves the old state intact rather than advertising a key nobody remembers.
func (im *IdentityManager) rotateLocked() error {
	priv, pub, err := common.GenerateEphemeralKeys()
	if err != nil {
		return err
	}
	now := im.now()
	k := SignedPreKey{ID: im.nextID, Private: priv, Public: pub, CreatedAt: now}
	k.Signature = common.SignPreKey(im.SigningSeed, k.ID, k.Public)

	oldSPKs, oldNext := im.spks, im.nextID
	next := make([]SignedPreKey, len(im.spks), len(im.spks)+1)
	copy(next, im.spks)
	for i := range next {
		if next[i].RetiredAt.IsZero() {
			next[i].RetiredAt = now
		}
	}
	im.spks = append(next, k)
	im.nextID++
	im.pruneLocked()

	if err := im.saveLocked(); err != nil {
		im.spks, im.nextID = oldSPKs, oldNext
		return fmt.Errorf("saving signed prekey: %w", err)
	}
	return nil
}

// RotateSPK replaces the signed prekey that is being advertised. The previous
// one is retired but its private half is kept for SPKGrace.
func (im *IdentityManager) RotateSPK() error {
	im.mu.Lock()
	defer im.mu.Unlock()
	return im.rotateLocked()
}

// Bundle is the public key material to register with the server.
func (im *IdentityManager) Bundle() common.PreKeyBundle {
	im.mu.Lock()
	defer im.mu.Unlock()
	cur := im.currentLocked()
	return common.PreKeyBundle{
		IdentityKey: im.PublicKey,
		SigningKey:  im.SigningKey,
		SPKID:       cur.ID,
		SPK:         cur.Public,
		SPKSig:      cur.Signature,
	}
}

// SPKPrivate returns the private half of the signed prekey with the given ID,
// whether it is current or retired within its grace period. A first message
// names the prekey it was built against, so this is how a responder finds it.
func (im *IdentityManager) SPKPrivate(id uint32) ([32]byte, bool) {
	im.mu.Lock()
	defer im.mu.Unlock()
	cutoff := im.now().Add(-SPKGrace)
	for _, k := range im.spks {
		if k.ID == id && (k.RetiredAt.IsZero() || k.RetiredAt.After(cutoff)) {
			return k.Private, true
		}
	}
	return [32]byte{}, false
}

// SignLogin answers the server's login challenge.
func (im *IdentityManager) SignLogin(nonce [common.LoginNonceSize]byte, username string) [common.SignatureSize]byte {
	return common.SignLogin(im.SigningSeed, nonce, im.PublicKey, username)
}

// SafetyNumber is the string two people compare, out of band, to confirm that
// neither was handed a substituted key by the server.
func (im *IdentityManager) SafetyNumber(peerIK, peerSigning [32]byte) string {
	return common.SafetyNumber(im.PublicKey, im.SigningKey, peerIK, peerSigning)
}
