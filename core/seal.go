package core

import (
	common "common"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
)

// Everything the engine keeps on disk is sealed: XChaCha20-Poly1305 under a key
// derived from a root the vault holds, with the record's own name bound in as
// associated data, so a file copied over another one does not open. Files are
// named by an HMAC of what they hold, so a folder listing says nothing about
// which chat is which.

// Vault stores small secrets. On Apple devices it is the Keychain, sealed again
// by the Secure Enclave; in the terminal client it is a folder of 0600 files.
type Vault interface {
	// Get returns the secret stored under name, or ErrNotInVault if there is
	// none. Any other error means the vault cannot be read right now (on iOS,
	// before the device's first unlock) and must never be taken for absence:
	// treating it as "no key" would make fresh keys and orphan everything sealed
	// under the old ones.
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Delete(name string) error
}

// secrets is the client's vault: the one it was given, or 0600 files in its
// data directory.
func (cl *Client) secrets() Vault {
	if cl.vault != nil {
		return cl.vault
	}
	return fileVault{dir: cl.dataPath(vaultDirName)}
}

// ErrNotInVault means the vault holds nothing under that name.
var ErrNotInVault = errors.New("not in the vault")

// Names of what the engine keeps in the vault.
const (
	vaultAccountKey = "account-key" // root of this sign-in's crypto state
	vaultIdentity   = "identity"    // the identity keys, sealed with the account key
	vaultSession    = "session"     // server, username and session token
)

// fileVault keeps each secret in its own 0600 file. It is what the terminal
// client uses, and gives no protection beyond the file's permissions.
type fileVault struct{ dir string }

func (v fileVault) path(name string) (string, error) {
	if !validVaultName(name) {
		return "", fmt.Errorf("invalid vault name %q", name)
	}
	return filepath.Join(v.dir, name), nil
}

func validVaultName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return name[0] != '.'
}

func (v fileVault) Get(name string) ([]byte, error) {
	p, err := v.path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotInVault
	}
	return b, err
}

func (v fileVault) Put(name string, value []byte) error {
	p, err := v.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(v.dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(p, value, 0o600)
}

func (v fileVault) Delete(name string) error {
	p, err := v.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// deriveKey derives a purpose-specific key from a root.
func deriveKey(root [32]byte, label string) [32]byte {
	var out [32]byte
	if _, err := io.ReadFull(hkdf.New(sha256.New, root[:], nil, []byte("GoMesh-"+label)), out[:]); err != nil {
		panic(err) // HKDF-SHA256 cannot fail for 32 bytes
	}
	return out
}

func sealBytes(key [32]byte, plain, aad []byte) ([]byte, error) {
	return common.Encrypt(key, plain, aad)
}

func unsealBytes(key [32]byte, sealed, aad []byte) ([]byte, error) {
	return common.Decrypt(key, sealed, aad)
}

// opaqueName names a file after an HMAC of what it holds: stable, and
// meaningless to anyone without the key.
func opaqueName(key [32]byte, name string) string {
	m := hmac.New(sha256.New, key[:])
	m.Write([]byte(name))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

func randomKey() ([32]byte, error) {
	var k [32]byte
	_, err := rand.Read(k[:])
	return k, err
}
