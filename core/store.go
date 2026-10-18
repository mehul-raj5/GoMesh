package core

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var validStateName = regexp.MustCompile(`^[a-z0-9-]+$`)

// StateStore keeps small gob-encoded records on disk, one sealed file each.
// Every write goes through a temporary file that is synced and then renamed
// over the target, so a crash leaves either the old record or the new one and
// never a torn mixture.
//
// It exists so ratchet state survives a restart. The ratchet never rewinds, so
// a session restored from an older record would reissue message keys that were
// already used; callers therefore save before a ciphertext leaves the machine.
//
// Records are sealed under a key derived from the account key in the vault, and
// each file is named by an HMAC of the record's name. The seal is bound to that
// file name, and the record's real name travels inside it, so a listing says
// nothing about which chat a file is for, a file copied over another fails to
// open, and List can still find records by decrypting them. When the account
// key is deleted at sign-out, whatever is left here can never be read again.
type StateStore struct {
	dir   string
	key   [32]byte // seals records
	names [32]byte // names their files
	mu    sync.Mutex
}

// OpenStateStore opens, creating if needed, the directory dir, sealed under
// keys derived from root.
func OpenStateStore(dir string, root [32]byte) (*StateStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}
	// A crash between creating a temporary file and renaming it leaves debris.
	if stale, _ := filepath.Glob(filepath.Join(dir, ".tmp-*")); len(stale) > 0 {
		for _, f := range stale {
			os.Remove(f)
		}
	}
	return &StateStore{dir: dir, key: deriveKey(root, "state-seal-v1"), names: deriveKey(root, "state-names-v1")}, nil
}

func (s *StateStore) file(name string) (string, error) {
	if !validStateName.MatchString(name) {
		return "", fmt.Errorf("invalid state name %q", name)
	}
	return opaqueName(s.names, name), nil
}

func stateAAD(file string) []byte { return []byte("GoMesh-state-v1|" + file) }

// sealRecord lays a record out as [NameLen 2][Name][Data] and seals it.
func (s *StateStore) sealRecord(file, name string, data []byte) ([]byte, error) {
	plain := make([]byte, 0, 2+len(name)+len(data))
	plain = binary.BigEndian.AppendUint16(plain, uint16(len(name)))
	plain = append(plain, name...)
	plain = append(plain, data...)
	return sealBytes(s.key, plain, stateAAD(file))
}

// openRecord unseals a file and returns the record's name and data. The name is
// checked against the file it came from.
func (s *StateStore) openRecord(file string, sealed []byte) (string, []byte, error) {
	plain, err := unsealBytes(s.key, sealed, stateAAD(file))
	if err != nil {
		return "", nil, err
	}
	if len(plain) < 2 {
		return "", nil, errors.New("record too short")
	}
	n := int(binary.BigEndian.Uint16(plain))
	if len(plain) < 2+n {
		return "", nil, errors.New("record name truncated")
	}
	name := string(plain[2 : 2+n])
	if opaqueName(s.names, name) != file {
		return "", nil, errors.New("record is not the one its file name says")
	}
	return name, plain[2+n:], nil
}

// Save atomically replaces the record called name with v.
func (s *StateStore) Save(name string, v any) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return fmt.Errorf("encoding %s: %w", name, err)
	}
	return s.saveRaw(name, buf.Bytes())
}

func (s *StateStore) saveRaw(name string, data []byte) error {
	file, err := s.file(name)
	if err != nil {
		return err
	}
	sealed, err := s.sealRecord(file, name, data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileAtomic(filepath.Join(s.dir, file), sealed, 0o600)
}

// Load reads the record called name into v. A record that does not exist is
// reported as (false, nil); one that exists but cannot be opened or decoded is
// an error, and is left where it is: discarding it would silently throw away
// key material that may yet be readable.
func (s *StateStore) Load(name string, v any) (bool, error) {
	file, err := s.file(name)
	if err != nil {
		return false, err
	}
	sealed, err := os.ReadFile(filepath.Join(s.dir, file))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, data, err := s.openRecord(file, sealed)
	if err != nil {
		return false, fmt.Errorf("opening %s: %w", name, err)
	}
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(v); err != nil {
		return false, fmt.Errorf("decoding %s: %w", name, err)
	}
	return true, nil
}

// Delete removes the record called name. Removing one that is not there is not
// an error.
func (s *StateStore) Delete(name string) error {
	file, err := s.file(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(filepath.Join(s.dir, file)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.dir)
}

// List returns the names of the records whose name starts with prefix. Names
// are inside the seals, so every file is opened; one that will not open is
// logged and skipped, never deleted.
func (s *StateStore) List(prefix string) ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		sealed, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		name, _, err := s.openRecord(e.Name(), sealed)
		if err != nil {
			log.Printf("[WARN] state file %s does not open; leaving it: %v", e.Name(), err)
			continue
		}
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
}

// MigrateLegacy moves the plaintext records an earlier version kept in
// legacyDir (one name.gob file each, and an "owner" file naming the identity)
// into this store, sealed. Each record is written sealed and synced before its
// plaintext is deleted, so a crash leaves it in one place or both; if both, the
// sealed copy is kept. Records that belonged to another identity are deleted,
// as the old store did: they could never be used, and they are plaintext.
func (s *StateStore) MigrateLegacy(legacyDir string, owner [32]byte) (int, error) {
	entries, err := os.ReadDir(legacyDir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	ownerPath := filepath.Join(legacyDir, "owner")
	have, err := os.ReadFile(ownerPath)
	ours := err == nil && string(have) == hex.EncodeToString(owner[:])

	moved := 0
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".gob")
		if !ok || e.IsDir() {
			continue
		}
		path := filepath.Join(legacyDir, e.Name())
		if ours && validStateName.MatchString(name) {
			file, _ := s.file(name)
			if _, err := os.Stat(filepath.Join(s.dir, file)); errors.Is(err, os.ErrNotExist) {
				data, err := os.ReadFile(path)
				if err != nil {
					return moved, err
				}
				if err := s.saveRaw(name, data); err != nil {
					return moved, err
				}
				moved++
			}
		} else if !ours {
			log.Printf("[WARN] %s belongs to another identity; deleting it", path)
		}
		if err := os.Remove(path); err != nil {
			return moved, err
		}
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			os.Remove(filepath.Join(legacyDir, e.Name()))
		}
	}
	os.Remove(ownerPath)
	os.Remove(legacyDir) // only if empty
	return moved, nil
}

// writeFileAtomic writes data to path so that it is either fully there or not
// at all: the bytes go to a sibling file that is synced, renamed into place,
// and then the directory entry itself is synced.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}

	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}

// syncDir makes a rename or removal in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
