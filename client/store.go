package main

import (
	"bytes"
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

const stateExt = ".gob"

var validStateName = regexp.MustCompile(`^[a-z0-9-]+$`)

// StateStore keeps small gob-encoded records on disk, one file each, in a
// private directory next to the identity key. Every write goes through a
// temporary file that is synced and then renamed over the target, so a crash
// leaves either the old record or the new one and never a torn mixture.
//
// It exists so ratchet state survives a restart. The ratchet never rewinds, so
// a session restored from an older record would reissue message keys that were
// already used; callers therefore save before a ciphertext leaves the machine.
type StateStore struct {
	dir string
	mu  sync.Mutex
}

// OpenStateStore opens, creating if needed, the directory dir for the identity
// whose public key is owner. State belongs to one identity: it is the output of
// that identity's handshakes. If the directory was last used by a different one
// the records are meaningless, and are removed rather than left to be loaded
// into a session that can never decrypt anything.
func OpenStateStore(dir string, owner [32]byte) (*StateStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}
	s := &StateStore{dir: dir}

	// A crash between creating a temporary file and renaming it leaves debris.
	if stale, _ := filepath.Glob(filepath.Join(dir, ".tmp-*")); len(stale) > 0 {
		for _, f := range stale {
			os.Remove(f)
		}
	}

	ownerPath := filepath.Join(dir, "owner")
	want := []byte(hex.EncodeToString(owner[:]))
	have, err := os.ReadFile(ownerPath)
	switch {
	case err == nil && bytes.Equal(have, want):
		return s, nil
	case err == nil:
		log.Printf("[WARN] state in %s belongs to a different identity key; discarding it", dir)
		records, _ := filepath.Glob(filepath.Join(dir, "*"+stateExt))
		for _, f := range records {
			os.Remove(f)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}

	if err := writeFileAtomic(ownerPath, want, 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *StateStore) path(name string) (string, error) {
	if !validStateName.MatchString(name) {
		return "", fmt.Errorf("invalid state name %q", name)
	}
	return filepath.Join(s.dir, name+stateExt), nil
}

// Save atomically replaces the record called name with v.
func (s *StateStore) Save(name string, v any) error {
	path, err := s.path(name)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return fmt.Errorf("encoding %s: %w", name, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileAtomic(path, buf.Bytes(), 0o600)
}

// Load reads the record called name into v. A record that does not exist is
// reported as (false, nil); one that exists but cannot be decoded is an error,
// since discarding it would silently throw away key material.
func (s *StateStore) Load(name string, v any) (bool, error) {
	path, err := s.path(name)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(v); err != nil {
		return false, fmt.Errorf("decoding %s: %w", name, err)
	}
	return true, nil
}

// Delete removes the record called name. Removing one that is not there is not
// an error.
func (s *StateStore) Delete(name string) error {
	path, err := s.path(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.dir)
}

// List returns the names of the records whose name starts with prefix.
func (s *StateStore) List(prefix string) ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n, ok := strings.CutSuffix(e.Name(), stateExt)
		if ok && !e.IsDir() && strings.HasPrefix(n, prefix) {
			names = append(names, n)
		}
	}
	return names, nil
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
