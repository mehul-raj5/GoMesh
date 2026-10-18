package core

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sample struct {
	Name string
	Key  [32]byte
	N    uint32
}

func openTestStore(t *testing.T, root byte) (*StateStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStateStore(dir, [32]byte{root})
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestStoreRoundTrip(t *testing.T) {
	s, _ := openTestStore(t, 1)
	want := sample{Name: "x", Key: [32]byte{1, 2, 3}, N: 9}
	if err := s.Save("session-ab", want); err != nil {
		t.Fatal(err)
	}
	var got sample
	ok, err := s.Load("session-ab", &got)
	if err != nil || !ok || got != want {
		t.Fatalf("load: ok=%v err=%v got=%+v", ok, err, got)
	}
}

func TestStoreMissingRecordIsNotAnError(t *testing.T) {
	s, _ := openTestStore(t, 1)
	var v sample
	if ok, err := s.Load("session-none", &v); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if err := s.Delete("session-none"); err != nil {
		t.Fatalf("deleting a missing record: %v", err)
	}
}

func TestStoreOverwriteReplacesAndLeavesNoDebris(t *testing.T) {
	s, dir := openTestStore(t, 1)
	for n := uint32(0); n < 5; n++ {
		if err := s.Save("session-ab", sample{N: n}); err != nil {
			t.Fatal(err)
		}
	}
	var got sample
	s.Load("session-ab", &got)
	if got.N != 4 {
		t.Fatalf("N = %d, want the last write", got.N)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files for one record", len(entries))
	}
}

func TestStoreFilesArePrivate(t *testing.T) {
	s, dir := openTestStore(t, 1)
	s.Save("session-ab", sample{})
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if info, _ := entries[0].Info(); info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v", info.Mode().Perm())
	}
}

// A folder listing names no record and no conversation, and no file holds
// anything readable.
func TestStoreFilesSayNothing(t *testing.T) {
	s, dir := openTestStore(t, 1)
	convID := [16]byte{0xAB, 0xCD, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	name := "session-" + hex.EncodeToString(convID[:])
	if err := s.Save(name, sample{Name: "a secret only in the record"}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "session") || strings.Contains(e.Name(), hex.EncodeToString(convID[:4])) {
			t.Fatalf("file name %q gives the record away", e.Name())
		}
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(b, []byte("a secret only")) || bytes.Contains(b, []byte(name)) {
			t.Fatal("a record is readable on disk")
		}
	}
}

// A file copied over another record's file does not open as that record.
func TestStoreSwappedFilesDoNotOpen(t *testing.T) {
	s, dir := openTestStore(t, 1)
	s.Save("session-aa", sample{N: 1})
	s.Save("session-bb", sample{N: 2})
	fa, _ := s.file("session-aa")
	fb, _ := s.file("session-bb")
	b, _ := os.ReadFile(filepath.Join(dir, fb))
	os.WriteFile(filepath.Join(dir, fa), b, 0o600)

	var v sample
	if ok, err := s.Load("session-aa", &v); ok || err == nil {
		t.Fatalf("a swapped file opened as the record it replaced: %+v", v)
	}
}

func TestStoreRefusesPathTricks(t *testing.T) {
	s, _ := openTestStore(t, 1)
	for _, name := range []string{"", "../escape", "a/b", "UPPER", "dot.name", "x y"} {
		if err := s.Save(name, sample{}); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
}

// A record that cannot be read is an error, not an empty result, and it is left
// where it is: treating it as absent would let the caller start a fresh session
// over key material that merely failed to open.
func TestStoreCorruptRecordIsAnErrorAndStays(t *testing.T) {
	s, dir := openTestStore(t, 1)
	s.Save("session-ab", sample{})
	file, _ := s.file("session-ab")
	os.WriteFile(filepath.Join(dir, file), []byte("not a sealed record at all, just bytes"), 0o600)
	var v sample
	if ok, err := s.Load("session-ab", &v); ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if names, err := s.List("session-"); err != nil || len(names) != 0 {
		t.Fatalf("list over a corrupt record: %v %v", names, err)
	}
	if _, err := os.Stat(filepath.Join(dir, file)); err != nil {
		t.Fatal("the unreadable record was deleted")
	}
}

func TestStoreListByPrefix(t *testing.T) {
	s, _ := openTestStore(t, 1)
	s.Save("session-aa", sample{})
	s.Save("session-bb", sample{})
	s.Save("prekeys", sample{})
	names, err := s.List("session-")
	if err != nil || len(names) != 2 {
		t.Fatalf("names=%v err=%v", names, err)
	}
}

// Under another root key nothing opens, nothing is found, and nothing is
// deleted either.
func TestStoreUnderAnotherKeyFindsNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, _ := OpenStateStore(dir, [32]byte{1})
	s.Save("session-ab", sample{N: 1})

	other, _ := OpenStateStore(dir, [32]byte{2})
	var v sample
	if ok, _ := other.Load("session-ab", &v); ok {
		t.Fatal("a record opened under another key")
	}
	if names, _ := other.List(""); len(names) != 0 {
		t.Fatalf("another key listed %v", names)
	}
	same, _ := OpenStateStore(dir, [32]byte{1})
	if ok, _ := same.Load("session-ab", &v); !ok || v.N != 1 {
		t.Fatal("the record did not survive being looked at under another key")
	}
}

func TestStoreClearsInterruptedWrites(t *testing.T) {
	s, dir := openTestStore(t, 1)
	s.Save("session-ab", sample{N: 3})
	os.WriteFile(filepath.Join(dir, ".tmp-123"), []byte("half"), 0o600)

	reopened, _ := OpenStateStore(dir, [32]byte{1})
	if _, err := os.Stat(filepath.Join(dir, ".tmp-123")); err == nil {
		t.Fatal("an interrupted write was left in place")
	}
	var v sample
	if ok, _ := reopened.Load("session-ab", &v); !ok || v.N != 3 {
		t.Fatal("the committed record was disturbed")
	}
}

// writeLegacy writes a record the way earlier versions did: plain gob in
// name.gob, next to an owner file naming the identity.
func writeLegacy(t *testing.T, dir string, owner [32]byte, name string, v any) {
	t.Helper()
	os.MkdirAll(dir, 0o700)
	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(v)
	os.WriteFile(filepath.Join(dir, name+".gob"), buf.Bytes(), 0o600)
	os.WriteFile(filepath.Join(dir, "owner"), []byte(hex.EncodeToString(owner[:])), 0o600)
}

func TestLegacyStateIsSealedAndRemoved(t *testing.T) {
	s, _ := openTestStore(t, 1)
	legacy := filepath.Join(t.TempDir(), legacyStateDir)
	owner := [32]byte{9}
	writeLegacy(t, legacy, owner, "session-ab", sample{N: 5})
	writeLegacy(t, legacy, owner, "prekeys", sample{N: 6})

	n, err := s.MigrateLegacy(legacy, owner)
	if err != nil || n != 2 {
		t.Fatalf("moved %d: %v", n, err)
	}
	var v sample
	if ok, _ := s.Load("session-ab", &v); !ok || v.N != 5 {
		t.Fatal("the record did not survive the move")
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("the plaintext directory is still there")
	}
}

// A move interrupted after the sealed write leaves both; the sealed copy, which
// may be newer, is kept.
func TestLegacyStateNeverOverwritesSealed(t *testing.T) {
	s, _ := openTestStore(t, 1)
	legacy := filepath.Join(t.TempDir(), legacyStateDir)
	owner := [32]byte{9}
	s.Save("session-ab", sample{N: 7})
	writeLegacy(t, legacy, owner, "session-ab", sample{N: 5})

	if _, err := s.MigrateLegacy(legacy, owner); err != nil {
		t.Fatal(err)
	}
	var v sample
	if s.Load("session-ab", &v); v.N != 7 {
		t.Fatalf("the plaintext copy (N=5) replaced the sealed one: N=%d", v.N)
	}
	if _, err := os.Stat(filepath.Join(legacy, "session-ab.gob")); !os.IsNotExist(err) {
		t.Fatal("the plaintext copy is still there")
	}
}

func TestLegacyStateOfAnotherIdentityIsDeleted(t *testing.T) {
	s, _ := openTestStore(t, 1)
	legacy := filepath.Join(t.TempDir(), legacyStateDir)
	writeLegacy(t, legacy, [32]byte{9}, "session-ab", sample{N: 5})

	if n, err := s.MigrateLegacy(legacy, [32]byte{8}); err != nil || n != 0 {
		t.Fatalf("moved %d: %v", n, err)
	}
	var v sample
	if ok, _ := s.Load("session-ab", &v); ok {
		t.Fatal("another identity's record was taken in")
	}
	if _, err := os.Stat(filepath.Join(legacy, "session-ab.gob")); !os.IsNotExist(err) {
		t.Fatal("another identity's plaintext record was left behind")
	}
}
