package core

import (
	"bytes"
	common "common"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testHistory(t *testing.T) (*history, string) {
	t.Helper()
	dir := t.TempDir()
	h, err := openHistory(filepath.Join(dir, historyFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h, dir
}

func TestHistoryKeepsMessagesInOrderAndPages(t *testing.T) {
	h, dir := testHistory(t)
	a, err := historyFor(h, newMemVault(), filepath.Join(dir, mediaDirName), [16]byte{1}, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	conv := [16]byte{9}
	for i := 0; i < 5; i++ {
		if _, err := a.append(conv, "bob", false, HistoryMessage{Text: string(rune('a' + i)), Time: time.Unix(int64(i), 0)}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := a.messages(conv, 0, 100)
	if err != nil || len(all) != 5 || all[0].Text != "a" || all[4].Text != "e" || all[4].Seq != 5 {
		t.Fatalf("messages: %+v %v", all, err)
	}
	page, _ := a.messages(conv, 4, 2) // the two before seq 4
	if len(page) != 2 || page[0].Text != "b" || page[1].Text != "c" {
		t.Fatalf("page: %+v", page)
	}
	convs, _ := a.conversations()
	if len(convs) != 1 || convs[0].Name != "bob" || convs[0].Messages != 5 {
		t.Fatalf("conversations: %+v", convs)
	}
}

// Two accounts on one device who chatted with each other share a conversation
// ID; each still has its own rows, and neither can read the other's.
func TestAccountsOnOneDeviceKeepSeparateHistories(t *testing.T) {
	h, dir := testHistory(t)
	v := newMemVault()
	alice, bob := [16]byte{1}, [16]byte{2}
	conv := common.HashIDs(alice, bob)
	a, _ := historyFor(h, v, filepath.Join(dir, mediaDirName), alice, "alice", true)
	b, _ := historyFor(h, v, filepath.Join(dir, mediaDirName), bob, "bob", true)
	a.append(conv, "bob", false, HistoryMessage{Text: "from alice's side"})
	b.append(conv, "alice", false, HistoryMessage{Text: "from bob's side"})

	am, _ := a.messages(conv, 0, 10)
	bm, _ := b.messages(conv, 0, 10)
	if len(am) != 1 || am[0].Text != "from alice's side" || len(bm) != 1 || bm[0].Text != "from bob's side" {
		t.Fatalf("alice %+v, bob %+v", am, bm)
	}
	if ac, _ := a.conversations(); len(ac) != 1 {
		t.Fatalf("alice sees %d conversations", len(ac))
	}
	accts, _ := historyAccounts(v)
	if len(accts) != 2 {
		t.Fatalf("accounts: %+v", accts)
	}
}

// Rows are bound to their place: swapped, they do not open.
func TestHistoryRowsCannotBeSwapped(t *testing.T) {
	h, dir := testHistory(t)
	a, _ := historyFor(h, newMemVault(), filepath.Join(dir, mediaDirName), [16]byte{1}, "alice", true)
	conv := [16]byte{9}
	a.append(conv, "bob", false, HistoryMessage{Text: "first"})
	a.append(conv, "bob", false, HistoryMessage{Text: "second"})
	var s1, s2 []byte
	h.db.QueryRow(`SELECT sealed FROM messages WHERE seq = 1`).Scan(&s1)
	h.db.QueryRow(`SELECT sealed FROM messages WHERE seq = 2`).Scan(&s2)
	h.db.Exec(`UPDATE messages SET sealed = ? WHERE seq = 1`, s2)
	h.db.Exec(`UPDATE messages SET sealed = ? WHERE seq = 2`, s1)
	if _, err := a.messages(conv, 0, 10); err == nil {
		t.Fatal("swapped rows opened")
	}
}

func TestAnUnreadableVaultDoesNotStartAFreshHistory(t *testing.T) {
	h, dir := testHistory(t)
	v := newMemVault()
	v.failGet = errLocked
	if _, err := historyFor(h, v, filepath.Join(dir, mediaDirName), [16]byte{1}, "alice", true); err == nil {
		t.Fatal("a history key was made although the vault could not be read")
	}
	if v.puts != 0 {
		t.Fatal("something was written over a vault that could not be read")
	}
}

func TestMediaIsKeptSealed(t *testing.T) {
	h, dir := testHistory(t)
	a, _ := historyFor(h, newMemVault(), filepath.Join(dir, mediaDirName), [16]byte{1}, "alice", true)
	secret := []byte("the contents of a file nobody should read off the disk")
	id, err := a.storeMedia(secret)
	if err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(filepath.Join(dir, mediaDirName, id))
	if bytes.Contains(onDisk, secret[:20]) {
		t.Fatal("the file is readable on disk")
	}
	got, err := a.openMedia(id)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open: %v", err)
	}
	if _, err := a.openMedia("../../etc/passwd"); err == nil {
		t.Fatal("a path was taken for a media ID")
	}
}

// Sign-out deletes the keys but keeps the history readable; deleting the
// history deletes its rows, its files and its key.
func TestHistoryOutlivesSignOutUntilDeleted(t *testing.T) {
	freshDataDir(t)
	if err := tcl.openDevice(); err != nil {
		t.Fatal(err)
	}
	tcl.mgr = NewClientManager([16]byte{1}, "alice")
	if err := tcl.openHistory([16]byte{1}, "alice"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcl.hist.Close(); tcl.hist, tcl.myHistory = nil, nil })
	conv := [16]byte{9}
	tcl.mgr.RegisterConversation(conv, "Private Chat: bob", false)
	tcl.record(conv, HistoryMessage{Text: "kept after sign-out"})
	id, _ := tcl.myHistory.storeMedia([]byte("a kept file"))

	if err := tcl.wipeDeviceState(); err != nil {
		t.Fatal(err)
	}
	tcl.myHistory = nil
	msgs, err := tcl.HistoryMessages([16]byte{1}, conv, 0, 10)
	if err != nil || len(msgs) != 1 || msgs[0].Text != "kept after sign-out" {
		t.Fatalf("after sign-out: %+v %v", msgs, err)
	}

	if err := tcl.DeleteHistory([16]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tcl.HistoryMessages([16]byte{1}, conv, 0, 10); err == nil {
		t.Fatal("the history is readable after it was deleted")
	}
	if _, err := tcl.secrets().Get(historyKeyName([16]byte{1})); !errors.Is(err, ErrNotInVault) {
		t.Fatal("the history key survived deleting the history")
	}
	if _, err := os.Stat(tcl.dataPath(filepath.Join(mediaDirName, id))); !os.IsNotExist(err) {
		t.Fatal("a kept file survived deleting the history")
	}
	if accts, _ := tcl.HistoryAccounts(); len(accts) != 0 {
		t.Fatalf("the account is still listed: %+v", accts)
	}
}

// The done criterion for at-rest encryption, checked: after a session with a
// direct chat, a group, a key change and a file, nothing the engine keeps names
// a conversation or a person, or holds a message, a username or a group name.
// The vault stands in for the Keychain and is outside the check, as are the
// terminal client's log and downloads.
func TestNothingAtRestIsReadable(t *testing.T) {
	addr := startServer(t)
	serverPinsMu.Lock()
	pin := serverPins[addr]
	serverPinsMu.Unlock()

	dir := t.TempDir()
	var mu sync.Mutex
	var seen []Event
	cl, err := New(Config{DataDir: dir, OnEvent: func(ev Event) { mu.Lock(); seen = append(seen, ev); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.CheckServer(addr, func(fp string) bool { return fp == pin }); err != nil {
		t.Fatal(err)
	}
	const me, them, group = "aliceliddell", "bobbyfischer", "Midnight Gardeners"
	const dmText, groupText, myText = "the eagle has landed", "pickled walnuts at dawn", "a reply nobody should find"
	if err := cl.Register(addr, me, testPassword); err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	bob := dialParty(t, addr, them)
	convID := bob.openDM(me)
	bob.sendDM(convID, dmText)
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("never got %s", what)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	kept := func(conv [16]byte, text string) func() bool {
		return func() bool {
			msgs, _ := cl.HistoryMessages(cl.UserID(), conv, 0, 50)
			for _, m := range msgs {
				if m.Text == text {
					return true
				}
			}
			return false
		}
	}
	waitFor("bob's message in the history", kept(convID, dmText))
	if err := cl.SendText(convID, myText); err != nil {
		t.Fatal(err)
	}
	bob.readDM(5 * time.Second)

	gid := genID()
	sc := common.SignChange(bob.sm.identity.SigningSeed, common.GroupChange{
		GroupID: gid, Version: 1, Action: common.ActionCreate, Actor: bob.id, Timestamp: time.Now().Unix(),
		Targets: []common.MemberKey{keyOf(bob), {ID: cl.UserID(), IdentityKey: cl.idMgr.PublicKey, SigningKey: cl.idMgr.SigningKey}},
	})
	body := (&common.GroupChangeBody{Name: group, Change: sc}).Encode()
	bob.send(&common.Packet{Header: common.Header{MsgType: common.CtrlGroupCreate, BodyLen: uint32(len(body))}, Body: body})
	bob.follow(5 * time.Second)
	waitFor("the group", func() bool { return cl.IsGroup(gid) })
	bob.sendGroupText(gid, groupText)
	waitFor("the group message in the history", kept(gid, groupText))

	loginParty(t, addr, them) // bob moves: a key change
	waitFor("the key change", func() bool {
		k, _ := cl.mgr.GetPublicKey(bob.id)
		return k != bob.pub
	})
	if _, err := cl.myHistory.storeMedia([]byte("a kept file: " + dmText)); err != nil {
		t.Fatal(err)
	}
	cl.Close()

	myID := cl.UserID()
	ids := [][]byte{myID[:], bob.id[:], convID[:], gid[:]}
	var forbiddenNames []string
	for _, id := range ids {
		forbiddenNames = append(forbiddenNames, hex.EncodeToString(id), hex.EncodeToString(id[:4]))
	}
	forbiddenText := []string{dmText, groupText, myText, me, them, group}

	checked := 0
	for _, root := range []string{stateDirName, historyFile, historyFile + "-wal", historyFile + "-shm", mediaDirName} {
		filepath.Walk(filepath.Join(dir, root), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			checked++
			for _, f := range forbiddenNames {
				if strings.Contains(info.Name(), f) {
					t.Errorf("%s is named after an ID", path)
				}
			}
			b, _ := os.ReadFile(path)
			for _, f := range forbiddenText {
				if bytes.Contains(b, []byte(f)) {
					t.Errorf("%s contains %q", path, f)
				}
			}
			return nil
		})
	}
	if checked < 4 {
		t.Fatalf("only %d files were checked; the session did not leave the state expected", checked)
	}
}
