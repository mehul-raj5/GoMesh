package core

import (
	common "common"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A chat's record keeps its last message and how many from others are unread.
// Sending reads the chat; system lines neither count nor replace the preview.
func TestChatRecordsKeepPreviewAndUnread(t *testing.T) {
	h, dir := testHistory(t)
	a, err := historyFor(h, newMemVault(), filepath.Join(dir, mediaDirName), [16]byte{1}, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	conv := [16]byte{9}
	get := func() HistoryConversation {
		t.Helper()
		convs, err := a.conversations()
		if err != nil || len(convs) != 1 {
			t.Fatalf("conversations: %+v %v", convs, err)
		}
		return convs[0]
	}
	add := func(m HistoryMessage) {
		t.Helper()
		if _, err := a.append(conv, directPrefix+"bob", false, m); err != nil {
			t.Fatal(err)
		}
	}

	add(HistoryMessage{Text: "one", Time: time.Unix(1, 0)})
	add(HistoryMessage{Text: "two", Time: time.Unix(2, 0)})
	if c := get(); c.Unread != 2 || c.Preview != "two" || c.PreviewFromMe || c.Name != "bob" {
		t.Fatalf("after two incoming: %+v", c)
	}
	add(HistoryMessage{System: true, Text: "bob signed in on a new device", Time: time.Unix(3, 0)})
	if c := get(); c.Unread != 2 || c.Preview != "two" {
		t.Fatalf("a system line counted or replaced the preview: %+v", c)
	}
	add(HistoryMessage{Outgoing: true, Text: "my reply", Time: time.Unix(4, 0)})
	if c := get(); c.Unread != 0 || c.Preview != "my reply" || !c.PreviewFromMe {
		t.Fatalf("after replying: %+v", c)
	}
	add(HistoryMessage{Media: &MediaRef{FileName: "photo.jpg"}, Time: time.Unix(5, 0)})
	if c := get(); c.Unread != 1 || c.Preview != "photo.jpg" || !c.PreviewIsFile {
		t.Fatalf("after a file: %+v", c)
	}
	if err := a.markRead(conv); err != nil {
		t.Fatal(err)
	}
	if c := get(); c.Unread != 0 || c.Messages != 5 {
		t.Fatalf("after reading: %+v", c)
	}
	msgs, _ := a.messages(conv, 0, 10)
	if len(msgs) != 5 || !msgs[2].System || msgs[0].System {
		t.Fatalf("the system flag did not round-trip: %+v", msgs)
	}
}

// Rows and records written before previews and system lines existed still open,
// and pick up the new fields from the next message on.
func TestOlderHistoryRowsStillOpen(t *testing.T) {
	h, dir := testHistory(t)
	a, err := historyFor(h, newMemVault(), filepath.Join(dir, mediaDirName), [16]byte{1}, "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	conv := [16]byte{9}
	tag := a.tag(conv)

	// The shapes as Phase 4 wrote them.
	type oldMessage struct {
		Seq        int64
		ConvID     [16]byte
		Sender     [16]byte
		SenderName string
		Outgoing   bool
		Time       time.Time
		Text       string
		Media      *MediaRef
	}
	type oldRecord struct {
		Account  [16]byte
		ConvID   [16]byte
		Name     string
		IsGroup  bool
		Last     int64
		LastTime time.Time
	}
	plain, _ := gobBytes(oldMessage{Seq: 1, ConvID: conv, SenderName: "bob", Text: "from before", Time: time.Unix(1, 0)})
	sealed, _ := sealBytes(a.rowKey, plain, rowAAD(tag, 1))
	if _, err := h.db.Exec(`INSERT INTO messages (tag, seq, sealed) VALUES (?, 1, ?)`, tag, sealed); err != nil {
		t.Fatal(err)
	}
	plain, _ = gobBytes(oldRecord{Account: [16]byte{1}, ConvID: conv, Name: directPrefix + "bob", Last: 1, LastTime: time.Unix(1, 0)})
	sealed, _ = sealBytes(a.rowKey, plain, convAAD(tag))
	if _, err := h.db.Exec(`INSERT INTO conversations (tag, sealed) VALUES (?, ?)`, tag, sealed); err != nil {
		t.Fatal(err)
	}

	convs, err := a.conversations()
	if err != nil || len(convs) != 1 || convs[0].Name != "bob" || convs[0].Unread != 0 || convs[0].Messages != 1 {
		t.Fatalf("an old record: %+v %v", convs, err)
	}
	msgs, err := a.messages(conv, 0, 10)
	if err != nil || len(msgs) != 1 || msgs[0].Text != "from before" || msgs[0].System {
		t.Fatalf("an old row: %+v %v", msgs, err)
	}
	if _, err := a.append(conv, directPrefix+"bob", false, HistoryMessage{Text: "after", Time: time.Unix(2, 0)}); err != nil {
		t.Fatal(err)
	}
	convs, _ = a.conversations()
	if convs[0].Unread != 1 || convs[0].Preview != "after" || convs[0].Messages != 2 {
		t.Fatalf("an old record after a new message: %+v", convs[0])
	}
}

// OpenChat finds people, never resets a chat that works, and says why it
// cannot open one.
func TestOpenChat(t *testing.T) {
	srv := startServerProc(t)
	cl, rec := signedInClient(t, srv.addr, "alice")
	bob := dialParty(t, srv.addr, "bob")

	if _, err := cl.OpenChat("nobody"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("an unknown user: %v", err)
	}
	if _, err := cl.OpenChat("Alice"); !errors.Is(err, ErrChatWithSelf) {
		t.Fatalf("oneself: %v", err)
	}
	conv, err := cl.OpenChat("Bob")
	if err != nil || conv != common.HashIDs(cl.UserID(), bob.id) {
		t.Fatalf("opening: %x %v", conv, err)
	}
	if err := cl.SendText(conv, "first"); err != nil {
		t.Fatal(err)
	}
	if got := bob.readDM(5 * time.Second); got != "first" {
		t.Fatalf("bob read %q", got)
	}

	before, _ := cl.sessionMgr.GetSession(conv)
	n := rec.count()
	again, err := cl.OpenChat("bob")
	if err != nil || again != conv {
		t.Fatalf("opening again: %x %v", again, err)
	}
	if after, _ := cl.sessionMgr.GetSession(conv); after != before {
		t.Fatal("opening an existing chat replaced its session")
	}
	rec.mu.Lock()
	for _, ev := range rec.events[n:] {
		if ev.Kind == EventNotice && ev.ConvID == conv {
			t.Errorf("opening an existing chat said: %s", ev.Text)
		}
	}
	rec.mu.Unlock()

	if err := cl.SendText(conv, "second"); err != nil {
		t.Fatal(err)
	}
	if got := bob.readDM(5 * time.Second); got != "second" {
		t.Fatalf("bob read %q after reopening", got)
	}
	if cs := cl.Conversations(); len(cs) != 1 || cs[0].Name != "bob" {
		t.Fatalf("conversations: %+v", cs)
	}
}

// What changes in a chat is written into it, so it is there on the next start,
// and the host is told which chat it was.
func TestSystemLinesLandInTheirChat(t *testing.T) {
	srv := startServerProc(t)
	cl, rec := signedInClient(t, srv.addr, "alice")
	bob := dialParty(t, srv.addr, "bob")
	conv := bob.openDM("alice")
	bob.sendDM(conv, "hello")
	eventually(t, "the chat", keptText(cl, conv, "hello"))

	n := rec.count()
	loginParty(t, srv.addr, "bob") // bob moves
	ev := rec.waitFor(t, "the move", n, func(ev Event) bool {
		return ev.Kind == EventNotice && ev.ConvID == conv
	})
	_ = ev
	msgs, err := cl.HistoryMessages(cl.UserID(), conv, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var line *HistoryMessage
	for i := range msgs {
		if msgs[i].System {
			line = &msgs[i]
		}
	}
	if line == nil {
		t.Fatalf("no system line kept: %+v", msgs)
	}
	if strings.Contains(line.Text, "/safety") || !strings.Contains(line.Text, "bob") {
		t.Fatalf("system line: %q", line.Text)
	}
	list, err := cl.ChatList()
	if err != nil || len(list) != 1 || list[0].Preview != "hello" || list[0].Unread != 1 || list[0].Name != "bob" {
		t.Fatalf("chat list: %+v %v", list, err)
	}
}

// A queued group message is kept as queued, and its row says what became of it
// when the outbox is flushed; the host hears of the change. A full outbox takes
// nothing more.
func TestQueuedMessagesReportWhatBecameOfThem(t *testing.T) {
	freshDataDir(t)
	if err := tcl.openDevice(); err != nil {
		t.Fatal(err)
	}
	tcl.mgr = NewClientManager([16]byte{1}, "alice")
	tcl.sessionMgr = NewSessionManager(tcl.idMgr, [16]byte{1})
	if err := tcl.openHistory([16]byte{1}, "alice"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcl.hist.Close(); tcl.hist, tcl.myHistory = nil, nil; tcl.sink = nil })
	var events []Event
	tcl.sink = func(ev Event) { events = append(events, ev) }

	gid := [16]byte{7}
	tcl.mgr.RegisterConversation(gid, "team", true)
	held := HistoryMessage{Outgoing: true, Text: "waiting", Time: time.Now(), Status: StatusQueued}
	pkt := common.Packet{Header: common.Header{MsgType: common.MsgText, ConversationID: gid}, Body: []byte("waiting")}
	if err := tcl.queueOutbox(gid, pkt, func() int64 { return tcl.recordSeq(gid, held) }); err != nil {
		t.Fatal(err)
	}
	msgs, _ := tcl.HistoryMessages([16]byte{1}, gid, 0, 10)
	if len(msgs) != 1 || msgs[0].Status != StatusQueued {
		t.Fatalf("kept as: %+v", msgs)
	}

	// This client holds no state for the group, so the flush cannot seal it.
	tcl.flushOutbox(gid)
	msgs, _ = tcl.HistoryMessages([16]byte{1}, gid, 0, 10)
	if len(msgs) != 1 || msgs[0].Status != StatusFailed || msgs[0].Text != "waiting" {
		t.Fatalf("after the flush: %+v", msgs)
	}
	var told bool
	for _, ev := range events {
		if ev.Kind == EventMessageStatus && ev.ConvID == gid && ev.Seq == msgs[0].Seq && ev.Status == StatusFailed {
			told = true
		}
	}
	if !told {
		t.Fatal("the host was not told")
	}

	for i := 0; i < maxOutbox; i++ {
		if err := tcl.queueOutbox(gid, pkt, nil); err != nil {
			t.Fatal(err)
		}
	}
	kept := 0
	if err := tcl.queueOutbox(gid, pkt, func() int64 { kept++; return 0 }); !errors.Is(err, ErrOutboxFull) || kept != 0 {
		t.Fatalf("a full outbox: %v, kept %d", err, kept)
	}
	if err := tcl.myHistory.setStatus(gid, msgs[0].Seq, StatusSent); err != nil {
		t.Fatal(err)
	}
	if m, _ := tcl.HistoryMessages([16]byte{1}, gid, 0, 10); m[0].Status != StatusSent {
		t.Fatalf("setStatus: %+v", m[0])
	}
}

// Signing out keeps the history; signing back in on the same device brings the
// private chats back writable, though their sessions went with the old keys,
// and the first send reopens one.
func TestPrivateChatsComeBackWritable(t *testing.T) {
	srv := startServerProc(t)
	alice, rec := signedInClient(t, srv.addr, "alice")
	bob, _ := signedInClient(t, srv.addr, "bob")
	dm, err := alice.OpenChat("bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.SendText(dm, "before signing out"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob reading it", keptText(bob, dm, "before signing out"))

	n := rec.count()
	alice.Logout(false)
	rec.waitFor(t, "the sign-out", n, func(ev Event) bool { return ev.Kind == EventSignedOut })
	dir := alice.dataDir
	alice.Close()

	again, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.Login(srv.addr, "alice", testPassword); err != nil {
		t.Fatal(err)
	}
	list, err := again.ChatList()
	if err != nil || len(list) != 1 || list[0].ID != dm || list[0].ReadOnly || list[0].Name != "bob" {
		t.Fatalf("after signing back in: %+v %v", list, err)
	}
	if err := again.SendText(dm, "after signing back in"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob reading the reopened chat", keptText(bob, dm, "after signing back in"))
}

// A message still queued when the app stopped waited in memory and went with
// it; the next start marks it failed, and leaves sent ones alone.
func TestMessagesQueuedWhenTheAppStoppedAreMarkedNotSent(t *testing.T) {
	freshDataDir(t)
	if err := tcl.openDevice(); err != nil {
		t.Fatal(err)
	}
	tcl.mgr = NewClientManager([16]byte{1}, "alice")
	if err := tcl.openHistory([16]byte{1}, "alice"); err != nil {
		t.Fatal(err)
	}
	gid := [16]byte{7}
	sent := tcl.recordSeq(gid, HistoryMessage{Outgoing: true, Text: "went", Time: time.Now()})
	stuck := tcl.recordSeq(gid, HistoryMessage{Outgoing: true, Text: "stuck", Time: time.Now(), Status: StatusQueued})
	gone := tcl.recordSeq(gid, HistoryMessage{Outgoing: true, Text: "went later", Time: time.Now(), Status: StatusQueued})
	if err := tcl.myHistory.setStatus(gid, gone, StatusSent); err != nil {
		t.Fatal(err)
	}

	// The app stops, and starts again on the same history.
	tcl.hist.Close()
	tcl.hist, tcl.myHistory = nil, nil
	if err := tcl.openHistory([16]byte{1}, "alice"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcl.hist.Close(); tcl.hist, tcl.myHistory = nil, nil })
	msgs, _ := tcl.HistoryMessages([16]byte{1}, gid, 0, 10)
	want := map[int64]MessageStatus{sent: StatusSent, stuck: StatusFailed, gone: StatusSent}
	if len(msgs) != 3 {
		t.Fatalf("kept: %+v", msgs)
	}
	for _, m := range msgs {
		if m.Status != want[m.Seq] {
			t.Errorf("%q is %v, want %v", m.Text, m.Status, want[m.Seq])
		}
	}
	// Once is enough: nothing is left queued for the start after.
	if stale, err := tcl.myHistory.failQueued(); err != nil || len(stale) != 0 {
		t.Fatalf("a second pass found %v (%v)", stale, err)
	}
}
