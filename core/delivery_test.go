package core

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// logBuffer collects what the engine logs during a test, as well as passing it on.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.buf.String(), sub)
}

func captureLog(t *testing.T) *logBuffer {
	l := &logBuffer{}
	log.SetOutput(io.MultiWriter(os.Stderr, l))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return l
}

func countText(cl *Client, conv [16]byte, text string) int {
	msgs, _ := cl.HistoryMessages(cl.UserID(), conv, 0, 200)
	n := 0
	for _, m := range msgs {
		if m.Text == text {
			n++
		}
	}
	return n
}

// A paused device is not connected and does not try to be; what was sent to
// it meanwhile arrives once it comes back.
func TestAPausedDeviceGetsEverythingWhenItComesBack(t *testing.T) {
	fastReconnect(t, 50*time.Millisecond)
	srv := startServerProc(t)
	alice, _ := signedInClient(t, srv.addr, "alice")
	bob, rec := signedInClient(t, srv.addr, "bob")
	dm, err := alice.OpenChat("bob")
	if err != nil {
		t.Fatal(err)
	}
	gid, err := alice.CreateGroup("team", []string{"bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.SendText(dm, "before"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob reading the chat", keptText(bob, dm, "before"))
	eventually(t, "bob in the group", func() bool { return bob.IsGroup(gid) })

	n := rec.count()
	bob.Pause()
	rec.waitFor(t, "bob's connection closing", n, isState(StateConnecting))
	time.Sleep(300 * time.Millisecond) // several reconnect delays: none may be tried
	if bob.online() || !bob.Paused() {
		t.Fatal("a paused client reconnected")
	}
	for _, m := range []string{"while paused 1", "while paused 2"} {
		if err := alice.SendText(dm, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := alice.SendText(gid, "group while paused"); err != nil {
		t.Fatal(err)
	}

	n = rec.count()
	bob.ReconnectNow()
	rec.waitFor(t, "bob back online", n, isState(StateOnline))
	eventually(t, "the direct messages", keptText(bob, dm, "while paused 2"))
	eventually(t, "the group message", keptText(bob, gid, "group while paused"))
	if bob.Paused() {
		t.Fatal("still paused")
	}
}

// A connection that drops after its messages were read but before they were
// acknowledged loses nothing: the server sends them again, and the device keeps
// one copy of each.
func TestADroppedConnectionLosesNothingAndDuplicatesNothing(t *testing.T) {
	fastReconnect(t, 50*time.Millisecond)
	savedDelay, savedEvery := ackDelay, ackEvery
	ackDelay, ackEvery = time.Hour, 1<<40 // read, never acknowledged
	t.Cleanup(func() { ackDelay, ackEvery = savedDelay, savedEvery })

	srv := startServerProc(t)
	alice, _ := signedInClient(t, srv.addr, "alice")
	bob, rec := signedInClient(t, srv.addr, "bob")
	dm, err := alice.OpenChat("bob")
	if err != nil {
		t.Fatal(err)
	}
	gid, err := alice.CreateGroup("team", []string{"bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.SendText(dm, "direct"); err != nil {
		t.Fatal(err)
	}
	if err := alice.SendText(gid, "grouped"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "bob reading both", func() bool {
		return keptText(bob, dm, "direct")() && keptText(bob, gid, "grouped")()
	})

	// The network goes: the socket closes under the client, unacknowledged.
	logs := captureLog(t)
	n := rec.count()
	bob.connLock.Lock()
	bob.conn.Close()
	bob.connLock.Unlock()
	n = rec.waitFor(t, "bob noticing", n, isState(StateConnecting))
	rec.waitFor(t, "bob back", n, isState(StateOnline))

	// Everything comes again; give it time to be read, then count.
	if err := alice.SendText(dm, "after"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the next message", keptText(bob, dm, "after"))
	time.Sleep(200 * time.Millisecond)
	for _, c := range []struct {
		conv [16]byte
		text string
	}{{dm, "direct"}, {gid, "grouped"}, {dm, "after"}} {
		if got := countText(bob, c.conv, c.text); got != 1 {
			t.Errorf("%q kept %d times", c.text, got)
		}
	}
	// The server did send them again, and the engine dropped the copies.
	if got := logs.count("Dropping packet"); got < 2 {
		t.Errorf("%d packets dropped as already read; the redelivery never happened", got)
	}
	msgs, _ := bob.HistoryMessages(bob.UserID(), dm, 0, 200)
	for _, m := range msgs {
		if m.System && strings.Contains(strings.ToLower(m.Text), "session") {
			t.Errorf("the redelivery disturbed the chat: %q", m.Text)
		}
	}
}
