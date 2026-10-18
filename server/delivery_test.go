package main

import (
	common "common"
	"net"
	"sync"
	"testing"
	"time"
)

// The tests' raw connections count what they read after signing in, as a real
// client does, so that they can acknowledge it.
var (
	readsMu sync.Mutex
	reads   = map[net.Conn]uint64{}
)

// decode reads one packet and counts it against its connection.
func decode(c net.Conn) (common.Packet, error) {
	p, err := common.Decode(c)
	if err == nil {
		readsMu.Lock()
		reads[c]++
		readsMu.Unlock()
	}
	return p, err
}

// acknowledge tells the server that u has handled everything it has read on
// its connection, and waits until the server has taken it in.
func acknowledge(t *testing.T, srv *Server, u *user) {
	t.Helper()
	readsMu.Lock()
	n := reads[u.conn]
	readsMu.Unlock()
	ack := common.DeliveredPacket(n)
	if err := ack.Encode(u.conn); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.RLock()
		c := srv.conns[u.conn]
		srv.mu.RUnlock()
		if c == nil {
			// The server's end of the connection is a different net.Conn; find it by user.
			srv.mu.RLock()
			c = srv.clients[u.id]
			srv.mu.RUnlock()
		}
		if c != nil {
			c.ackMu.Lock()
			done := c.acked >= n
			c.ackMu.Unlock()
			if done {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the server never took in %s's acknowledgement of %d packets", u.name, n)
}

// dropConn closes u's connection and waits for the server to finish with it.
func dropConn(t *testing.T, srv *Server, u *user) {
	t.Helper()
	u.conn.Close()
	waitGone(t, srv, u.id)
}

// A packet the device read but never acknowledged is sent again on its next
// connection, whether it was live or waiting in the queue; once acknowledged,
// it is not.
func TestUnacknowledgedPacketsAreSentAgain(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")

	sendText(t, alice.conn, convID, "live")
	if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != "live" {
		t.Fatalf("bob read %q", got.Body)
	}
	dropConn(t, srv, bob)
	if n := queueRows(t, srv.store); n != 1 {
		t.Fatalf("%d rows after a live packet went unacknowledged, want 1", n)
	}
	sendText(t, alice.conn, convID, "queued")
	time.Sleep(50 * time.Millisecond)

	relogin(t, addr, bob)
	for _, want := range []string{"live", "queued"} {
		if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != want {
			t.Fatalf("bob read %q, want %q", got.Body, want)
		}
	}
	// Read again and still not acknowledged: kept, without new rows.
	dropConn(t, srv, bob)
	if n := queueRows(t, srv.store); n != 2 {
		t.Fatalf("%d rows, want 2", n)
	}

	relogin(t, addr, bob)
	for _, want := range []string{"live", "queued"} {
		if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != want {
			t.Fatalf("bob read %q, want %q", got.Body, want)
		}
	}
	acknowledge(t, srv, bob)
	if n := queueRows(t, srv.store); n != 0 {
		t.Fatalf("%d rows after the acknowledgement", n)
	}
	dropConn(t, srv, bob)
	relogin(t, addr, bob)
	expectNo(t, bob.conn, common.MsgText, 300*time.Millisecond)
}

// A reply belongs to the connection that asked; the next one does not get it.
func TestAnUnacknowledgedReplyIsNotSentAgain(t *testing.T) {
	srv, addr := startServer(t)
	newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	openDM(t, bob.conn, "alice") // a CtrlDirectAck, read and not acknowledged
	dropConn(t, srv, bob)
	if n := queueRows(t, srv.store); n != 0 {
		t.Fatalf("%d rows after a reply went unacknowledged", n)
	}
	relogin(t, addr, bob)
	expectNo(t, bob.conn, common.CtrlDirectAck, 300*time.Millisecond)
}

// A device that comes back before the server has noticed its old connection
// is gone still gets what the old one had not had acknowledged.
func TestAReconnectGetsWhatTheDeadConnectionHeld(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")
	sendText(t, alice.conn, convID, "in flight")
	readUntil(t, bob.conn, common.MsgText, 3*time.Second)

	old := bob.conn // not closed: the server still counts it as connected
	relogin(t, addr, bob)
	defer old.Close()
	if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != "in flight" {
		t.Fatalf("bob read %q", got.Body)
	}
	_ = srv
}

// The server stops writing to a device that has too much unacknowledged, picks
// up again when it acknowledges, and gives up on one that never does.
func TestTheServerWaitsForAcknowledgements(t *testing.T) {
	savedMax, savedTimeout := maxUnacked, ackTimeout
	maxUnacked, ackTimeout = 3, 400*time.Millisecond
	t.Cleanup(func() { maxUnacked, ackTimeout = savedMax, savedTimeout })

	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")
	acknowledge(t, srv, bob) // what bob has read so far, so the window is empty
	for _, m := range []string{"1", "2", "3", "4", "5"} {
		sendText(t, alice.conn, convID, m)
	}
	for _, want := range []string{"1", "2", "3"} {
		if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != want {
			t.Fatalf("bob read %q, want %q", got.Body, want)
		}
	}
	expectNo(t, bob.conn, common.MsgText, 150*time.Millisecond)
	acknowledge(t, srv, bob)
	for _, want := range []string{"4", "5"} {
		if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != want {
			t.Fatalf("bob read %q, want %q", got.Body, want)
		}
	}

	// Never acknowledged: after ackTimeout the connection is closed, and the
	// packets wait for the next one.
	for _, m := range []string{"6", "7", "8", "9"} {
		sendText(t, alice.conn, convID, m)
	}
	awaitClosed(t, bob.conn, 3*time.Second)
	waitGone(t, srv, bob.id)
	relogin(t, addr, bob)
	for _, want := range []string{"4", "5", "6", "7", "8", "9"} {
		if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != want {
			t.Fatalf("after reconnecting bob read %q, want %q", got.Body, want)
		}
		acknowledge(t, srv, bob)
	}
}

// The read loop can outlive the write loop by a moment: an acknowledgement that
// arrives after the connection put its packets back changes nothing.
func TestAnAcknowledgementAfterTheRequeueIsIgnored(t *testing.T) {
	srv := newTestServer(t)
	u, dev := testUser(srv, "bob")
	c := newClient(closedConn(), u.ID, dev.ID, "bob")
	c.track(queued{pkt: textPacket("one")})
	c.track(queued{pkt: textPacket("two")})
	srv.requeueUnacked(c)
	srv.acknowledge(c, common.DeliveredPacket(2).Body) // must not panic
	srv.mu.RLock()
	n := len(dev.Queue)
	srv.mu.RUnlock()
	if n != 2 {
		t.Fatalf("%d packets queued after the late acknowledgement, want 2", n)
	}
}

// An acknowledgement for more than was written, or less than before, is ignored.
func TestABadAcknowledgementChangesNothing(t *testing.T) {
	srv, addr := startServer(t)
	alice := newUser(t, addr, "alice", 1)
	bob := newUser(t, addr, "bob", 2)
	convID, _ := openDM(t, alice.conn, "bob")
	sendText(t, alice.conn, convID, "kept")
	readUntil(t, bob.conn, common.MsgText, 3*time.Second)
	for _, n := range []uint64{1 << 40} {
		if err := (func() *common.Packet { p := common.DeliveredPacket(n); return &p }()).Encode(bob.conn); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	dropConn(t, srv, bob)
	relogin(t, addr, bob)
	if got := readUntil(t, bob.conn, common.MsgText, 3*time.Second); string(got.Body) != "kept" {
		t.Fatalf("bob read %q", got.Body)
	}
}
