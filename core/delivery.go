package core

import (
	common "common"
	"net"
	"sync"
	"time"
)

// The server keeps every packet it writes until this device says it has
// handled it, and delivers again on the next connection whatever was not
// acknowledged: a phone that is suspended or changes networks with packets
// unread loses nothing. The acknowledgement is a count of the packets handled
// on the connection, sent after a quiet moment, every ackEvery packets, and
// before the device closes the connection itself.

// Variables so tests can change them.
var (
	ackDelay = 250 * time.Millisecond
	ackEvery = uint64(64)
)

// acker acknowledges what one connection's read loop has handled.
type acker struct {
	cl   *Client
	conn net.Conn

	mu      sync.Mutex
	handled uint64 // packets read and handled on conn
	sent    uint64 // the count last acknowledged
	timer   *time.Timer
	stopped bool

	sendMu sync.Mutex // one acknowledgement at a time, so counts arrive in order
}

func newAcker(cl *Client, conn net.Conn) *acker { return &acker{cl: cl, conn: conn} }

// done counts one more packet handled.
func (a *acker) done() {
	a.mu.Lock()
	a.handled++
	due := a.handled-a.sent >= ackEvery
	if !due && a.timer == nil && !a.stopped {
		a.timer = time.AfterFunc(ackDelay, func() {
			a.mu.Lock()
			a.timer = nil
			a.mu.Unlock()
			a.flush()
		})
	}
	a.mu.Unlock()
	if due {
		a.flush()
	}
}

// flush acknowledges everything handled so far, if that is more than before
// and the connection is still the current one.
func (a *acker) flush() {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	a.mu.Lock()
	n := a.handled
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.mu.Unlock()
	if n <= a.sent {
		return
	}
	pkt := common.DeliveredPacket(n)
	a.cl.connLock.Lock()
	err := error(nil)
	if a.cl.conn == a.conn {
		err = pkt.Encode(a.conn)
	}
	a.cl.connLock.Unlock()
	if err == nil {
		a.mu.Lock()
		a.sent = n
		a.mu.Unlock()
	}
}

// stop ends the acker with its connection. What it had not acknowledged is
// delivered again on the next connection.
func (a *acker) stop() {
	a.mu.Lock()
	a.stopped = true
	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	a.mu.Unlock()
}

// Pause acknowledges what this device has handled, closes the connection and
// stops reconnecting until ReconnectNow. An iPhone app calls it on going to the
// background: iOS suspends the app and drops the socket anyway, and a clean
// close lets the server hold everything for the next connection rather than
// write it to a socket nobody reads.
func (cl *Client) Pause() {
	if cl.leaving.Load() || !cl.paused.CompareAndSwap(false, true) {
		return
	}
	if a := cl.acks.Load(); a != nil {
		a.flush()
	}
	cl.connLock.Lock()
	c := cl.conn
	cl.connLock.Unlock()
	if c != nil {
		c.Close() // the read loop ends, and the reconnect loop waits for ReconnectNow
	}
}

// Paused reports whether Pause is in effect.
func (cl *Client) Paused() bool { return cl.paused.Load() }
