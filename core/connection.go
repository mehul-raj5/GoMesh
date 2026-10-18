package core

import (
	common "common"
	"errors"
	"log"
	"math/rand/v2"
	"time"
)

// Phones lose their connection all the time: the app goes to the background,
// the network changes, the server restarts. The engine reconnects on its own,
// resuming with the saved session over the pinned certificate, and backs off
// while it cannot. It never asks anything from the background: a server whose
// certificate is not pinned is not connected to, and a session that needs the
// password is handed to the host.

// ErrOffline means the client is not connected, so nothing was encrypted or sent.
var ErrOffline = errors.New("not connected to the server")

// Reconnect backoff. Variables so tests can shorten them.
var (
	reconnectMin = time.Second
	reconnectMax = 30 * time.Second
)

// online reports whether the client is connected and signed in.
func (cl *Client) online() bool { return cl.isOnline.Load() }

func (cl *Client) setState(s ConnState, text string) {
	cl.isOnline.Store(s == StateOnline)
	cl.emit(Event{Kind: EventConnection, State: s, Text: text})
}

// connectionLost runs when the read loop's connection fails. Unless the client
// is leaving, it starts reconnecting.
func (cl *Client) connectionLost(err error) {
	if cl.leaving.Load() {
		return
	}
	if cl.paused.Load() {
		cl.setState(StateConnecting, "")
	} else {
		log.Printf("[INFO] connection lost: %v", err)
		cl.setState(StateConnecting, "The connection to the server was lost; reconnecting.")
	}
	cl.spawn(cl.reconnect)
}

// spawn runs a read or reconnect loop that Close waits for.
func (cl *Client) spawn(loop func()) {
	cl.loops.Add(1)
	go func() {
		defer cl.loops.Done()
		loop()
	}()
}

// ReconnectNow cuts the current reconnect delay short, and ends a Pause: the
// app calls it when it comes to the foreground or the network comes back. It
// does nothing while the client is connected.
func (cl *Client) ReconnectNow() {
	cl.paused.Store(false)
	select {
	case cl.wake <- struct{}{}:
	default:
	}
}

// reconnect resumes the session until it works, the session turns out to be
// over, or the client is closed.
func (cl *Client) reconnect() {
	select { // a nudge from before the connection was lost is stale
	case <-cl.wake:
	default:
	}
	delay := cl.backoffMin
	warnedPin := false
	for {
		if cl.paused.Load() {
			// Paused: nothing until ReconnectNow, which connects at once.
			select {
			case <-cl.stop:
				return
			case <-cl.wake:
				delay = cl.backoffMin
			}
		} else {
			// Up to half the delay again, so clients that lost the same server do
			// not all come back in the same instant.
			wait := delay + time.Duration(rand.Int64N(int64(delay)/2+1))
			select {
			case <-cl.stop:
				return
			case <-cl.wake:
				delay = cl.backoffMin
			case <-time.After(wait):
			}
		}
		if cl.leaving.Load() {
			return
		}
		if cl.paused.Load() {
			continue
		}

		err := cl.resumeConnection()
		switch errorCode(err) {
		case common.ErrUnknown:
			if err == nil {
				return
			}
		case common.ErrDeviceReplaced:
			cl.signOut("This account signed in on another device. This device's keys have been deleted.")
			return
		case common.ErrSessionRevoked:
			cl.signOut("Your session ended. This device's keys have been deleted; sign in again.")
			return
		case common.ErrPasswordRequired:
			cl.setState(StateOffline, "")
			cl.emit(Event{Kind: EventPasswordRequired, Text: "Sign in again with your password."})
			return
		}
		if errors.Is(err, ErrNoSavedSession) || errors.Is(err, ErrUntrustedServer) {
			cl.setState(StateOffline, "")
			cl.emit(Event{Kind: EventPasswordRequired, Text: "Sign in again with your password."})
			return
		}
		// A certificate other than the pinned one may be a captive portal on a
		// public network, or someone in the middle; either way nothing is sent to
		// it, and the client keeps trying, but the person should know.
		if errors.Is(err, common.ErrPinMismatch) && !warnedPin {
			warnedPin = true
			cl.setState(StateConnecting, "The server presented a certificate this device does not trust. Still trying.")
		}
		log.Printf("[INFO] reconnect failed, retrying: %v", err)
		delay = min(2*delay, cl.backoffMax)
	}
}

// resumeConnection connects to the saved server and resumes the session. On
// success the read loop is running again.
func (cl *Client) resumeConnection() error {
	s, err := cl.loadSession()
	if err != nil {
		return err
	}
	if s == nil {
		return ErrNoSavedSession
	}
	token, err := s.token()
	if err != nil {
		return &common.ServerError{Code: common.ErrPasswordRequired, Message: err.Error()}
	}
	c, err := cl.connectTLS(s.Server, nil) // the pin only; never a question from the background
	if err != nil {
		return err
	}
	cl.setConn(c)
	id, err := cl.performResume(token, s.Username)
	if err != nil {
		c.Close()
		return err
	}
	if id != cl.mgr.UserID {
		c.Close()
		return errors.New("the server resumed a different account")
	}
	if cl.leaving.Load() {
		c.Close()
		return nil
	}
	cl.setState(StateOnline, "")
	cl.spawn(cl.readLoop)
	cl.afterConnect()
	if cl.paused.Load() {
		c.Close() // paused while connecting: the read loop ends, and waits for ReconnectNow
	}
	return nil
}

// SetReconnectDelayForTest sets the shortest reconnect delay for Clients made
// afterwards and returns the previous one. It is for other packages' tests.
func SetReconnectDelayForTest(d time.Duration) time.Duration {
	saved := reconnectMin
	reconnectMin = d
	return saved
}
