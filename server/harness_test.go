package main

import (
	common "common"
	"crypto/tls"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const testPassword = "correct horse battery staple"

// cheapAuth keeps password hashing fast and the limits out of the way, so the
// suite neither crawls nor trips over every test connecting from 127.0.0.1.
// Only the rate-limit tests run with real limits.
var cheapAuth = authConfig{
	Argon:        argonParams{Time: 1, MemoryKiB: 64, Threads: 1},
	IPAttempts:   1 << 20,
	IPWindow:     time.Minute,
	UserFailures: 1 << 20,
	UserWindow:   time.Minute,
	HashSlots:    8,
	HashWait:     5 * time.Second,
}

var testCert struct {
	once sync.Once
	cfg  *tls.Config
	fp   string
}

// serverTLS is one self-signed certificate for the whole test run.
func serverTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	testCert.once.Do(func() {
		certPEM, keyPEM, err := common.GenerateSelfSigned()
		if err != nil {
			panic(err)
		}
		testCert.cfg, testCert.fp, err = common.ServerTLSConfig(certPEM, keyPEM)
		if err != nil {
			panic(err)
		}
	})
	return testCert.cfg, testCert.fp
}

// dial connects over TLS, pinning the test certificate as a real client does.
func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	_, fp := serverTLS(t)
	cfg, err := common.PinnedTLSConfig(fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// startServer brings up a server on an OS-assigned port, with an in-memory
// database, and waits for it to accept. A fixed port silently breaks repeat
// runs: the second Start fails to bind, the error goes nowhere, and the test
// connects to the previous run's server instead of its own.
func startServer(t *testing.T) (*Server, string) {
	t.Helper()
	store, err := OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	return startServerOn(t, store, cheapAuth)
}

// startServerAt runs a server on a database file, for tests that restart it.
func startServerAt(t *testing.T, dir string) (*Server, string) {
	t.Helper()
	store, err := OpenStore(filepath.Join(dir, "gomesh.db"))
	if err != nil {
		t.Fatal(err)
	}
	return startServerOn(t, store, cheapAuth)
}

func startServerOn(t *testing.T, store *Store, auth authConfig) (*Server, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv, err := NewServer(store)
	if err != nil {
		t.Fatal(err)
	}
	srv.tls, _ = serverTLS(t)
	srv.auth = newAuthenticator(auth)
	exited := make(chan error, 1)
	go func() { exited <- srv.Start(addr) }()
	t.Cleanup(func() { srv.Close() })

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			t.Fatalf("server exited early: %v", err)
		default:
		}
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return srv, addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server never came up on %s", addr)
	return nil, ""
}

// sendCredentials opens with a CtrlRegister or CtrlLogin.
func sendCredentials(t *testing.T, c net.Conn, msgType uint8, name, password string, b *common.PreKeyBundle) {
	t.Helper()
	body, err := common.EncodeCredentials(&common.Credentials{Username: name, Password: password, Bundle: *b, DeviceName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&common.Packet{Header: common.Header{MsgType: msgType, BodyLen: uint32(len(body))}, Body: body}).Encode(c); err != nil {
		t.Fatalf("credentials: %v", err)
	}
}

// authAttempt registers or logs in, answering the challenge with seed, and
// returns the connection and the server's final reply: a CtrlLoginAck, a
// CtrlError, or a zero packet if it just hung up.
func authAttempt(t *testing.T, addr string, msgType uint8, name, password string, b *common.PreKeyBundle, seed [32]byte) (net.Conn, common.Packet) {
	t.Helper()
	c := dial(t, addr)
	sendCredentials(t, c, msgType, name, password, b)
	// The proof covers the username in its canonical form, as a real client signs it.
	if canon, err := common.NormalizeUsername(name); err == nil {
		name = canon
	}
	return c, answerChallenge(t, c, name, b, seed)
}

// resumeAttempt presents a session token instead of a password.
func resumeAttempt(t *testing.T, addr, name string, token [common.SessionTokenSize]byte, b *common.PreKeyBundle, seed [32]byte) (net.Conn, common.Packet) {
	t.Helper()
	c := dial(t, addr)
	body := common.EncodeResume(token, b)
	if err := (&common.Packet{Header: common.Header{MsgType: common.CtrlResume, BodyLen: uint32(len(body))}, Body: body}).Encode(c); err != nil {
		t.Fatal(err)
	}
	return c, answerChallenge(t, c, name, b, seed)
}

// register creates name and returns its connection, user ID and session token.
func register(t *testing.T, addr, name string, keyByte byte) (net.Conn, [16]byte, [common.SessionTokenSize]byte) {
	t.Helper()
	c, reply := authAttempt(t, addr, common.CtrlRegister, name, testPassword, testBundle(keyByte), testSeed(keyByte))
	id, token := ackOf(t, reply)
	return c, id, token
}

func ackOf(t *testing.T, reply common.Packet) ([16]byte, [common.SessionTokenSize]byte) {
	t.Helper()
	if reply.Header.MsgType != common.CtrlLoginAck {
		t.Fatalf("expected a login ack, got type %#x (%s)", reply.Header.MsgType, errCode(reply))
	}
	id, token, err := common.DecodeLoginAck(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

// errCode is the code a CtrlError carries, or ErrUnknown for anything else.
func errCode(p common.Packet) common.ErrorCode {
	if p.Header.MsgType != common.CtrlError {
		return common.ErrUnknown
	}
	e, err := common.DecodeError(p.Body)
	if err != nil {
		return common.ErrUnknown
	}
	return e.Code
}
