package common

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
)

// tlsServer accepts one connection with the given certificate and completes the
// handshake, so a test can see whether the client accepted it.
func tlsServer(t *testing.T, certPEM, keyPEM []byte) string {
	t.Helper()
	cfg, _, err := ServerTLSConfig(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.(*tls.Conn).Handshake()
				c.Read(make([]byte, 1))
			}()
		}
	}()
	return ln.Addr().String()
}

func dialPinned(addr, pin string, seen func(string)) error {
	cfg, err := PinnedTLSConfig(pin, seen)
	if err != nil {
		return err
	}
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	return c.Close()
}

func TestPinnedTLSAcceptsOnlyThePinnedCertificate(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	_, fp, _ := ServerTLSConfig(certPEM, keyPEM)
	addr := tlsServer(t, certPEM, keyPEM)

	if err := dialPinned(addr, fp, nil); err != nil {
		t.Fatalf("the pinned certificate was refused: %v", err)
	}
	if err := dialPinned(addr, strings.ToUpper(FormatFingerprint(fp)), nil); err != nil {
		t.Fatalf("a pin written with spaces and capitals was refused: %v", err)
	}

	otherCert, otherKey, _ := GenerateSelfSigned()
	_, otherFP, _ := ServerTLSConfig(otherCert, otherKey)
	err = dialPinned(addr, otherFP, nil)
	if err == nil {
		t.Fatal("a server with a different certificate was accepted")
	}
	if !errors.Is(err, ErrPinMismatch) && !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("unexpected error for a wrong pin: %v", err)
	}
}

func TestPinnedTLSFailsClosed(t *testing.T) {
	cfg, err := PinnedTLSConfig(strings.Repeat("ab", 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("a connection with no peer certificate was accepted")
	}

	// No pin and nobody to show the fingerprint to: refuse rather than trust.
	certPEM, keyPEM, _ := GenerateSelfSigned()
	addr := tlsServer(t, certPEM, keyPEM)
	if err := dialPinned(addr, "", nil); err == nil {
		t.Fatal("an unpinned connection was accepted without anyone seeing the fingerprint")
	}

	if _, err := PinnedTLSConfig("not-a-fingerprint", nil); err == nil {
		t.Fatal("a malformed pin was accepted")
	}
}

func TestFirstUseReportsTheFingerprint(t *testing.T) {
	certPEM, keyPEM, _ := GenerateSelfSigned("192.168.1.20", "gomesh.local")
	_, want, _ := ServerTLSConfig(certPEM, keyPEM)
	addr := tlsServer(t, certPEM, keyPEM)

	var got string
	if err := dialPinned(addr, "", func(fp string) { got = fp }); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("first use reported %s, want %s", got, want)
	}
}

func TestPinnedTLSRefusesPlaintextServers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Write([]byte("not tls at all, just bytes on a socket\n"))
			c.Close()
		}
	}()
	if err := dialPinned(ln.Addr().String(), strings.Repeat("ab", 32), nil); err == nil {
		t.Fatal("a plaintext server was accepted")
	}
}
