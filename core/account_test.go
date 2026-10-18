package core

import (
	"bytes"
	common "common"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// freshDataDir gives one test its own device directory.
func freshDataDir(t *testing.T) string {
	t.Helper()
	saved := tcl.dataDir
	tcl.dataDir = t.TempDir()
	t.Cleanup(func() { tcl.dataDir = saved })
	return tcl.dataDir
}

func TestWipeDeletesOnlyThisDevicesKeys(t *testing.T) {
	dir := freshDataDir(t)
	if err := tcl.openDevice(); err != nil {
		t.Fatal(err)
	}
	if err := tcl.saveSession("localhost:8080", "alice", [16]byte{1}, [common.SessionTokenSize]byte{2}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{legacyKeyFile, legacySessionFile, serversFileName, "client.log"} {
		os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600)
	}
	os.MkdirAll(filepath.Join(dir, legacyStateDir), 0o700)

	// Whatever sits in the working directory is the developer's, not the test's.
	cwdKey, cwdErr := os.ReadFile(legacyKeyFile)

	if err := tcl.wipeDeviceState(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{vaultAccountKey, vaultIdentity, vaultSession} {
		if _, err := tcl.secrets().Get(name); !errors.Is(err, ErrNotInVault) {
			t.Errorf("%s survived the wipe", name)
		}
	}
	for _, gone := range []string{stateDirName, legacyKeyFile, legacySessionFile, legacyStateDir} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s survived the wipe", gone)
		}
	}
	for _, kept := range []string{serversFileName, "client.log"} {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Errorf("%s was deleted, but it is not part of the device's keys", kept)
		}
	}
	after, afterErr := os.ReadFile(legacyKeyFile)
	if (cwdErr == nil) != (afterErr == nil) || !bytes.Equal(cwdKey, after) {
		t.Fatal("the wipe touched identity.key in the working directory")
	}
}

func TestSavedSessionIsPrivateAndRoundTrips(t *testing.T) {
	dir := freshDataDir(t)
	var id [16]byte
	var token [common.SessionTokenSize]byte
	id[0], token[5] = 1, 7
	if err := tcl.saveSession("localhost:8080", "alice", id, token); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, vaultDirName, vaultSession))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the vault's session file: %v %v", info, err)
	}
	s, err := tcl.loadSession()
	if err != nil || s == nil {
		t.Fatalf("load: %v", err)
	}
	got, err := s.token()
	if err != nil || got != token || s.Username != "alice" || s.Server != "localhost:8080" {
		t.Fatalf("session did not round trip: %+v %v", s, err)
	}
}

// An earlier version's session.json moves into the vault on first read.
func TestLegacySessionFileMovesIntoTheVault(t *testing.T) {
	dir := freshDataDir(t)
	legacy := `{"server":"localhost:8080","username":"alice","user_id":"01","token":"` + strings.Repeat("ab", 32) + `"}`
	os.WriteFile(filepath.Join(dir, legacySessionFile), []byte(legacy), 0o600)
	s, err := tcl.loadSession()
	if err != nil || s == nil || s.Username != "alice" {
		t.Fatalf("load: %+v %v", s, err)
	}
	if _, err := os.Stat(filepath.Join(dir, legacySessionFile)); !os.IsNotExist(err) {
		t.Fatal("session.json is still there")
	}
	if _, err := tcl.secrets().Get(vaultSession); err != nil {
		t.Fatal("the session did not reach the vault")
	}
}

// tlsListener accepts connections with a fresh certificate and returns its
// address and fingerprint.
func tlsListener(t *testing.T) (string, string) {
	t.Helper()
	certPEM, keyPEM, err := common.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cfg, fp, err := common.ServerTLSConfig(certPEM, keyPEM)
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
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				c.Read(make([]byte, 1))
			}()
		}
	}()
	return ln.Addr().String(), fp
}

func TestServerIsPinnedOnFirstUse(t *testing.T) {
	freshDataDir(t)
	t.Setenv("GOMESH_SERVER_FP", "")
	addr, fp := tlsListener(t)

	var shown string
	if _, err := tcl.connectTLS(addr, func(seen string) bool { shown = seen; return false }); err == nil {
		t.Fatal("connected although the user did not trust the certificate")
	}
	if shown != fp {
		t.Fatalf("the user was shown %s, the server's fingerprint is %s", shown, fp)
	}
	if tcl.loadPins()[addr] != "" {
		t.Fatal("a refused certificate was pinned")
	}

	c, err := tcl.connectTLS(addr, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if tcl.loadPins()[addr] != fp {
		t.Fatal("a trusted certificate was not pinned")
	}

	// Pinned now: no question asked the second time.
	c, err = tcl.connectTLS(addr, func(string) bool { t.Fatal("asked again about a pinned server"); return false })
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestAChangedCertificateIsRefused(t *testing.T) {
	freshDataDir(t)
	t.Setenv("GOMESH_SERVER_FP", "")
	addr, _ := tlsListener(t)
	_, otherFP := tlsListener(t)
	if err := tcl.savePin(addr, otherFP); err != nil {
		t.Fatal(err)
	}
	_, err := tcl.connectTLS(addr, func(string) bool { return true })
	if err == nil {
		t.Fatal("a server with a different certificate was accepted")
	}
	if !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

func TestPinFromEnvironment(t *testing.T) {
	freshDataDir(t)
	addr, fp := tlsListener(t)
	t.Setenv("GOMESH_SERVER_FP", common.FormatFingerprint(fp))
	c, err := tcl.connectTLS(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	_, otherFP := tlsListener(t)
	t.Setenv("GOMESH_SERVER_FP", otherFP)
	if _, err := tcl.connectTLS(addr, nil); err == nil {
		t.Fatal("GOMESH_SERVER_FP did not pin the server")
	}
}

// --- against the real server ---

// useConn points the client's global connection at a fresh TLS connection.
func useConn(t *testing.T, addr string) {
	t.Helper()
	tcl.conn = dialTLS(t, addr)
}

func TestE2ERefusalsComeBackTyped(t *testing.T) {
	addr := startServer(t)
	startClient(t, addr, "alice")

	useConn(t, addr)
	if _, _, err := tcl.performAuth(common.CtrlRegister, "alice", testPassword); errorCode(err) != common.ErrUsernameTaken {
		t.Fatalf("registering a taken name: %v", err)
	}
	useConn(t, addr)
	if _, _, err := tcl.performAuth(common.CtrlLogin, "alice", "the wrong password"); errorCode(err) != common.ErrBadCredentials {
		t.Fatalf("a wrong password: %v", err)
	}
	useConn(t, addr)
	if _, _, err := tcl.performAuth(common.CtrlRegister, "bob", ""); errorCode(err) != common.ErrWeakPassword {
		t.Fatalf("an empty password: %v", err)
	}
}

func TestE2EResumeWithTheSavedToken(t *testing.T) {
	addr := startServer(t)
	tcl.idMgr = newTestIdentity(t)

	useConn(t, addr)
	id, token, err := tcl.performAuth(common.CtrlRegister, "alice", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	useConn(t, addr)
	again, err := tcl.performResume(token, "alice")
	if err != nil || again != id {
		t.Fatalf("resume: %v", err)
	}
}

// When the account signs in on another device, the client under test is told,
// wipes its keys and leaves.
func TestE2EReplacedDeviceSignsOut(t *testing.T) {
	addr := startServer(t)
	freshDataDir(t)
	startClient(t, addr, "alice")
	tcl.secrets().Put(vaultAccountKey, make([]byte, 32))

	// alice signs in elsewhere with her password and new keys.
	phone := dialTLS(t, addr)
	im := newTestIdentity(t)
	body, _ := common.EncodeCredentials(&common.Credentials{Username: "alice", Password: testPassword, Bundle: im.Bundle()})
	(&common.Packet{Header: common.Header{MsgType: common.CtrlLogin, BodyLen: uint32(len(body))}, Body: body}).Encode(phone)
	ch, err := common.Decode(phone)
	if err != nil || ch.Header.MsgType != common.CtrlLoginChallenge {
		t.Fatalf("challenge: %v", err)
	}
	var nonce [common.LoginNonceSize]byte
	copy(nonce[:], ch.Body)
	sig := im.SignLogin(nonce, "alice")
	(&common.Packet{Header: common.Header{MsgType: common.CtrlLoginProof, BodyLen: common.SignatureSize}, Body: sig[:]}).Encode(phone)
	if ack, err := common.Decode(phone); err != nil || ack.Header.MsgType != common.CtrlLoginAck {
		t.Fatalf("the phone was not admitted: %v", err)
	}

	events := captureEvents(t)

	deadline := time.After(5 * time.Second)
	for {
		select {
		case pkt, ok := <-clientIn:
			if !ok {
				t.Fatal("the connection closed before the notice arrived")
			}
			if !tcl.signedOutBy(pkt) {
				continue
			}
			if !events.has(EventSignedOut) {
				t.Fatal("signed out without telling the host")
			}
			if _, err := tcl.secrets().Get(vaultAccountKey); !errors.Is(err, ErrNotInVault) {
				t.Fatal("the replaced device's keys were not deleted")
			}
			return
		case <-deadline:
			t.Fatal("the replaced device was never told")
		}
	}
}

// /logout deletes the keys before the server hears of it, so the server
// hanging up cannot beat the wipe, and the server is told.
func TestLogoutWipesThenTellsTheServer(t *testing.T) {
	freshDataDir(t)
	tcl.secrets().Put(vaultAccountKey, make([]byte, 32))
	sent := pipeConn(t)

	events := captureEvents(t)

	wipedFirst := make(chan bool, 1)
	go func() {
		pkt := <-sent
		_, err := tcl.secrets().Get(vaultAccountKey)
		wipedFirst <- pkt.Header.MsgType == common.CtrlLogout && errors.Is(err, ErrNotInVault) && tcl.leaving.Load()
	}()
	tcl.logout()

	select {
	case ok := <-wipedFirst:
		if !ok {
			t.Fatal("the server was told before the keys were deleted and the sign-out flagged")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the server was never sent CtrlLogout")
	}
	if !events.has(EventSignedOut) {
		t.Fatal("logout did not tell the host")
	}
}
