package core

import (
	common "common"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (cl *Client) dataPath(name string) string { return filepath.Join(cl.dataDir, name) }

const (
	legacySessionFile = "session.json" // where earlier versions kept the session
	serversFileName   = "servers.json"
)

// savedSession lets the next start resume without the password.
type savedSession struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	UserID   string `json:"user_id"`
	Token    string `json:"token"`
}

func (s *savedSession) token() ([common.SessionTokenSize]byte, error) {
	var t [common.SessionTokenSize]byte
	b, err := hex.DecodeString(s.Token)
	if err != nil || len(b) != len(t) {
		return t, errors.New("saved session token is malformed")
	}
	copy(t[:], b)
	return t, nil
}

// loadSession reads the saved session from the vault. One an earlier version
// left in session.json is moved into the vault first.
func (cl *Client) loadSession() (*savedSession, error) {
	data, err := cl.secrets().Get(vaultSession)
	if errors.Is(err, ErrNotInVault) {
		legacy, lerr := os.ReadFile(cl.dataPath(legacySessionFile))
		if errors.Is(lerr, os.ErrNotExist) {
			return nil, nil
		}
		if lerr != nil {
			return nil, lerr
		}
		if err := cl.secrets().Put(vaultSession, legacy); err != nil {
			return nil, fmt.Errorf("moving the session into the vault: %w", err)
		}
		if err := os.Remove(cl.dataPath(legacySessionFile)); err != nil {
			return nil, err
		}
		data, err = legacy, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the vault: %w", err)
	}
	var s savedSession
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("reading the saved session: %w", err)
	}
	return &s, nil
}

func (cl *Client) saveSession(server, username string, userID [16]byte, token [common.SessionTokenSize]byte) error {
	data, err := json.Marshal(savedSession{
		Server: server, Username: username,
		UserID: hex.EncodeToString(userID[:]), Token: hex.EncodeToString(token[:]),
	})
	if err != nil {
		return err
	}
	return cl.secrets().Put(vaultSession, data)
}

// loadPins returns the certificate fingerprint pinned for each server address.
func (cl *Client) loadPins() map[string]string {
	pins := map[string]string{}
	if data, err := os.ReadFile(cl.dataPath(serversFileName)); err == nil {
		json.Unmarshal(data, &pins)
	}
	return pins
}

func (cl *Client) savePin(addr, fingerprint string) error {
	pins := cl.loadPins()
	pins[addr] = fingerprint
	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(cl.dataPath(serversFileName), data, 0o600)
}

// ErrUntrustedServer means the server's certificate is not pinned and nobody
// confirmed it, so nothing was sent to it.
var ErrUntrustedServer = errors.New("server certificate not trusted")

// pinFor returns the fingerprint pinned for addr. GOMESH_SERVER_FP, if set,
// overrides the saved pins.
func (cl *Client) pinFor(addr string) string {
	if pin := os.Getenv("GOMESH_SERVER_FP"); pin != "" {
		return pin
	}
	return cl.loadPins()[addr]
}

// connectTLS dials addr over TLS and accepts only the certificate pinned for
// it. With no pin yet, confirm is shown the fingerprint and decides; a yes pins
// it for next time. Close cancels a dial in progress.
func (cl *Client) connectTLS(addr string, confirm func(fingerprint string) bool) (net.Conn, error) {
	pin := cl.pinFor(addr)
	if pin != "" {
		cfg, err := common.PinnedTLSConfig(pin, nil)
		if err != nil {
			return nil, err
		}
		c, err := cl.dialTLS(addr, cfg)
		if errors.Is(err, common.ErrPinMismatch) {
			return nil, fmt.Errorf("%w\nIf the server's certificate really was replaced, remove %q from %s and connect again", err, addr, cl.dataPath(serversFileName))
		}
		return c, err
	}

	var seen string
	cfg, err := common.PinnedTLSConfig("", func(fp string) { seen = fp })
	if err != nil {
		return nil, err
	}
	c, err := cl.dialTLS(addr, cfg)
	if err != nil {
		return nil, err
	}
	if confirm == nil || !confirm(seen) {
		c.Close()
		return nil, ErrUntrustedServer
	}
	if err := cl.savePin(addr, seen); err != nil {
		log.Printf("[WARN] could not save the server's fingerprint: %v", err)
	}
	return c, nil
}

func (cl *Client) dialTLS(addr string, cfg *tls.Config) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		select {
		case <-cl.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	return d.DialContext(ctx, "tcp", addr)
}

// ServerFingerprint connects to addr and returns its certificate's
// fingerprint, and whether that is the one this device already trusts. A server
// presenting a certificate other than the pinned one is an ErrPinMismatch.
// Nothing is pinned here: an app shows the fingerprint, and TrustServer pins
// exactly the one it showed.
func (cl *Client) ServerFingerprint(addr string) (fingerprint string, pinned bool, err error) {
	if pin := cl.pinFor(addr); pin != "" {
		c, err := cl.connectTLS(addr, nil)
		if err != nil {
			return "", false, err
		}
		c.Close()
		fp, err := common.NormalizeFingerprint(pin)
		return fp, true, err
	}
	var seen string
	cfg, err := common.PinnedTLSConfig("", func(fp string) { seen = fp })
	if err != nil {
		return "", false, err
	}
	c, err := cl.dialTLS(addr, cfg)
	if err != nil {
		return "", false, err
	}
	c.Close()
	return seen, false, nil
}

// TrustServer pins fingerprint for addr, once the person has compared it. A
// server already pinned to another certificate keeps its pin: ForgetServer
// first, deliberately.
func (cl *Client) TrustServer(addr, fingerprint string) error {
	fp, err := common.NormalizeFingerprint(fingerprint)
	if err != nil {
		return err
	}
	if old := cl.loadPins()[addr]; old != "" {
		if prev, _ := common.NormalizeFingerprint(old); prev != fp {
			return fmt.Errorf("%w: %s is pinned to another certificate", common.ErrPinMismatch, addr)
		}
		return nil
	}
	return cl.savePin(addr, fp)
}

// ForgetServer removes the pin for addr, so the next connection asks again.
func (cl *Client) ForgetServer(addr string) error {
	pins := cl.loadPins()
	if _, ok := pins[addr]; !ok {
		return nil
	}
	delete(pins, addr)
	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(cl.dataPath(serversFileName), data, 0o600)
}

// deviceLabel names this device to the server.
func (cl *Client) deviceLabel() string {
	if cl.deviceName != "" {
		return cl.deviceName
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown host"
	}
	return strings.TrimSuffix(host, ".local")
}

// performAuth registers (kind CtrlRegister) or logs in (CtrlLogin) on conn and
// returns the user ID and session token. A refusal comes back as a
// *common.ServerError.
func (cl *Client) performAuth(kind uint8, username, password string) ([16]byte, [common.SessionTokenSize]byte, error) {
	// The login proof covers the canonical form of the name, which is what the
	// server verifies against, so every caller is normalized here.
	username = canonicalUsername(username)
	body, err := common.EncodeCredentials(&common.Credentials{
		Username: username, Password: password, Bundle: cl.idMgr.Bundle(), DeviceName: cl.deviceLabel(),
	})
	if err != nil {
		return [16]byte{}, [common.SessionTokenSize]byte{}, err
	}
	if err := cl.sendPacket(&common.Packet{Header: common.Header{MsgType: kind, BodyLen: uint32(len(body))}, Body: body}); err != nil {
		return [16]byte{}, [common.SessionTokenSize]byte{}, err
	}
	return cl.finishLogin(username)
}

// performResume signs in with a saved session token instead of the password.
func (cl *Client) performResume(token [common.SessionTokenSize]byte, username string) ([16]byte, error) {
	username = canonicalUsername(username)
	bundle := cl.idMgr.Bundle()
	body := common.EncodeResume(token, &bundle)
	if err := cl.sendPacket(&common.Packet{Header: common.Header{MsgType: common.CtrlResume, BodyLen: uint32(len(body))}, Body: body}); err != nil {
		return [16]byte{}, err
	}
	id, _, err := cl.finishLogin(username)
	return id, err
}

// finishLogin answers the server's challenge with a signature from the identity
// signing key and reads the result.
func (cl *Client) finishLogin(username string) ([16]byte, [common.SessionTokenSize]byte, error) {
	var id [16]byte
	var token [common.SessionTokenSize]byte

	challenge, err := common.DecodeMax(cl.conn, common.MaxPreAuthBody)
	if err != nil {
		return id, token, err
	}
	if challenge.Header.MsgType == common.CtrlError {
		return id, token, serverError(challenge)
	}
	if challenge.Header.MsgType != common.CtrlLoginChallenge || len(challenge.Body) != common.LoginNonceSize {
		return id, token, fmt.Errorf("unexpected login challenge: type %d", challenge.Header.MsgType)
	}
	var nonce [common.LoginNonceSize]byte
	copy(nonce[:], challenge.Body)

	sig := cl.idMgr.SignLogin(nonce, username)
	proof := common.Packet{
		Header: common.Header{MsgType: common.CtrlLoginProof, BodyLen: common.SignatureSize},
		Body:   sig[:],
	}
	if err := cl.sendPacket(&proof); err != nil {
		return id, token, err
	}

	resp, err := common.Decode(cl.conn)
	if err != nil {
		return id, token, err
	}
	if resp.Header.MsgType == common.CtrlError {
		return id, token, serverError(resp)
	}
	if resp.Header.MsgType != common.CtrlLoginAck {
		return id, token, fmt.Errorf("unexpected login response: type %d", resp.Header.MsgType)
	}
	return common.DecodeLoginAck(resp.Body)
}

// canonicalUsername returns the form the server stores and verifies proofs
// against. A name that fails the rules is passed through; the server refuses it.
func canonicalUsername(name string) string {
	if canon, err := common.NormalizeUsername(name); err == nil {
		return canon
	}
	return name
}

func serverError(p common.Packet) error {
	e, err := common.DecodeError(p.Body)
	if err != nil {
		return fmt.Errorf("unreadable error from the server: %w", err)
	}
	return e
}

func errorCode(err error) common.ErrorCode {
	var se *common.ServerError
	if errors.As(err, &se) {
		return se.Code
	}
	return common.ErrUnknown
}

// wipeDeviceState deletes this device's keys, its saved sessions and its
// session token: everything that made it the account's device. The account key
// goes first, so whatever is left of the rest, in flash or anywhere else, can
// never be opened again. The servers it trusts, the history and its keys,
// received files and the log stay.
func (cl *Client) wipeDeviceState() error {
	var errs []error
	for _, name := range []string{vaultAccountKey, vaultIdentity, vaultSession} {
		if err := cl.secrets().Delete(name); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.RemoveAll(cl.dataPath(stateDirName)); err != nil {
		errs = append(errs, err)
	}
	// And whatever an earlier version kept in plaintext.
	for _, name := range []string{legacyKeyFile, legacySessionFile} {
		if err := os.Remove(cl.dataPath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := os.RemoveAll(cl.dataPath(legacyStateDir)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// signOut wipes this device and tells the host. It runs when the server says
// the account moved to another device or the session ended.
func (cl *Client) signOut(reason string) {
	cl.beginSignOut()
	cl.emit(Event{Kind: EventSignedOut, Text: reason})
}

// logout signs out at the user's request. The flag is set and the keys deleted
// before the server hears of it: the server hangs up as soon as it does, and
// readLoop must already know that is expected.
func (cl *Client) logout() {
	cl.beginSignOut()
	if err := cl.sendPacket(&common.Packet{Header: common.Header{MsgType: common.CtrlLogout}}); err != nil {
		log.Printf("[WARN] could not tell the server about the logout: %v", err)
	}
	cl.emit(Event{Kind: EventSignedOut, Text: "Signed out. This device's keys have been deleted."})
}

func (cl *Client) beginSignOut() {
	cl.leaving.Store(true)
	if err := cl.wipeDeviceState(); err != nil {
		log.Printf("[ERROR] wiping device state: %v", err)
	}
}

// signedOutBy reports whether pkt ends this device's session, and if so signs out.
func (cl *Client) signedOutBy(pkt common.Packet) bool {
	if pkt.Header.MsgType != common.CtrlError {
		return false
	}
	e, err := common.DecodeError(pkt.Body)
	if err != nil {
		return false
	}
	switch e.Code {
	case common.ErrDeviceReplaced:
		cl.signOut("This account signed in on another device. This device's keys have been deleted.")
		return true
	case common.ErrSessionRevoked:
		cl.signOut("Your session ended. This device's keys have been deleted; sign in again.")
		return true
	}
	return false
}
