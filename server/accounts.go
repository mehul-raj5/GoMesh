package main

import (
	common "common"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
	"unicode"
)

// errHungUp is a connection closed before it sent anything, which is how a
// client checks a server's certificate before signing in. Not worth a log line.
var errHungUp = errors.New("closed before logging in")

// session is what a successful login hands the connection.
type session struct {
	userID   [common.IDSize]byte
	deviceID [common.IDSize]byte
	username string
	token    [common.SessionTokenSize]byte
}

// refusal is a login failure the client is told about.
type refusal struct {
	code common.ErrorCode
	msg  string
	why  error // logged, never sent
}

func (r *refusal) Error() string {
	if r.why != nil {
		return fmt.Sprintf("%s (%v)", r.code, r.why)
	}
	return r.code.String()
}

func refuse(code common.ErrorCode, msg string, why error) *refusal {
	return &refusal{code: code, msg: msg, why: why}
}

// authenticate runs the login exchange on a new connection: register, password
// login or resume, each followed by the signed challenge. A refusal is sent to
// the client before it is returned.
func (s *Server) authenticate(conn net.Conn) (session, error) {
	sess, err := s.authenticateInner(conn)
	if err != nil {
		var r *refusal
		if errors.As(err, &r) {
			pkt := common.ErrorPacket(r.code, r.msg)
			pkt.Encode(conn)
		}
	}
	return sess, err
}

func (s *Server) authenticateInner(conn net.Conn) (session, error) {
	p, err := common.DecodeMax(conn, common.MaxPreAuthBody)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return session{}, errHungUp
		}
		return session{}, fmt.Errorf("first packet: %w", err)
	}
	ip := remoteIP(conn)

	switch p.Header.MsgType {
	case common.CtrlRegister, common.CtrlLogin:
		if !s.auth.allowIP(ip) {
			return session{}, refuse(common.ErrRateLimited, "", nil)
		}
		if p.Header.MsgType == common.CtrlRegister {
			return s.register(conn, p.Body)
		}
		return s.passwordLogin(conn, p.Body)
	case common.CtrlResume:
		// A resume never hashes a password and its token cannot be guessed, so it
		// has its own, much larger allowance: phones reconnect often, and many
		// share one carrier IP.
		if !s.auth.allowResume(ip) {
			return session{}, refuse(common.ErrRateLimited, "", nil)
		}
		return s.resume(conn, p.Body)
	default:
		return session{}, refuse(common.ErrBadRequest, "expected register, login or resume",
			fmt.Errorf("first packet was type %#x", p.Header.MsgType))
	}
}

func (s *Server) register(conn net.Conn, body []byte) (session, error) {
	creds, err := common.DecodeCredentials(body)
	if err != nil {
		return session{}, refuse(common.ErrBadRequest, "malformed registration", err)
	}
	name, err := common.NormalizeUsername(creds.Username)
	if err != nil {
		return session{}, refuse(common.ErrInvalidUsername, err.Error(), nil)
	}
	if err := common.CheckPassword(creds.Password, name); err != nil {
		return session{}, refuse(common.ErrWeakPassword, err.Error(), nil)
	}
	if !creds.Bundle.Verify() {
		return session{}, refuse(common.ErrBadRequest, "invalid prekey bundle", nil)
	}
	// Cheap early answer; the unique constraint settles a race for the name.
	if _, taken := s.getUserIDByName(name); taken {
		return session{}, refuse(common.ErrUsernameTaken, "", nil)
	}
	if err := s.proveKeyPossession(conn, name, creds.Bundle); err != nil {
		return session{}, refuse(common.ErrBadRequest, "login proof failed", err)
	}
	hash, err := s.auth.hash(creds.Password)
	if err != nil {
		return session{}, hashRefusal(err)
	}

	sess := session{userID: genID(), deviceID: genID(), username: name, token: newToken()}
	rec := userRecord{
		ID: sess.userID, Username: name, PasswordHash: hash, Bundle: creds.Bundle,
		DeviceID: sess.deviceID, DeviceName: deviceName(creds.DeviceName),
	}

	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	if err := s.store.CreateUser(rec, sess.token, time.Now()); err != nil {
		if errors.Is(err, errUsernameTaken) {
			return session{}, refuse(common.ErrUsernameTaken, "", nil)
		}
		return session{}, refuse(common.ErrInternal, "", err)
	}
	s.mu.Lock()
	s.users[rec.ID] = &User{
		ID: rec.ID, Username: name, IdentityKey: rec.Bundle.IdentityKey, Bundle: rec.Bundle,
		PasswordHash: hash, Device: &Device{ID: rec.DeviceID, Name: rec.DeviceName},
	}
	s.usernames[name] = rec.ID
	s.mu.Unlock()
	log.Printf("Registered %s", name)
	return sess, nil
}

func (s *Server) passwordLogin(conn net.Conn, body []byte) (session, error) {
	creds, err := common.DecodeCredentials(body)
	if err != nil {
		return session{}, refuse(common.ErrBadRequest, "malformed login", err)
	}
	// A name that could never have been registered is just a wrong username.
	name, err := common.NormalizeUsername(creds.Username)
	if err != nil {
		return session{}, refuse(common.ErrBadCredentials, "", err)
	}
	if s.auth.userLocked(name) {
		return session{}, refuse(common.ErrRateLimited, "", fmt.Errorf("%s is locked out", name))
	}

	s.mu.RLock()
	var hash string
	id, known := s.usernames[name]
	if u := s.users[id]; known && u != nil {
		hash = u.PasswordHash
	}
	s.mu.RUnlock()
	if !known || hash == "" {
		s.auth.failed(name)
		return session{}, refuse(common.ErrBadCredentials, "", fmt.Errorf("no account %s", name))
	}
	ok, err := s.auth.verify(creds.Password, hash)
	if err != nil {
		return session{}, hashRefusal(err)
	}
	if !ok {
		s.auth.failed(name)
		return session{}, refuse(common.ErrBadCredentials, "", fmt.Errorf("wrong password for %s", name))
	}
	s.auth.succeeded(name)

	if !creds.Bundle.Verify() {
		return session{}, refuse(common.ErrBadRequest, "invalid prekey bundle", nil)
	}
	if err := s.proveKeyPossession(conn, name, creds.Bundle); err != nil {
		return session{}, refuse(common.ErrBadRequest, "login proof failed", err)
	}

	sess := session{userID: id, username: name, token: newToken()}
	s.accountMu.Lock()
	defer s.accountMu.Unlock()

	s.mu.RLock()
	user := s.users[id]
	sameDevice := user.IdentityKey == creds.Bundle.IdentityKey && user.Bundle.SigningKey == creds.Bundle.SigningKey
	current := user.Device.ID
	s.mu.RUnlock()

	if sameDevice {
		// The device this account already uses, signing in again with its
		// password. It keeps its queue and gets a fresh token.
		if err := s.store.ReissueToken(id, current, creds.Bundle, sess.token, time.Now()); err != nil {
			return session{}, refuse(common.ErrInternal, "", err)
		}
		s.mu.Lock()
		user.Bundle = creds.Bundle
		s.mu.Unlock()
		sess.deviceID = current
		return sess, nil
	}

	sess.deviceID, err = s.replaceDevice(user, creds.Bundle, deviceName(creds.DeviceName), sess.token)
	if err != nil {
		return session{}, refuse(common.ErrInternal, "", err)
	}
	return sess, nil
}

// replaceDevice moves an account to new keys. Called with accountMu held.
//
// The order matters, and the in-memory part happens under one hold of s.mu so
// no packet can be queued in between:
//
//  1. the new device gets a new, empty queue;
//  2. the old device, and its queue with it, is dropped for good;
//  3. the old token is revoked as "replaced", which is what an old device that
//     is offline now learns when it next tries to resume;
//  4. if the old device is connected, it is sent DeviceReplaced through its own
//     write loop, fire and forget;
//  5. its connection then closes, and anything it still held is discarded,
//     because queueOffline drops packets for a device that no longer exists;
//  6. everyone who shares a conversation with the account is told its new keys.
func (s *Server) replaceDevice(user *User, bundle common.PreKeyBundle, name string,
	token [common.SessionTokenSize]byte) ([common.IDSize]byte, error) {
	newDev := &Device{ID: genID(), Name: name}

	s.mu.RLock()
	oldID := user.Device.ID
	s.mu.RUnlock()
	if err := s.store.ReplaceDevice(user.ID, oldID, newDev.ID, name, bundle, token, time.Now()); err != nil {
		return [common.IDSize]byte{}, err
	}

	s.mu.Lock()
	dropped := len(user.Device.Queue)
	user.Device = newDev
	user.Bundle = bundle
	user.IdentityKey = bundle.IdentityKey
	old := s.clients[user.ID]
	s.mu.Unlock()

	if old != nil && old.DeviceID == oldID {
		old.retire(common.ErrorPacket(common.ErrDeviceReplaced, "signed in on "+name))
	}
	log.Printf("%s moved to a new device (%s); %d queued packet(s) for the old one deleted", user.Username, name, dropped)

	// 6. Only now, with the old device gone, do its contacts hear of the new keys.
	s.broadcastKeyChange(user.ID)
	return newDev.ID, nil
}

func (s *Server) resume(conn net.Conn, body []byte) (session, error) {
	token, bundle, err := common.DecodeResume(body)
	if err != nil {
		return session{}, refuse(common.ErrBadRequest, "malformed resume", err)
	}
	userID, devID, reason, found, err := s.store.LookupToken(token)
	switch {
	case err != nil:
		return session{}, refuse(common.ErrInternal, "", err)
	case !found:
		return session{}, refuse(common.ErrSessionRevoked, "", errors.New("unknown token"))
	case reason == revokedReplaced:
		return session{}, refuse(common.ErrDeviceReplaced, "", nil)
	case reason != notRevoked:
		return session{}, refuse(common.ErrSessionRevoked, "", nil)
	}

	s.mu.RLock()
	user := s.users[userID]
	var name string
	var current [common.IDSize]byte
	var sameKeys bool
	if user != nil {
		name, current = user.Username, user.Device.ID
		sameKeys = user.IdentityKey == bundle.IdentityKey && user.Bundle.SigningKey == bundle.SigningKey
	}
	s.mu.RUnlock()
	switch {
	case user == nil:
		return session{}, refuse(common.ErrSessionRevoked, "", errors.New("token for a missing account"))
	case current != devID:
		return session{}, refuse(common.ErrDeviceReplaced, "", nil)
	case !sameKeys:
		// A token is only good for the keys it was issued to. New keys are a
		// device change, and that takes the password.
		return session{}, refuse(common.ErrPasswordRequired, "", nil)
	case !bundle.Verify():
		return session{}, refuse(common.ErrBadRequest, "invalid prekey bundle", nil)
	}
	if err := s.proveKeyPossession(conn, name, bundle); err != nil {
		return session{}, refuse(common.ErrBadRequest, "login proof failed", err)
	}

	s.accountMu.Lock()
	defer s.accountMu.Unlock()
	if err := s.store.Resumed(userID, devID, bundle, time.Now()); err != nil {
		return session{}, refuse(common.ErrInternal, "", err)
	}
	s.mu.Lock()
	user.Bundle = bundle
	s.mu.Unlock()
	return session{userID: userID, deviceID: devID, username: name, token: token}, nil
}

// logout ends the session c belongs to. Its token stops working; the device
// stays the account's current one until the account signs in somewhere.
func (s *Server) logout(c *Client) {
	s.accountMu.Lock()
	err := s.store.Revoke(c.DeviceID, revokedLogout, time.Now())
	s.accountMu.Unlock()
	if err != nil {
		log.Printf("[ERROR] logout for %s: %v", c.Username, err)
	}
	c.close()
}

func hashRefusal(err error) *refusal {
	if errors.Is(err, errBusy) {
		return refuse(common.ErrRateLimited, "server busy", err)
	}
	return refuse(common.ErrInternal, "", err)
}

func newToken() (t [common.SessionTokenSize]byte) {
	if _, err := rand.Read(t[:]); err != nil {
		panic(err)
	}
	return t
}

// deviceName keeps a client-chosen device label printable and short.
func deviceName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, strings.TrimSpace(s))
	if s == "" {
		return "unnamed device"
	}
	return s
}

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
