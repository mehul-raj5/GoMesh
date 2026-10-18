package bridge

import (
	common "common"
	"context"
	"core"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
)

// Error is every error the bridge returns. Its text is JSON,
// {"code":"...","message":"..."}, which is what reaches the app as the
// NSError's description; Message is fit to show.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return mustJSON(e) }

// The codes an Error carries.
const (
	codeBadRequest       = "bad_request"
	codeBadCredentials   = "bad_credentials"
	codeUsernameTaken    = "username_taken"
	codeInvalidUsername  = "invalid_username"
	codeWeakPassword     = "weak_password"
	codeRateLimited      = "rate_limited"
	codeSessionRevoked   = "session_revoked"
	codeDeviceReplaced   = "device_replaced"
	codePasswordRequired = "password_required"
	codeServerError      = "server_error"
	codeOffline          = "offline"
	codeUnreachable      = "unreachable"
	codeUntrustedServer  = "untrusted_server"
	codePinMismatch      = "pin_mismatch"
	codeNoSavedSession   = "no_saved_session"
	codeVault            = "vault"
	codeClosed           = "closed"
	codeSignedOut        = "signed_out"
	codeNotSignedIn      = "not_signed_in"
	codeAlreadySignedIn  = "already_signed_in"
	codeUserNotFound     = "user_not_found"
	codeChatWithSelf     = "chat_with_self"
	codeOutboxFull       = "outbox_full"
	codeNoGroupName      = "no_group_name"
	codeFileTooLarge     = "file_too_large"
	codeInternal         = "internal"
)

func codeError(code, message string) *Error { return &Error{Code: code, Message: message} }

var serverCodes = map[common.ErrorCode]string{
	common.ErrBadRequest:       codeBadRequest,
	common.ErrBadCredentials:   codeBadCredentials,
	common.ErrUsernameTaken:    codeUsernameTaken,
	common.ErrInvalidUsername:  codeInvalidUsername,
	common.ErrWeakPassword:     codeWeakPassword,
	common.ErrRateLimited:      codeRateLimited,
	common.ErrSessionRevoked:   codeSessionRevoked,
	common.ErrDeviceReplaced:   codeDeviceReplaced,
	common.ErrPasswordRequired: codePasswordRequired,
	common.ErrInternal:         codeServerError,
}

var serverMessages = map[common.ErrorCode]string{
	common.ErrBadRequest:       "The server didn't understand that request.",
	common.ErrBadCredentials:   "Wrong username or password.",
	common.ErrUsernameTaken:    "That username is taken.",
	common.ErrInvalidUsername:  "Usernames are 3 to 32 letters, digits, dots, dashes or underscores.",
	common.ErrWeakPassword:     "Enter a password.",
	common.ErrRateLimited:      "Too many attempts. Try again in a little while.",
	common.ErrSessionRevoked:   "Your session ended. Sign in again.",
	common.ErrDeviceReplaced:   "This account signed in on another device. Sign in again to use it here.",
	common.ErrPasswordRequired: "Sign in again with your password.",
	common.ErrInternal:         "Something went wrong on the server.",
}

// wrap turns an engine error into an *Error. It is the one place codes are
// decided.
func wrap(err error) error {
	if err == nil {
		return nil
	}
	var be *Error
	if errors.As(err, &be) {
		return be
	}
	var se *common.ServerError
	if errors.As(err, &se) {
		code, ok := serverCodes[se.Code]
		if !ok {
			return codeError(codeServerError, "The server refused: "+se.Error())
		}
		msg := serverMessages[se.Code]
		if se.Code == common.ErrInvalidUsername || se.Code == common.ErrWeakPassword || se.Code == common.ErrBadRequest {
			if se.Message != "" { // the server says what exactly was wrong
				msg = se.Message
			}
		}
		return codeError(code, msg)
	}
	var ve *vaultError
	switch {
	case errors.As(err, &ve):
		return codeError(codeVault, "This device's keychain could not be used: "+ve.err.Error())
	case errors.Is(err, core.ErrOffline):
		return codeError(codeOffline, "You're offline. Nothing was sent.")
	case errors.Is(err, core.ErrUserNotFound):
		return codeError(codeUserNotFound, "There's nobody with that username.")
	case errors.Is(err, core.ErrChatWithSelf):
		return codeError(codeChatWithSelf, "That's you. Pick someone else to chat with.")
	case errors.Is(err, core.ErrFileTooLarge):
		return codeError(codeFileTooLarge, "Files can be at most 50 MB.")
	case errors.Is(err, core.ErrNoGroupName):
		return codeError(codeNoGroupName, "Give the group a name.")
	case errors.Is(err, core.ErrOutboxFull):
		return codeError(codeOutboxFull, "Too many messages are already waiting to go to this group. Try again once they've gone.")
	case errors.Is(err, core.ErrAlreadySignedIn):
		return codeError(codeAlreadySignedIn, "This device is already signed in. Sign out first.")
	case errors.Is(err, core.ErrNoSavedSession):
		return codeError(codeNoSavedSession, "There's no saved session on this device.")
	case errors.Is(err, core.ErrUntrustedServer):
		return codeError(codeUntrustedServer, "This server's certificate isn't trusted yet.")
	case errors.Is(err, common.ErrPinMismatch):
		return codeError(codePinMismatch, "The server's certificate doesn't match the one this device trusts. If its operator really replaced it, forget the server under Advanced and check the new fingerprint.")
	}
	var recordErr tls.RecordHeaderError
	var netErr net.Error
	var opErr *net.OpError
	if errors.As(err, &netErr) || errors.As(err, &opErr) || errors.As(err, &recordErr) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, net.ErrClosed) {
		return codeError(codeUnreachable, "Couldn't reach a GoMesh server at that address.")
	}
	return codeError(codeInternal, err.Error())
}

// ErrorCode returns the code of an error the bridge returned, or "" if it is
// not one. The app does the same by decoding the error's text.
func ErrorCode(text string) string {
	var e Error
	if json.Unmarshal([]byte(text), &e) != nil {
		return ""
	}
	return e.Code
}

// vaultError is an error from the app's vault, kept apart so it is never
// mistaken for anything else.
type vaultError struct{ err error }

func (e *vaultError) Error() string { return "vault: " + e.err.Error() }
func (e *vaultError) Unwrap() error { return e.err }

// vaultAdapter gives the engine the app's vault. Empty data from Get is an
// item that is not there, which is the one case the engine may create keys
// for; every error stays an error.
type vaultAdapter struct{ v Vault }

func (a vaultAdapter) Get(name string) ([]byte, error) {
	b, err := a.v.Get(name)
	if err != nil {
		return nil, &vaultError{err}
	}
	if len(b) == 0 {
		return nil, core.ErrNotInVault
	}
	return b, nil
}

func (a vaultAdapter) Put(name string, value []byte) error {
	if len(value) == 0 { // empty means absent, so it cannot be stored
		return &vaultError{errors.New("refusing to store an empty item")}
	}
	if err := a.v.Put(name, value); err != nil {
		return &vaultError{err}
	}
	return nil
}

func (a vaultAdapter) Delete(name string) error {
	if err := a.v.Delete(name); err != nil {
		return &vaultError{err}
	}
	return nil
}
