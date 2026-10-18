package common

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCredentialsRoundTrip(t *testing.T) {
	in := Credentials{Username: "alice", Password: "correct horse ünïcode", Bundle: testBundle(t), DeviceName: "Alice's Mac"}
	body, err := EncodeCredentials(&in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeCredentials(body)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip changed the credentials: %+v", out)
	}
}

func TestCredentialsRejectsMalformedBodies(t *testing.T) {
	in := Credentials{Username: "alice", Password: "a long password", Bundle: testBundle(t), DeviceName: "mac"}
	body, _ := EncodeCredentials(&in)

	for n := 0; n < len(body); n++ {
		if _, err := DecodeCredentials(body[:n]); err == nil {
			t.Fatalf("a body truncated to %d of %d bytes was accepted", n, len(body))
		}
	}
	if _, err := DecodeCredentials(append(body, 0)); err == nil {
		t.Fatal("trailing bytes were accepted")
	}

	long := in
	long.Password = strings.Repeat("x", MaxPasswordBytes+1)
	if _, err := EncodeCredentials(&long); err == nil {
		t.Fatal("an oversized password was encoded")
	}
	// A hand-built body claiming an oversized password.
	forged := []byte{5, 'a', 'l', 'i', 'c', 'e', 0xFF, 0xFF}
	if _, err := DecodeCredentials(forged); err == nil {
		t.Fatal("a password length above the limit was accepted")
	}
}

func TestPasswordLengthFieldHoldsMultibytePasswords(t *testing.T) {
	// 128 characters of four-byte UTF-8 is 512 bytes, past what one byte can count.
	pw := strings.Repeat("😀", MaxPasswordBytes/4)
	in := Credentials{Username: "alice", Password: pw, Bundle: testBundle(t)}
	body, err := EncodeCredentials(&in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeCredentials(body)
	if err != nil || out.Password != pw {
		t.Fatalf("multibyte password did not survive: %v", err)
	}
	if err := CheckPassword(pw, "alice"); err != nil {
		t.Fatalf("a 128-character password was refused: %v", err)
	}
}

func TestResumeAndAckRoundTrip(t *testing.T) {
	b := testBundle(t)
	var token [SessionTokenSize]byte
	token[0], token[31] = 7, 9
	gotToken, gotB, err := DecodeResume(EncodeResume(token, &b))
	if err != nil || gotToken != token || gotB != b {
		t.Fatalf("resume round trip: %v", err)
	}
	if _, _, err := DecodeResume(EncodeResume(token, &b)[1:]); err == nil {
		t.Fatal("short resume accepted")
	}

	var id [IDSize]byte
	id[3] = 1
	gotID, gotTok, err := DecodeLoginAck(EncodeLoginAck(id, token))
	if err != nil || gotID != id || gotTok != token {
		t.Fatalf("ack round trip: %v", err)
	}
	if _, _, err := DecodeLoginAck(id[:]); err == nil {
		t.Fatal("an ack without a token was accepted")
	}
}

func TestErrorBodyRoundTrip(t *testing.T) {
	e, err := DecodeError(EncodeError(ErrUsernameTaken, "pick another"))
	if err != nil || e.Code != ErrUsernameTaken || e.Message != "pick another" {
		t.Fatalf("error round trip: %+v %v", e, err)
	}
	if e, err := DecodeError(nil); err != nil || e.Code != ErrUnknown {
		t.Fatal("an empty error body should decode as ErrUnknown")
	}
	if _, err := DecodeError([]byte{1, 0, 5, 'x'}); err == nil {
		t.Fatal("an error body shorter than its length field was accepted")
	}
	var se *ServerError
	if !errors.As(error(e), &se) {
		t.Fatal("ServerError does not satisfy error")
	}
}

func TestDecodeMaxRefusesLargeBodies(t *testing.T) {
	var buf bytes.Buffer
	(&Packet{Header: Header{MsgType: CtrlLogin, BodyLen: MaxPreAuthBody + 1}, Body: make([]byte, MaxPreAuthBody+1)}).Encode(&buf)
	if _, err := DecodeMax(bytes.NewReader(buf.Bytes()), MaxPreAuthBody); err == nil {
		t.Fatal("a body over the limit was read")
	}
}

func TestNormalizeUsername(t *testing.T) {
	good := map[string]string{"Alice": "alice", "  bob_99 ": "bob_99", "a.b": "a.b"}
	for in, want := range good {
		got, err := NormalizeUsername(in)
		if err != nil || got != want {
			t.Errorf("NormalizeUsername(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ab", strings.Repeat("a", 33), "has space", "dash-ed", "émile", "a/b"} {
		if _, err := NormalizeUsername(bad); err == nil {
			t.Errorf("NormalizeUsername(%q) was accepted", bad)
		}
	}
}

// While GoMesh is being tested, any password goes except an empty one, one
// that is not text, and one too long for the message.
func TestCheckPassword(t *testing.T) {
	for _, ok := range []string{"a", "1", "password", "alice", "a perfectly fine passphrase"} {
		if err := CheckPassword(ok, "alice"); err != nil {
			t.Errorf("CheckPassword(%q) was refused: %v", ok, err)
		}
	}
	if err := CheckPassword("", "alice"); err == nil {
		t.Error("an empty password was accepted")
	}
	if err := CheckPassword(strings.Repeat("x", MaxPasswordBytes+1), "alice"); err == nil {
		t.Error("a password longer than the message allows was accepted")
	}
	if err := CheckPassword("\xff\xfe", "alice"); err == nil {
		t.Error("invalid UTF-8 was accepted")
	}
}

func TestLoginProofUsesTheCurrentDomain(t *testing.T) {
	// A proof is bound to its domain string, so a change of login semantics
	// cannot be confused with an earlier version's.
	if !bytes.HasPrefix(loginMessage([LoginNonceSize]byte{}, [KeySize]byte{}, "x"), []byte("GoMesh-login-v2")) {
		t.Fatal("login proofs are not domain-separated as v2")
	}
}
