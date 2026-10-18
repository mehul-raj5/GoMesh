package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// The chat runs over TLS 1.3. A development server uses a self-signed
// certificate, so clients pin it by fingerprint instead of asking the system
// to trust it. Nothing at the OS level forces TLS on a raw socket, so both
// sides enforce it here.

// GenerateSelfSigned returns a PEM certificate and key for a development
// server: ECDSA P-256, valid for two years. Clients pin the certificate, so the
// names it carries are informational.
func GenerateSelfSigned(hosts ...string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "GoMesh development server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// CertFingerprint is the SHA-256 of a certificate's DER bytes, as 64 lowercase
// hex characters.
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// NormalizeFingerprint accepts a fingerprint with or without colons, spaces or
// upper case, and returns the 64-character form, or an error.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
	if b, err := hex.DecodeString(s); err != nil || len(b) != sha256.Size {
		return "", errors.New("a fingerprint is 64 hex characters")
	}
	return s, nil
}

// FormatFingerprint groups a fingerprint in fours so a person can compare it.
func FormatFingerprint(fp string) string {
	var parts []string
	for i := 0; i+4 <= len(fp); i += 4 {
		parts = append(parts, fp[i:i+4])
	}
	return strings.Join(parts, " ")
}

// ServerTLSConfig loads a certificate pair for the server: TLS 1.3 only.
func ServerTLSConfig(certPEM, keyPEM []byte) (*tls.Config, string, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	}, CertFingerprint(pair.Certificate[0]), nil
}

// ErrPinMismatch means the server presented a certificate other than the pinned one.
var ErrPinMismatch = errors.New("the server's certificate does not match the pinned fingerprint")

// PinnedTLSConfig accepts exactly one server certificate: the one whose
// fingerprint is pin. The usual chain check is switched off because the
// certificate is self-signed; VerifyConnection replaces it and fails closed,
// so a missing or different certificate ends the handshake.
//
// With an empty pin, any certificate is accepted and its fingerprint is passed
// to seen, so a client can show it to the user and pin it afterwards. That is
// trust on first use, and only ever for a connection the user then confirms.
func PinnedTLSConfig(pin string, seen func(fingerprint string)) (*tls.Config, error) {
	if pin != "" {
		var err error
		if pin, err = NormalizeFingerprint(pin); err != nil {
			return nil, err
		}
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the server presented no certificate")
			}
			fp := CertFingerprint(cs.PeerCertificates[0].Raw)
			if seen != nil {
				seen(fp)
			}
			if pin == "" {
				if seen == nil {
					return errors.New("no fingerprint pinned for this server")
				}
				return nil
			}
			if fp != pin {
				return fmt.Errorf("%w (got %s)", ErrPinMismatch, FormatFingerprint(fp))
			}
			return nil
		},
	}, nil
}
