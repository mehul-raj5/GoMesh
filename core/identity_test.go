package core

import (
	"bytes"
	common "common"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestIdentity builds a complete identity the way a device does, with its
// files in throwaway directories: keys, a state store, and a first signed prekey.
func newTestIdentity(t *testing.T) *IdentityManager {
	t.Helper()
	key, _ := randomKey()
	im, err := openIdentity(newMemVault(), key, filepath.Join(t.TempDir(), legacyKeyFile))
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	store, err := OpenStateStore(filepath.Join(t.TempDir(), stateDirName), key)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := im.LoadPreKeys(store); err != nil {
		t.Fatalf("prekeys: %v", err)
	}
	return im
}

// loginAs runs the three-step login by hand on c and returns the user ID.
func loginAs(t *testing.T, c net.Conn, im *IdentityManager, name string) [16]byte {
	t.Helper()
	body, err := common.EncodeCredentials(&common.Credentials{Username: name, Password: testPassword, Bundle: im.Bundle(), DeviceName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&common.Packet{Header: common.Header{MsgType: common.CtrlRegister, BodyLen: uint32(len(body))}, Body: body}).Encode(c); err != nil {
		t.Fatalf("register: %v", err)
	}
	ch, err := common.Decode(c)
	if err != nil || ch.Header.MsgType != common.CtrlLoginChallenge {
		t.Fatalf("challenge: %v type=%#x", err, ch.Header.MsgType)
	}
	var nonce [common.LoginNonceSize]byte
	copy(nonce[:], ch.Body)
	sig := im.SignLogin(nonce, name)
	if err := (&common.Packet{Header: common.Header{MsgType: common.CtrlLoginProof, BodyLen: common.SignatureSize}, Body: sig[:]}).Encode(c); err != nil {
		t.Fatalf("proof: %v", err)
	}
	ack, err := common.Decode(c)
	if err != nil || ack.Header.MsgType != common.CtrlLoginAck {
		t.Fatalf("login ack: %v type=%#x", err, ack.Header.MsgType)
	}
	id, _, err := common.DecodeLoginAck(ack.Body)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIdentityIsCreatedAndReloaded(t *testing.T) {
	v, key := newMemVault(), [32]byte{7}
	legacy := filepath.Join(t.TempDir(), legacyKeyFile)
	first, err := openIdentity(v, key, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !common.IsValidKey(first.SigningKey) {
		t.Fatal("no signing key generated")
	}
	stored, err := v.Get(vaultIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, first.PrivateKey[:]) || bytes.Contains(stored, first.SigningSeed[:]) {
		t.Fatal("the vault holds the identity keys unsealed")
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("a plaintext identity file was written")
	}

	again, err := openIdentity(v, key, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if again.PrivateKey != first.PrivateKey || again.PublicKey != first.PublicKey ||
		again.SigningSeed != first.SigningSeed || again.SigningKey != first.SigningKey {
		t.Fatal("reloading changed the identity")
	}
	if _, err := openIdentity(v, [32]byte{8}, legacy); err == nil {
		t.Fatal("the identity opened under another account key")
	}
}

// An earlier version's plaintext identity.key moves into the vault and is
// deleted. A file from before signing keys existed holds only the X25519 pair,
// which is kept, since peers know it, and a signing key is added.
func TestLegacyIdentityFileMovesIntoTheVault(t *testing.T) {
	v, key := newMemVault(), [32]byte{7}
	path := filepath.Join(t.TempDir(), legacyKeyFile)
	priv, pub, _ := common.GenerateIdentityKeys()
	if err := os.WriteFile(path, append(append([]byte{}, priv[:]...), pub[:]...), 0o644); err != nil {
		t.Fatal(err)
	}

	im, err := openIdentity(v, key, path)
	if err != nil {
		t.Fatal(err)
	}
	if im.PrivateKey != priv || im.PublicKey != pub {
		t.Fatal("the move replaced the existing identity key")
	}
	if !common.IsValidKey(im.SigningKey) {
		t.Fatal("no signing key added")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the plaintext identity file is still there")
	}
	again, _ := openIdentity(v, key, path)
	if again.SigningKey != im.SigningKey {
		t.Fatal("the signing key changed between loads")
	}
}

// A plaintext file left by a move that was interrupted after the vault write
// loses to the vault's copy, and goes.
func TestTheVaultsIdentityWinsOverALeftoverFile(t *testing.T) {
	v, key := newMemVault(), [32]byte{7}
	path := filepath.Join(t.TempDir(), legacyKeyFile)
	im, _ := openIdentity(v, key, path)
	os.WriteFile(path, make([]byte, identityLen), 0o600)

	again, err := openIdentity(v, key, path)
	if err != nil || again.PublicKey != im.PublicKey {
		t.Fatalf("the leftover file won: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the leftover plaintext file is still there")
	}
}

func TestIdentityRejectsAMangledFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), legacyKeyFile)
	os.WriteFile(path, make([]byte, 70), 0o600)
	if _, err := openIdentity(newMemVault(), [32]byte{7}, path); err == nil {
		t.Fatal("a file of the wrong length was accepted")
	}
}

// A vault that cannot be read is not an empty vault: making new keys over it
// would orphan every session the old ones hold.
func TestAnUnreadableVaultIsNotTakenForEmpty(t *testing.T) {
	v := newMemVault()
	v.failGet = errLocked
	if _, err := openIdentity(v, [32]byte{7}, filepath.Join(t.TempDir(), legacyKeyFile)); err == nil {
		t.Fatal("an identity was made although the vault could not be read")
	}
	cl := newClient()
	cl.dataDir, cl.vault = t.TempDir(), v
	if _, err := cl.accountKey(); err == nil {
		t.Fatal("an account key was made although the vault could not be read")
	}
	if err := cl.openDevice(); err == nil {
		t.Fatal("the device opened although the vault could not be read")
	}
	if v.puts != 0 {
		t.Fatalf("%d secrets were written over a vault that could not be read", v.puts)
	}

	// Once it can be read, the device opens.
	v.failGet = nil
	if err := cl.openDevice(); err != nil {
		t.Fatal(err)
	}
}

// Sealed identity keys without the key that seals them are not replaced.
func TestAMissingAccountKeyIsNotPaperedOver(t *testing.T) {
	v := newMemVault()
	cl := newClient()
	cl.dataDir, cl.vault = t.TempDir(), v
	if err := cl.openDevice(); err != nil {
		t.Fatal(err)
	}
	v.Delete(vaultAccountKey)
	if err := cl.openDevice(); err == nil {
		t.Fatal("new keys were made over sealed ones whose key is gone")
	}
}

func TestFirstRunCreatesAVerifiableSignedPreKey(t *testing.T) {
	im := newTestIdentity(t)
	b := im.Bundle()
	if !b.Verify() {
		t.Fatal("the bundle a fresh identity offers does not verify")
	}
	if b.IdentityKey != im.PublicKey || b.SigningKey != im.SigningKey || b.SPKID != 1 {
		t.Fatalf("unexpected bundle: %+v", b)
	}
	if _, ok := im.SPKPrivate(b.SPKID); !ok {
		t.Fatal("the private half of the advertised prekey is not held")
	}
}

func TestPreKeysSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	v, key := newMemVault(), [32]byte{7}
	open := func() *IdentityManager {
		im, err := openIdentity(v, key, filepath.Join(dir, legacyKeyFile))
		if err != nil {
			t.Fatal(err)
		}
		store, err := OpenStateStore(filepath.Join(dir, stateDirName), key)
		if err != nil {
			t.Fatal(err)
		}
		if err := im.LoadPreKeys(store); err != nil {
			t.Fatal(err)
		}
		return im
	}

	first := open()
	b1 := first.Bundle()
	priv1, _ := first.SPKPrivate(b1.SPKID)

	second := open()
	b2 := second.Bundle()
	if b1 != b2 {
		t.Fatal("the advertised prekey changed across a restart")
	}
	if priv2, ok := second.SPKPrivate(b2.SPKID); !ok || priv2 != priv1 {
		t.Fatal("the prekey's private half did not survive")
	}
}

func TestRotationKeepsTheOldKeyForTheGracePeriodOnly(t *testing.T) {
	im := newTestIdentity(t)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	im.now = func() time.Time { return clock }

	old := im.Bundle()
	oldPriv, _ := im.SPKPrivate(old.SPKID)

	if err := im.RotateSPK(); err != nil {
		t.Fatal(err)
	}
	cur := im.Bundle()
	if cur.SPKID != old.SPKID+1 || cur.SPK == old.SPK || !cur.Verify() {
		t.Fatalf("rotation did not install a fresh verifiable key: %+v", cur)
	}

	// A first message built from the bundle fetched just before the rotation
	// must still be answerable.
	clock = clock.Add(SPKGrace - time.Hour)
	if got, ok := im.SPKPrivate(old.SPKID); !ok || got != oldPriv {
		t.Fatal("the retired prekey was dropped inside its grace period")
	}

	clock = clock.Add(2 * time.Hour)
	if _, ok := im.SPKPrivate(old.SPKID); ok {
		t.Fatal("the retired prekey is still usable past its grace period")
	}
	if _, ok := im.SPKPrivate(cur.SPKID); !ok {
		t.Fatal("the current prekey became unusable with the passage of time")
	}

	// The next rotation prunes what has aged out.
	if err := im.RotateSPK(); err != nil {
		t.Fatal(err)
	}
	for _, k := range im.spks {
		if k.ID == old.SPKID {
			t.Fatal("an expired prekey was kept on disk")
		}
	}
}

func TestPreKeyIDsNeverRepeat(t *testing.T) {
	im := newTestIdentity(t)
	seen := map[uint32]bool{im.Bundle().SPKID: true}
	for i := 0; i < 5; i++ {
		if err := im.RotateSPK(); err != nil {
			t.Fatal(err)
		}
		id := im.Bundle().SPKID
		if seen[id] {
			t.Fatalf("prekey ID %d reused", id)
		}
		seen[id] = true
	}
}

// Prekey state tampered with on disk must not be trusted: its signatures have to
// be ours.
func TestPreKeyStateSignedByAnotherIdentityIsRefused(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, stateDirName)

	a, _ := openIdentity(newMemVault(), [32]byte{1}, filepath.Join(dir, "a.key"))
	storeA, _ := OpenStateStore(stateDir, [32]byte{1})
	if err := a.LoadPreKeys(storeA); err != nil {
		t.Fatal(err)
	}

	// A second identity pointed at the same state.
	b, _ := openIdentity(newMemVault(), [32]byte{2}, filepath.Join(dir, "b.key"))
	if err := b.LoadPreKeys(storeA); err == nil {
		t.Fatal("prekeys signed by a different identity were loaded")
	}
}

func TestLoginProofVerifiesAgainstTheSigningKey(t *testing.T) {
	im := newTestIdentity(t)
	var nonce [common.LoginNonceSize]byte
	nonce[0] = 7
	sig := im.SignLogin(nonce, "alice")
	if !common.VerifyLogin(im.SigningKey, nonce, im.PublicKey, "alice", sig) {
		t.Fatal("the identity's own login proof does not verify")
	}
}

func TestSafetyNumberMatchesOnBothSides(t *testing.T) {
	a, b := newTestIdentity(t), newTestIdentity(t)
	if a.SafetyNumber(b.PublicKey, b.SigningKey) != b.SafetyNumber(a.PublicKey, a.SigningKey) {
		t.Fatal("the two sides see different safety numbers")
	}
}
