package attest

// keys_test.go — Ed25519 signing and PEM storage.

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSignVerifyAndTamper(t *testing.T) {
	kp := mustKey(t)
	msg := []byte("measure twice")
	sig, err := Sign(kp, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySig(kp.Public, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifySig(kp.Public, []byte("cut once"), sig) {
		t.Fatal("signature accepted for a different message")
	}
	other := mustKey(t)
	if VerifySig(other.Public, msg, sig) {
		t.Fatal("signature accepted for a different key")
	}
}

func TestVerifySigFailsClosed(t *testing.T) {
	kp := mustKey(t)
	msg := []byte("x")
	sig, _ := Sign(kp, msg)
	if VerifySig(nil, msg, sig) {
		t.Fatal("nil key accepted")
	}
	if VerifySig(kp.Public, msg, nil) {
		t.Fatal("nil signature accepted")
	}
	if VerifySig(kp.Public, msg, sig[:10]) {
		t.Fatal("short signature accepted")
	}
	if VerifySig(kp.Public[:10], msg, sig) {
		t.Fatal("short key accepted")
	}
}

func TestSignRejectsNilKeypair(t *testing.T) {
	if _, err := Sign(nil, []byte("x")); err == nil {
		t.Fatal("Sign(nil) did not error")
	}
	if _, err := Sign(&Keypair{}, []byte("x")); err == nil {
		t.Fatal("Sign of an empty keypair did not error")
	}
}

func TestSaveLoadKeypairPEM(t *testing.T) {
	kp := mustKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "coordinator.pem")
	if err := SaveKeypairPEM(kp, path); err != nil {
		t.Fatalf("SaveKeypairPEM: %v", err)
	}

	// The 0600 guarantee is POSIX-only: Windows has no mode bits and Go
	// reports 0666 for any writable file. Elsewhere, the mode is the point of
	// the test and is asserted strictly.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("key file mode = %o, want 600", perm)
		}
	}

	loaded, err := LoadKeypairPEM(path)
	if err != nil {
		t.Fatalf("LoadKeypairPEM: %v", err)
	}
	if !equalBytes(loaded.Private, kp.Private) {
		t.Fatal("private key did not round-trip")
	}
	if !equalBytes(loaded.Public, kp.Public) {
		t.Fatal("public key did not round-trip")
	}

	// A key loaded from disk still signs for the original public key.
	sig, err := Sign(loaded, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if !VerifySig(kp.Public, []byte("hello"), sig) {
		t.Fatal("signature from a loaded key does not verify")
	}
}

func TestLoadPublicKeyPEM(t *testing.T) {
	kp := mustKey(t)
	path := filepath.Join(t.TempDir(), "coordinator.pem")
	if err := SaveKeypairPEM(kp, path); err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKeyPEM(path)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM: %v", err)
	}
	if !equalBytes(pub, kp.Public) {
		t.Fatal("public key mismatch")
	}
}

func TestSaveKeypairPEMRejectsInvalidKeypair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.pem")
	if err := SaveKeypairPEM(nil, path); err == nil {
		t.Fatal("nil keypair accepted")
	}
	if err := SaveKeypairPEM(&Keypair{}, path); err == nil {
		t.Fatal("empty keypair accepted")
	}
	// Mismatched halves must be refused.
	a, b := mustKey(t), mustKey(t)
	if err := SaveKeypairPEM(&Keypair{Private: a.Private, Public: b.Public}, path); err == nil {
		t.Fatal("mismatched keypair accepted")
	}
}

func TestLoadKeypairPEMRejectsEncrypted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enc.pem")
	doc := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("whatever")})
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeypairPEM(path); err == nil {
		t.Fatal("encrypted private key accepted")
	}
}

func TestLoadKeypairPEMRejectsMismatchedPublic(t *testing.T) {
	kp1, kp2 := mustKey(t), mustKey(t)
	privDER, err := x509.MarshalPKCS8PrivateKey(kp1.Private)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(kp2.Public)
	if err != nil {
		t.Fatal(err)
	}
	doc := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	doc = append(doc, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})...)

	path := filepath.Join(t.TempDir(), "mismatch.pem")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeypairPEM(path); err == nil {
		t.Fatal("a key file whose halves disagree was accepted")
	}
}

func TestLoadKeypairPEMRejectsNoPrivateKey(t *testing.T) {
	kp := mustKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	doc := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	path := filepath.Join(t.TempDir(), "public-only.pem")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeypairPEM(path); err == nil {
		t.Fatal("a public-only file was accepted as a keypair")
	}
}

func TestParsePublicKeyHex(t *testing.T) {
	kp := mustKey(t)
	hexKey := PublicKeyHex(kp.Public)
	pub, err := ParsePublicKeyHex(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(pub, kp.Public) {
		t.Fatal("hex round-trip mismatch")
	}
	if len(hexKey) != 2*32 {
		t.Fatalf("public key hex length = %d, want 64", len(hexKey))
	}
	if _, err := ParsePublicKeyHex("zz"); err == nil {
		t.Fatal("non-hex accepted")
	}
	if _, err := ParsePublicKeyHex("abcd"); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := ParsePublicKeyHex(hex.EncodeToString(make([]byte, 33))); err == nil {
		t.Fatal("33-byte key accepted")
	}
}
