package attest

// keys.go — Ed25519 identities and their PEM storage.
//
// Two kinds of key material exist in the protocol:
//
//   - the coordinator key, whose public half is published inside the bundle
//     signature (it signs the whole bundle);
//   - worker keys, whose public halves are pinned per worker inside the bundle
//     (each worker signs its own commit).
//
// Both are Ed25519. Private keys are stored as PKCS#8 PEM ("PRIVATE KEY"), the
// portable form every modern tool understands, and the matching public key is
// stored as a PKIX PEM block ("PUBLIC KEY") in the same file so a single
// artifact is enough to hand out. The public key is never secret: it also
// travels as lowercase hex inside the bundle, so verification never needs the
// key file at all.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// pemPrivateKeyType is the PEM block type for a PKCS#8 private key.
const pemPrivateKeyType = "PRIVATE KEY"

// pemPublicKeyType is the PEM block type for a PKIX public key.
const pemPublicKeyType = "PUBLIC KEY"

// maxKeyFileBytes bounds key file reads so a hostile or corrupt path cannot
// make the process allocate an unbounded buffer.
const maxKeyFileBytes = 64 << 10

// Keypair is an Ed25519 identity: the private key that signs and the public
// key that verifies.
type Keypair struct {
	// Private is the 64-byte Ed25519 private key (seed + public half).
	Private ed25519.PrivateKey
	// Public is the 32-byte Ed25519 public key.
	Public ed25519.PublicKey
}

// GenerateKeypair returns a fresh Ed25519 identity from the system CSPRNG.
func GenerateKeypair() (*Keypair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("attest: generate Ed25519 key: %w", err)
	}
	return &Keypair{Private: priv, Public: pub}, nil
}

// Sign signs msg with the keypair's private key. It returns an error for a nil
// or malformed keypair instead of panicking.
func Sign(kp *Keypair, msg []byte) ([]byte, error) {
	if kp == nil || len(kp.Private) != ed25519.PrivateKeySize {
		return nil, errors.New("attest: signing requires a valid Ed25519 private key")
	}
	return ed25519.Sign(kp.Private, msg), nil
}

// VerifySig reports whether sig is a valid Ed25519 signature over msg by pub.
// Any malformed input (wrong key size, wrong signature size, nil) is simply
// invalid — the caller never has to pre-validate bytes that arrived from an
// untrusted file.
func VerifySig(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// PublicKeyHex returns the lowercase hex form of a public key, exactly as it
// appears in a bundle's public_key / signature.key members.
func PublicKeyHex(pub ed25519.PublicKey) string { return hex.EncodeToString(pub) }

// ParsePublicKeyHex decodes the hex form used by the bundle format. It rejects
// anything that is not exactly a 32-byte key.
func ParsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("attest: public key is not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("attest: public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// SaveKeypairPEM writes the private key as a PKCS#8 PEM block followed by the
// public key as a PKIX PEM block.
//
// The write is atomic (temporary file + rename) and the file is created with
// mode 0600 before the rename, so a partially written or world-readable key
// never hits the disk. SaveKeypairPEM deliberately overwrites; callers that
// must not clobber an existing identity (the keygen command) check first.
func SaveKeypairPEM(kp *Keypair, path string) error {
	if kp == nil || len(kp.Private) != ed25519.PrivateKeySize || len(kp.Public) != ed25519.PublicKeySize {
		return errors.New("attest: save requires a valid Ed25519 keypair")
	}
	if err := verifyKeypairConsistency(kp.Private, kp.Public); err != nil {
		return err
	}

	der, err := x509.MarshalPKCS8PrivateKey(kp.Private)
	if err != nil {
		return fmt.Errorf("attest: marshal PKCS#8 private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(kp.Public)
	if err != nil {
		return fmt.Errorf("attest: marshal PKIX public key: %w", err)
	}

	doc := pem.EncodeToMemory(&pem.Block{Type: pemPrivateKeyType, Bytes: der})
	doc = append(doc, pem.EncodeToMemory(&pem.Block{Type: pemPublicKeyType, Bytes: pubDER})...)

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("attest: create key directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("attest: create temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best effort: the rename removes the file on the success path.
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("attest: restrict key file permissions: %w", err)
	}
	if _, err := tmp.Write(doc); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("attest: write key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("attest: sync key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("attest: close key file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("attest: install key file: %w", err)
	}
	return nil
}

// LoadKeypairPEM reads a key file written by SaveKeypairPEM.
//
// It tolerates a file that contains only the private key block, rejects
// encrypted keys with a clear message (the protocol requires an unencrypted key
// so a signing run cannot block on a passphrase), and fails closed when a
// public block is present but does not match the private key: a file whose two
// halves disagree is never usable for signing.
func LoadKeypairPEM(path string) (*Keypair, error) {
	doc, err := readLimited(path, maxKeyFileBytes)
	if err != nil {
		return nil, err
	}

	kp := &Keypair{}
	blocks := 0
	var publicFromFile ed25519.PublicKey
	rest := doc
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		switch block.Type {
		case pemPrivateKeyType:
			key, err := parsePKCS8Ed25519(block.Bytes)
			if err != nil {
				return nil, err
			}
			if kp.Private != nil {
				return nil, errors.New("attest: key file contains more than one private key")
			}
			kp.Private = key
			kp.Public = key.Public().(ed25519.PublicKey)
		case pemPublicKeyType:
			pub, err := parsePKIXEd25519(block.Bytes)
			if err != nil {
				return nil, err
			}
			publicFromFile = pub
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("attest: encrypted private keys are not supported; decrypt the key first (openssl pkcs8 -topk8 -nocrypt)")
		default:
			// Unknown block types are ignored so that a file carrying extra
			// metadata (e.g. an X.509 certificate) still loads.
		}
	}
	if len(strings.TrimSpace(string(rest))) > 0 && strings.Contains(string(rest), "-----BEGIN") {
		return nil, errors.New("attest: key file contains an unparsable PEM block")
	}
	if blocks == 0 {
		return nil, errors.New("attest: key file contains no PEM block")
	}
	if kp.Private == nil {
		return nil, errors.New("attest: key file contains no private key")
	}
	if publicFromFile != nil && !equalBytes(publicFromFile, kp.Public) {
		return nil, errors.New("attest: public key block does not match the private key")
	}
	return kp, nil
}

// LoadPublicKeyPEM reads a public key from a PKIX PEM file, either a bare
// "PUBLIC KEY" block or the public block of a key file written by
// SaveKeypairPEM. It exists so a verifier can pin a coordinator key out of
// band instead of trusting the key embedded in the bundle.
func LoadPublicKeyPEM(path string) (ed25519.PublicKey, error) {
	doc, err := readLimited(path, maxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	rest := doc
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemPublicKeyType {
			continue
		}
		return parsePKIXEd25519(block.Bytes)
	}
	return nil, errors.New("attest: no PUBLIC KEY block found")
}

// parsePKCS8Ed25519 decodes a PKCS#8 document and insists on Ed25519.
func parsePKCS8Ed25519(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("attest: parse PKCS#8 private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("attest: private key is %T, want ed25519.PrivateKey", key)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("attest: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return priv, nil
}

// parsePKIXEd25519 decodes a PKIX document and insists on Ed25519.
func parsePKIXEd25519(der []byte) (ed25519.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("attest: parse PKIX public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("attest: public key is %T, want ed25519.PublicKey", key)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("attest: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	return pub, nil
}

// verifyKeypairConsistency fails when the public half does not belong to the
// private half. Ed25519 private keys embed their public half, so this is a
// cheap structural check against a hand-assembled Keypair.
func verifyKeypairConsistency(priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !equalBytes(derived, pub) {
		return errors.New("attest: keypair public and private halves do not match")
	}
	return nil
}

// readLimited reads at most limit bytes from path and fails when the file is
// larger, so an attacker cannot turn a key path into an unbounded allocation.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("attest: read %s: %w", path, err)
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("attest: %s is larger than the %d byte limit", path, limit)
	}
	return buf, nil
}
