package coordinator

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"

	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
)

// TestRegisterFailsClosedWhenPinned verifies the identity gate of the worker
// allowlist: when the coordinator has pinned worker identities, self-registration
// from an unpinned worker id must be rejected (fail closed), while a pinned id
// is accepted. An empty allowlist keeps the coordinator open (single-tenant /
// local development mode) and is therefore not a failure here.
func TestRegisterFailsClosedWhenPinned(t *testing.T) {
	const pinnedID = "w1"
	pubHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" // 32 bytes, valid hex
	master := NewMaster(MasterConfig{AuthorizedWorkers: map[string]string{pinnedID: pubHex}})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: "w2", Address: "10.0.0.9:50061"}); err != nil || resp.GetAccepted() {
		t.Fatalf("unpinned worker w2 must be rejected: accepted=%v err=%v", resp.GetAccepted(), err)
	}

	resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: pinnedID, Address: "10.0.0.1:50061"})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("pinned worker %s must be accepted: accepted=%v err=%v msg=%s", pinnedID, resp.GetAccepted(), err, resp.GetMessage())
	}
}

// TestRegisterAcceptsUnpinnedWhenAllowlistEmpty verifies the dev-mode default:
// with no allowlist configured, registration is open (the fleet is opted into
// pinning explicitly).
func TestRegisterAcceptsUnpinnedWhenAllowlistEmpty(t *testing.T) {
	master := NewMaster(MasterConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: "w1", Address: "10.0.0.1:50061"})
	if err != nil || !resp.GetAccepted() {
		t.Fatalf("open mode must accept registration: accepted=%v err=%v", resp.GetAccepted(), err)
	}
}

// TestVerifyWorkerAttestation checks the Ed25519 half of worker attestation:
// a genuine signature from the pinned worker verifies, while a missing pin, a
// mismatched key or a tampered signature does not.
func TestVerifyWorkerAttestation(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pub, priv := kp.Public, kp.Private
	pubHex := attest.PublicKeyHex(pub)
	master := NewMaster(MasterConfig{})
	if err := master.SetWorkerKey("w1", pubHex); err != nil {
		t.Fatalf("set worker key: %v", err)
	}

	msg := []byte("stressstrike/worker-attest/v1\nworker=w1\nrun=demo\nreport=abc")
	sig, err := attest.Sign(&attest.Keypair{Private: priv}, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !master.VerifyWorkerAttestation("w1", pub, msg, sig) {
		t.Fatal("genuine worker attestation must verify against the pinned key")
	}

	if master.VerifyWorkerAttestation("w2", pub, msg, sig) {
		t.Fatal("unknown worker must not verify")
	}

	otherKP, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	otherPub := otherKP.Public
	otherSig, err := attest.Sign(otherKP, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if master.VerifyWorkerAttestation("w1", otherPub, msg, otherSig) {
		t.Fatal("signature from a different key must not verify against the pinned worker")
	}

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if master.VerifyWorkerAttestation("w1", pub, msg, tampered) {
		t.Fatal("tampered signature must not verify")
	}

	if err := master.SetWorkerKey("w1", ""); err != nil {
		t.Fatalf("clear worker key: %v", err)
	}
	if master.VerifyWorkerAttestation("w1", pub, msg, sig) {
		t.Fatal("cleared pin must not verify")
	}
}

// TestSetWorkerKeyRejectsMalformedPin verifies that an operator-supplied
// malformed pin is rejected instead of poisoning the allowlist.
func TestSetWorkerKeyRejectsMalformedPin(t *testing.T) {
	master := NewMaster(MasterConfig{})
	if err := master.SetWorkerKey("w1", "not-hex"); err == nil {
		t.Fatal("malformed pin must be rejected")
	}
}

// TestWorkerAttestationKeySize is a guard on the stable attest key surface used
// by the coordinator's worker attestation path.
func TestWorkerAttestationKeySize(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pub := kp.Public
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("ed25519 public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}
