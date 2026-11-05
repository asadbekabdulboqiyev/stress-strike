package coordinator

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
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

// --- signature half of worker attestation -------------------------------
//
// The tests below drive the exact handler recvLoop uses (handleRunProgress /
// handleRunCompleted), so they cover the accept/reject decision without needing
// a fake gRPC stream. The two *_E2E tests at the bottom run the whole path over
// real gRPC streams.

// attestationTestMaster returns a master that requires signed telemetry and has
// kp's public key pinned under workerID.
func attestationTestMaster(t *testing.T, workerID string, kp *attest.Keypair) *Master {
	t.Helper()
	m := NewMaster(MasterConfig{
		RequireWorkerAttestation: true,
		Logf:                     func(string, ...any) {},
	})
	if err := m.SetWorkerKey(workerID, attest.PublicKeyHex(kp.Public)); err != nil {
		t.Fatalf("pin worker key: %v", err)
	}
	m.mu.Lock()
	m.workerCount = 1
	m.mu.Unlock()
	return m
}

// attestationTestSnapshot is a fully populated snapshot: maps, floats and steps
// all exercise the deterministic digest path, not just scalar fields.
func attestationTestSnapshot() *distproto.TelemetrySnapshot {
	return &distproto.TelemetrySnapshot{
		Timestamp:     1_700_000_000_000,
		ElapsedMs:     2_000,
		TotalRequests: 42,
		TotalErrors:   1,
		Rps:           21,
		ActiveUsers:   4,
		StatusCodes:   map[int32]int64{200: 41, 500: 1},
		ErrorTypes:    map[string]int64{"timeout": 1},
		Latency:       &distproto.LatencyPercentiles{P50Ms: 3, P95Ms: 9, P99Ms: 12, AvgMs: 5, MinMs: 1, MaxMs: 20},
		Steps:         []*distproto.StepTelemetry{{Name: "req", Requests: 42, Errors: 1}},
	}
}

// signedProgress builds the event a worker with kp emits for workerID.
func signedProgress(t *testing.T, kp *attest.Keypair, workerID, runID string, snap *distproto.TelemetrySnapshot) *distproto.RunProgress {
	t.Helper()
	ts := time.Now().UnixMilli()
	sig, err := SignProgress(kp, workerID, runID, ts, snap)
	if err != nil {
		t.Fatalf("sign progress: %v", err)
	}
	return &distproto.RunProgress{
		RunId:     runID,
		Timestamp: ts,
		Telemetry: snap,
		WorkerId:  workerID,
		Signature: sig,
	}
}

// TestSignedProgressAccepted is the happy path: a snapshot signed by the pinned
// worker key is aggregated, the connection is bound to that identity, and
// nothing is marked failed or rejected.
func TestSignedProgressAccepted(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := attestationTestMaster(t, "w1", kp)
	const addr = "10.0.0.1:50061"

	rp := signedProgress(t, kp, "w1", "run-1", attestationTestSnapshot())
	if !master.handleRunProgress(addr, rp, nil) {
		t.Fatalf("signed progress must be accepted (rejected: %v)", master.RejectedWorkers())
	}

	agg := master.Aggregator().Snapshot()
	if agg.Workers != 1 || agg.TotalRequests != 42 || agg.TotalErrors != 1 {
		t.Fatalf("signed snapshot was not aggregated: %+v", agg)
	}
	if id, ok := master.WorkerIDForAddr(addr); !ok || id != "w1" {
		t.Fatalf("connection binding = (%q,%v), want (w1,true)", id, ok)
	}
	if got := master.RejectedWorkers(); len(got) != 0 {
		t.Fatalf("no rejection expected, got %v", got)
	}
	if got := master.FailedWorkers(); len(got) != 0 {
		t.Fatalf("attested worker must not be marked failed, got %v", got)
	}
	if n := master.Aggregator().RejectedCount(); n != 0 {
		t.Fatalf("aggregator rejected %d snapshots, want 0", n)
	}
}

// TestUnsignedProgressRejected is the fail-closed half: once attestation is on,
// a snapshot with no worker_id/signature must be discarded, its telemetry must
// never reach the aggregator, and the worker must be marked failed.
func TestUnsignedProgressRejected(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := attestationTestMaster(t, "w1", kp)
	const addr = "10.0.0.2:50061"

	snap := attestationTestSnapshot()
	rp := &distproto.RunProgress{RunId: "run-1", Timestamp: time.Now().UnixMilli(), Telemetry: snap}
	if master.handleRunProgress(addr, rp, nil) {
		t.Fatal("unsigned progress must be rejected when attestation is required")
	}

	if agg := master.Aggregator().Snapshot(); agg.Workers != 0 || agg.TotalRequests != 0 {
		t.Fatalf("unsigned telemetry must not be aggregated: %+v", agg)
	}
	if got := master.RejectedWorkers(); len(got) != 1 || got[addr] == "" {
		t.Fatalf("rejection reason not recorded for %s: %v", addr, got)
	}
	if got := master.FailedWorkers(); len(got) != 1 || got[0] != addr {
		t.Fatalf("unsigned worker must be marked failed, got %v", got)
	}
}

// TestForgedProgressRejected covers two forgeries of the signature half: a
// signature produced by a different key than the pinned one, and a genuine
// signature over a snapshot that was modified afterwards.
func TestForgedProgressRejected(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	other, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("second keypair: %v", err)
	}

	t.Run("signed by another key", func(t *testing.T) {
		master := attestationTestMaster(t, "w1", kp)
		const addr = "10.0.0.3:50061"
		rp := signedProgress(t, other, "w1", "run-1", attestationTestSnapshot())

		if master.handleRunProgress(addr, rp, nil) {
			t.Fatal("signature from a different key must be rejected")
		}
		if agg := master.Aggregator().Snapshot(); agg.Workers != 0 {
			t.Fatalf("forged telemetry was aggregated: %+v", agg)
		}
		if len(master.RejectedWorkers()) != 1 {
			t.Fatalf("forged worker must be recorded as rejected: %v", master.RejectedWorkers())
		}
		if len(master.FailedWorkers()) != 1 {
			t.Fatalf("forged worker must be marked failed: %v", master.FailedWorkers())
		}
	})

	t.Run("telemetry tampered after signing", func(t *testing.T) {
		master := attestationTestMaster(t, "w1", kp)
		const addr = "10.0.0.4:50061"
		rp := signedProgress(t, kp, "w1", "run-1", attestationTestSnapshot())
		rp.Telemetry.TotalRequests = 1_000_000 // inflate the numbers on the wire

		if master.handleRunProgress(addr, rp, nil) {
			t.Fatal("tampered telemetry must not verify")
		}
		if agg := master.Aggregator().Snapshot(); agg.Workers != 0 {
			t.Fatalf("tampered telemetry was aggregated: %+v", agg)
		}
	})

	t.Run("identity mismatch on one connection", func(t *testing.T) {
		master := attestationTestMaster(t, "w1", kp)
		const addr = "10.0.0.5:50061"
		if !master.handleRunProgress(addr, signedProgress(t, kp, "w1", "run-1", attestationTestSnapshot()), nil) {
			t.Fatal("first attested snapshot must be accepted")
		}
		// Same pinned key, but the stream now claims a different worker id:
		// one connection may only ever speak for one identity.
		claim := signedProgress(t, kp, "w2", "run-1", attestationTestSnapshot())
		if master.handleRunProgress(addr, claim, nil) {
			t.Fatal("a second worker identity on the same connection must be rejected")
		}
	})
}

// TestSignedFinalReportAccepted verifies the RunCompleted half of the
// attestation: a report signed by the pinned worker verifies, a tampered report
// does not.
func TestSignedFinalReportAccepted(t *testing.T) {
	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	master := attestationTestMaster(t, "w1", kp)
	const addr = "10.0.0.6:50061"

	rep := &distproto.Report{Name: "injected", TotalRequests: 10, TotalErrors: 0, Rps: 5}
	ts := time.Now().UnixMilli()
	sig, err := SignReport(kp, "w1", "run-1", ts, rep)
	if err != nil {
		t.Fatalf("sign report: %v", err)
	}
	rc := &distproto.RunCompleted{RunId: "run-1", Timestamp: ts, Report: rep, WorkerId: "w1", Signature: sig}
	if !master.handleRunCompleted(addr, rc, nil) {
		t.Fatalf("signed final report must be accepted (rejected: %v)", master.RejectedWorkers())
	}

	master2 := attestationTestMaster(t, "w1", kp)
	rc.Report.TotalRequests = 999_999
	if master2.handleRunCompleted("10.0.0.7:50061", rc, nil) {
		t.Fatal("tampered final report must not verify")
	}
}

// TestAggregatorStrictGate is the defence-in-depth check: even a caller that
// bypasses the recvLoop verification cannot push an unverified snapshot into a
// strict aggregator.
func TestAggregatorStrictGate(t *testing.T) {
	a := NewAggregator()
	a.SetRequireVerified(true)
	if a.Update("w1", attestationTestSnapshot()) {
		t.Fatal("strict aggregator must refuse Update (unverified)")
	}
	if a.UpdateVerified("w1", attestationTestSnapshot(), false) {
		t.Fatal("strict aggregator must refuse an explicitly unverified snapshot")
	}
	if !a.UpdateVerified("w1", attestationTestSnapshot(), true) {
		t.Fatal("strict aggregator must accept a verified snapshot")
	}
	if n := a.RejectedCount(); n != 2 {
		t.Fatalf("RejectedCount = %d, want 2", n)
	}

	a.SetRequireVerified(false)
	if !a.Update("w2", attestationTestSnapshot()) {
		t.Fatal("unstrict aggregator must accept unsigned snapshots")
	}
}

// TestDistributedRunAttestedE2E runs the full path over real gRPC: a worker
// holding an Ed25519 keypair streams signed progress and a signed final report,
// and a master that pins that key and requires attestation completes the run
// with the telemetry counted.
func TestDistributedRunAttestedE2E(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	addr, _ := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 100, Keypair: kp})

	master := NewMaster(MasterConfig{
		Scenario:                 tinyScenario(t, target.URL, 4, 2),
		Workers:                  []string{addr},
		ListenAddr:               "127.0.0.1:0",
		RunTimeout:               20 * time.Second,
		RequireWorkerAttestation: true,
		AuthorizedWorkers:        map[string]string{"w1": attest.PublicKeyHex(kp.Public)},
		Logf:                     func(string, ...any) {},
	})
	defer master.Close()

	ctx := context.Background()
	if _, err := master.Connect(ctx, []string{addr}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := master.StartRun(ctx, "run-attested"); err != nil {
		t.Fatalf("start run: %v", err)
	}
	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for the attested run")
	}

	if got := master.FailedWorkers(); len(got) != 0 {
		t.Fatalf("attested worker must not fail, got %v (rejections: %v)", got, master.RejectedWorkers())
	}
	rep := master.FinalReport()
	if rep == nil || rep.TotalRequests == 0 {
		t.Fatalf("expected a non-empty merged report, got %+v", rep)
	}
	if agg := master.Aggregator().Snapshot(); agg.Workers == 0 || agg.TotalRequests == 0 {
		t.Fatalf("signed progress never reached the aggregator: %+v", agg)
	}
}

// TestDistributedRunRejectsUnsignedWorkerE2E proves the fail-closed path end to
// end: a worker with no keypair cannot get telemetry into an attested master,
// and it is reported as failed instead of contributing numbers.
func TestDistributedRunRejectsUnsignedWorkerE2E(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	kp, err := attest.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	// Worker has no Keypair: it streams unsigned telemetry.
	addr, _ := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 100})

	master := NewMaster(MasterConfig{
		Scenario:                 tinyScenario(t, target.URL, 4, 2),
		Workers:                  []string{addr},
		ListenAddr:               "127.0.0.1:0",
		RunTimeout:               20 * time.Second,
		RequireWorkerAttestation: true,
		AuthorizedWorkers:        map[string]string{"w1": attest.PublicKeyHex(kp.Public)},
		Logf:                     func(string, ...any) {},
	})
	defer master.Close()

	ctx := context.Background()
	if _, err := master.Connect(ctx, []string{addr}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := master.StartRun(ctx, "run-unsigned"); err != nil {
		t.Fatalf("start run: %v", err)
	}
	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for the unsigned worker to be dropped")
	}

	if got := master.FailedWorkers(); len(got) != 1 || got[0] != addr {
		t.Fatalf("unsigned worker must be marked failed, got %v", got)
	}
	if got := master.RejectedWorkers(); len(got) != 1 {
		t.Fatalf("rejection reason must be recorded, got %v", got)
	}
	if agg := master.Aggregator().Snapshot(); agg.Workers != 0 || agg.TotalRequests != 0 {
		t.Fatalf("unsigned telemetry must not be aggregated: %+v", agg)
	}
	if rep := master.FinalReport(); rep != nil && rep.TotalRequests > 0 {
		t.Fatalf("unsigned worker report must not be merged, got %d requests", rep.TotalRequests)
	}
}
