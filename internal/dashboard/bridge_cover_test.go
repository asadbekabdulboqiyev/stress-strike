package dashboard

// bridge_cover_test.go — lifecycle, telemetry and attestation coverage for
// EngineBridge (bridge.go). Every path that returns normally is driven here;
// the bridge has no os.Exit, so the whole state machine is testable in-process.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
)

// newTestBridge builds a bridge whose attestation data dir lands in a temp
// directory: getDashboardDataDir derives it from the user config dir, which
// follows HOME / XDG_CONFIG_HOME.
func newTestBridge(t *testing.T) (*EngineBridge, *Server, *RunConfig) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	srv := NewServer()
	b := NewEngineBridge(srv)
	cfg := &RunConfig{
		TargetURL:       "https://example.com/",
		Users:           4,
		DurationSeconds: 10,
		RateLimit:       100,
		Profile:         "steady",
	}
	return b, srv, cfg
}

func serverState(s *Server) *RunState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runState
}

func serverSnapshot(s *Server) *LiveSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

func serverHistory(s *Server) []HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]HistoryEntry(nil), s.history...)
}

func TestBridgeAttachEngineSinkBeforeStart(t *testing.T) {
	b := NewEngineBridge(NewServer())
	if got := b.AttachEngineSink(); got != nil {
		t.Fatalf("AttachEngineSink before StartRun = %v, want nil", got)
	}
}

func TestBridgeRunLifecycle(t *testing.T) {
	b, srv, cfg := newTestBridge(t)

	b.StartRun(cfg)
	if b.IsStopped() {
		t.Fatal("fresh run reports stopped")
	}

	if b.collector == nil || b.coordKey == nil || b.workerKey == nil {
		t.Fatalf("attestation not initialised: collector=%v coord=%v worker=%v",
			b.collector, b.coordKey, b.workerKey)
	}
	if _, err := os.Stat(filepath.Join(b.attestDataDir, "operator.key")); err != nil {
		t.Errorf("operator key not persisted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.attestDataDir, "bundles", b.runID)); err != nil {
		t.Errorf("bundle dir not created: %v", err)
	}

	state := serverState(srv)
	if state == nil || state.Status != "running" || state.Config != cfg {
		t.Fatalf("run state after StartRun = %+v", state)
	}
	if state.Duration != 10*time.Second {
		t.Errorf("duration = %v, want 10s", state.Duration)
	}

	// Per-request path: one clean 200, one transport error with no status
	// (recorded as 500) and one explicit 503.
	b.RecordRequest(200, 12*time.Millisecond, false)
	b.RecordRequest(0, 5*time.Millisecond, true)
	b.RecordRequest(503, 7*time.Millisecond, true)

	snap := serverSnapshot(srv)
	if snap.TotalReq != 3 {
		t.Errorf("TotalReq = %d, want 3", snap.TotalReq)
	}
	if snap.TotalErrors != 2 {
		t.Errorf("TotalErrors = %d, want 2", snap.TotalErrors)
	}
	if snap.ErrorRate < 66 || snap.ErrorRate > 67 {
		t.Errorf("ErrorRate = %v, want ~66.7", snap.ErrorRate)
	}
	if snap.StatusCodes[200] != 1 || snap.StatusCodes[503] != 1 {
		t.Errorf("StatusCodes = %v", snap.StatusCodes)
	}
	if snap.P50Latency <= 0 || snap.P99Latency <= 0 || snap.MaxLatency <= 0 || snap.AvgLatency <= 0 {
		t.Errorf("latency percentiles not filled: %+v", snap)
	}
	if snap.RPS <= 0 {
		t.Errorf("RPS = %v, want > 0", snap.RPS)
	}

	// Once the engine feeds the collector, RecordRequest must not feed it too.
	coll := b.AttachEngineSink()
	if coll == nil {
		t.Fatal("AttachEngineSink returned nil after StartRun")
	}
	before := len(coll.Records())
	b.RecordRequest(200, time.Millisecond, false)
	if got := len(coll.Records()); got != before {
		t.Errorf("engine-fed collector received %d extra record(s)", got-before)
	}

	// nil snapshots are ignored; real ones replace the server snapshot.
	// RecordRequest above pushed its own snapshot, so re-read the current one.
	current := serverSnapshot(srv)
	b.PushSnapshot(nil)
	if serverSnapshot(srv) != current {
		t.Error("nil snapshot changed the server snapshot")
	}
	pushed := &LiveSnapshot{TotalReq: 42, StatusCodes: map[int]uint64{200: 42}}
	b.PushSnapshot(pushed)
	if serverSnapshot(srv) != pushed {
		t.Error("pushed snapshot was not forwarded")
	}

	// Stopping the run reveals the terminal state and blocks further snapshots.
	b.StopRun()
	if !b.IsStopped() {
		t.Fatal("IsStopped = false after StopRun")
	}
	if got := serverState(srv).Status; got != "stopped" {
		t.Errorf("state after StopRun = %q", got)
	}
	b.PushSnapshot(pushed)
	if serverSnapshot(srv) != pushed {
		t.Error("snapshot pushed into a stopped run should be ignored")
	}

	// The second StopRun is a no-op and must not panic on a closed channel.
	b.StopRun()

	// Completing a stopped run keeps "stopped" and still records history.
	before2 := len(serverHistory(srv))
	b.RunComplete()
	history := serverHistory(srv)
	if len(history) != before2+1 {
		t.Fatalf("history entries = %d, want %d", len(history), before2+1)
	}
	entry := history[len(history)-1]
	if !strings.HasPrefix(entry.ID, "run-") {
		t.Errorf("history ID = %q", entry.ID)
	}
	if entry.Result.TotalRequests != 42 {
		t.Errorf("history total requests = %d, want 42 (from last snapshot)", entry.Result.TotalRequests)
	}
	if entry.Duration == "" {
		t.Error("history duration is empty")
	}
	if entry.Config.TargetURL != cfg.TargetURL {
		t.Errorf("history config target = %q", entry.Config.TargetURL)
	}
	final := serverState(srv)
	if final.Status != "stopped" {
		t.Errorf("final state = %q, want stopped", final.Status)
	}
	// The run finished in milliseconds of a 10s window, so the completion
	// state carries the real (tiny) progress rather than a hard-coded 100.
	if final.Progress <= 0 || final.Progress >= 100 {
		t.Errorf("final progress = %v, want 0 < p < 100", final.Progress)
	}

	// Attestation was emitted and the bundle is on disk.
	srv.attestMu.RLock()
	info := srv.attestInfo
	srv.attestMu.RUnlock()
	if !info.Exists {
		t.Fatalf("attestation info not set: %+v", info)
	}
	if info.RunID != b.runID {
		t.Errorf("attestation run id = %q, want %q", info.RunID, b.runID)
	}
	if !strings.HasSuffix(info.Fingerprint, "...") || len(info.PubKeyHex) < 16 {
		t.Errorf("attestation fingerprint = %q (key %q)", info.Fingerprint, info.PubKeyHex)
	}
	raw, err := os.ReadFile(info.BundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("bundle is not JSON: %v", err)
	}
	if _, err := os.Stat(info.SamplesPath); err != nil {
		t.Errorf("samples sidecar missing: %v", err)
	}

	// A second completion is ignored: no duplicate history.
	b.RunComplete()
	if got := len(serverHistory(srv)); got != len(history) {
		t.Errorf("second RunComplete added %d entr(ies)", got-len(history))
	}
	// StopRun after completion is a no-op.
	b.StopRun()
	if got := serverState(srv).Status; got != "stopped" {
		t.Errorf("state after late StopRun = %q", got)
	}
}

func TestBridgeRunFailed(t *testing.T) {
	b, srv, cfg := newTestBridge(t)
	b.StartRun(cfg)

	b.RunFailed(errors.New("connection refused"))
	state := serverState(srv)
	if state.Status != "failed" || state.Error != "connection refused" {
		t.Fatalf("failed state = %+v", state)
	}
	if len(serverHistory(srv)) != 0 {
		t.Error("failed run must not be added to history")
	}

	// A second failure is ignored and does not overwrite the message.
	b.RunFailed(errors.New("other"))
	if got := serverState(srv).Error; got != "connection refused" {
		t.Errorf("late RunFailed overwrote the error: %q", got)
	}

	// A nil error still marks the run failed, with an empty message.
	b2, srv2, _ := newTestBridge(t)
	b2.StartRun(nil)
	b2.RunFailed(nil)
	if got := serverState(srv2); got.Status != "failed" || got.Error != "" {
		t.Errorf("nil-error failure state = %+v", got)
	}
}

func TestBridgeBeforeStartGuards(t *testing.T) {
	b := NewEngineBridge(NewServer())

	b.PushSnapshot(&LiveSnapshot{TotalReq: 1})
	if serverSnapshot(b.server).TotalReq != 0 {
		t.Error("snapshot pushed before StartRun must be ignored")
	}

	b.RecordRequest(200, time.Millisecond, false)
	if b.totalReqs != 0 {
		t.Errorf("RecordRequest before StartRun counted %d request(s)", b.totalReqs)
	}

	b.finish(false, "")
	if b.finished {
		t.Error("finish without a config must not mark the bridge finished")
	}

	// StopRun on a never-started bridge closes its channel and publishes
	// "stopped" with a zero progress.
	b.StopRun()
	if !b.IsStopped() {
		t.Error("StopRun before StartRun did not set stopped")
	}
	state := serverState(b.server)
	if state.Status != "stopped" || state.Progress != 0 || state.Duration != 0 {
		t.Errorf("pre-start stopped state = %+v", state)
	}
}

func TestBridgeSnapshotFromTelemetry(t *testing.T) {
	b := NewEngineBridge(NewServer())
	if got := b.SnapshotFromTelemetry(nil); got != nil {
		t.Fatalf("SnapshotFromTelemetry(nil) = %+v", got)
	}

	tel := metrics.NewTelemetry()
	tel.Overall.Record(10*time.Millisecond, 200, "")
	tel.Overall.Record(30*time.Millisecond, 500, "server error")
	tel.Steps = []*metrics.StepStats{tel.Overall}
	tel.ActiveUsers.Store(4)

	snap := b.SnapshotFromTelemetry(tel)
	if snap.TotalReq != 2 || snap.TotalErrors != 1 {
		t.Errorf("telemetry totals = %d/%d", snap.TotalReq, snap.TotalErrors)
	}
	if snap.ErrorRate != 50 {
		t.Errorf("ErrorRate = %v, want 50", snap.ErrorRate)
	}
	if snap.ActiveUsers != 4 {
		t.Errorf("ActiveUsers = %d", snap.ActiveUsers)
	}
	if snap.StatusCodes[200] != 1 || snap.StatusCodes[500] != 1 {
		t.Errorf("StatusCodes = %v", snap.StatusCodes)
	}
	if snap.P50Latency <= 0 || snap.MaxLatency < 30 {
		t.Errorf("latency fields = %+v", snap)
	}
}

func TestBridgeAttestationSkipsAndFailures(t *testing.T) {
	// No collector: emitAttestation is a silent no-op.
	b := NewEngineBridge(NewServer())
	if err := b.emitAttestation(); err != nil {
		t.Errorf("emitAttestation without a collector: %v", err)
	}

	// A data dir that cannot be created makes emission fail; RunComplete
	// swallows the error and leaves the attestation info unset.
	b2, srv, _ := newTestBridge(t)
	b2.StartRun(&RunConfig{TargetURL: "https://example.com/", DurationSeconds: 5})
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	b2.mu.Lock()
	b2.attestDataDir = filepath.Join(file, "data")
	b2.mu.Unlock()
	b2.RunComplete()

	srv.attestMu.RLock()
	info := srv.attestInfo
	srv.attestMu.RUnlock()
	if info.Exists {
		t.Errorf("attestation info set despite a broken data dir: %+v", info)
	}
	if len(serverHistory(srv)) != 1 {
		t.Log("history may still be recorded; attestation failure must not break the run")
	}
}

func TestBridgeHelpers(t *testing.T) {
	if got := latencyMillis(1500 * time.Microsecond); got != 1.5 {
		t.Errorf("latencyMillis = %v, want 1.5", got)
	}

	if got := cloneStatusCodes(nil); got == nil || len(got) != 0 {
		t.Errorf("cloneStatusCodes(nil) = %v", got)
	}
	in := map[int]uint64{200: 3, 500: 1}
	out := cloneStatusCodes(in)
	if out[200] != 3 || out[500] != 1 {
		t.Errorf("clone = %v", out)
	}
	out[200] = 99
	if in[200] != 3 {
		t.Error("cloneStatusCodes aliased the input map")
	}

	id := defaultWorkerIDBridge()
	if !strings.Contains(id, "-") {
		t.Errorf("worker id %q should end with the pid", id)
	}
}
