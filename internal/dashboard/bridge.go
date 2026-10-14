package dashboard

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/attest"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/evidence"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/version"
)

// EngineBridge connects the load engine to the dashboard
type EngineBridge struct {
	server *Server

	mu        sync.Mutex
	stopCh    chan struct{}
	stopped   bool
	finished  bool
	config    *RunConfig
	startTime time.Time
	lastSnap  *LiveSnapshot

	// Per-request bookkeeping (RecordRequest path). Snapshots pushed from the
	// engine telemetry already carry authoritative totals, so these are only
	// used when the caller drives the bridge with RecordRequest instead.
	hist        metrics.Histogram
	totalReqs   uint64
	totalErrors uint64
	statusCodes map[int]uint64

	// Attestation fields
	attestDataDir string
	collector     *evidence.Collector
	coordKey      *attest.Keypair
	workerKey     *attest.Keypair
	runID         string

	// engineFeedsSamples records that the collector was handed to the engine as
	// its SampleSink (via AttachEngineSink). The collector must be fed by
	// exactly one source: if the engine feeds it, RecordRequest must not, or
	// every request would be recorded twice and the signed bundle would
	// over-count the run — a false claim about a run that never happened, which
	// is precisely what this evidence format exists to make impossible.
	engineFeedsSamples bool
}

func NewEngineBridge(server *Server) *EngineBridge {
	return &EngineBridge{
		server:      server,
		stopCh:      make(chan struct{}),
		statusCodes: make(map[int]uint64),
	}
}

// StartRun initializes a new load test run. It fully resets the run state —
// counters, last snapshot, stopped/finished flags and the stop channel — so a
// new run can always be started after a previous run completed, stopped or
// failed.
func (b *EngineBridge) StartRun(config *RunConfig) {
	if config == nil {
		config = &RunConfig{}
	}
	b.mu.Lock()
	b.stopCh = make(chan struct{})
	b.stopped = false
	b.finished = false
	b.config = config
	b.startTime = time.Now()
	b.lastSnap = nil
	b.hist = metrics.Histogram{}
	b.totalReqs = 0
	b.totalErrors = 0
	b.statusCodes = make(map[int]uint64)
	b.mu.Unlock()

	// Initialize attestation collector and keys
	b.initAttestation(config)

	b.server.SetRunState(&RunState{
		Status:    "running",
		Config:    config,
		StartTime: b.startTime,
		Duration:  time.Duration(config.DurationSeconds) * time.Second,
	})
}

// StopRun stops the current run — safe to call multiple times and across runs.
// Each StartRun installs a fresh stop channel, so a second run can always be
// stopped even if a previous one already hit StopRun. A stop request that
// races a completed/failed run is ignored so it cannot overwrite the terminal
// state.
func (b *EngineBridge) StopRun() {
	b.mu.Lock()
	if b.stopped || b.finished {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	stop := b.stopCh
	b.mu.Unlock()

	select {
	case <-stop:
	default:
		close(stop)
	}
	b.pushState("stopped")
}

// IsStopped returns true if the current run was stopped via StopRun
func (b *EngineBridge) IsStopped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopped
}

// PushSnapshot receives a live snapshot from the engine and forwards it to the
// dashboard. Snapshots should be built from engine telemetry via
// SnapshotFromTelemetry (or any other source that already carries the latency
// percentiles stored on LiveSnapshot).
func (b *EngineBridge) PushSnapshot(snap *LiveSnapshot) {
	if snap == nil {
		return
	}
	b.mu.Lock()
	if b.config == nil || b.stopped || b.finished {
		b.mu.Unlock()
		return
	}
	b.lastSnap = snap
	b.mu.Unlock()

	b.server.UpdateSnapshot(snap)
	b.pushState("running")
}

// RecordRequest records a single request result (per-request counting path).
// Bounded latency samples are accumulated in a histogram so the emitted
// snapshot carries real P50/P95/P99/Avg/Max values instead of zeros.
func (b *EngineBridge) RecordRequest(statusCode int, latency time.Duration, isError bool) {
	b.mu.Lock()
	if b.config == nil {
		b.mu.Unlock()
		return
	}
	b.hist.Add(latency)
	seq := b.totalReqs
	b.totalReqs++
	if statusCode > 0 {
		b.statusCodes[statusCode]++
	}
	if isError {
		b.totalErrors++
	}
	collector := b.collector
	engineFeeds := b.engineFeedsSamples
	startTime := b.startTime
	b.mu.Unlock()

	// Only synthesise a record here when the engine is not already the sample
	// source — see engineFeedsSamples. When the engine feeds the collector it
	// emits the real attempt timestamps, byte counts and sequence numbers, so
	// this lower-fidelity path must stay out of the way.
	if collector != nil && !engineFeeds {
		status := statusCode
		if isError && (status < 100 || status > 599) {
			status = 500
		}
		collector.Emit(engine.Sample{
			Seq:       seq,
			StartNS:   time.Now().UnixNano(),
			LatencyNS: latency.Nanoseconds(),
			Status:    status,
			Bytes:     0,
		})
	}

	elapsed := time.Since(startTime)
	elapsedSec := elapsed.Seconds()
	if elapsedSec <= 0 {
		elapsedSec = 0.001 // avoid division by zero
	}
	rps := float64(b.totalReqs) / elapsedSec
	var errorRate float64
	if b.totalReqs > 0 {
		errorRate = float64(b.totalErrors) / float64(b.totalReqs) * 100
	}
	// Read percentiles live
	b.mu.Lock()
	hist := &b.hist
	snap := &LiveSnapshot{
		Timestamp:   time.Now(),
		RPS:         rps,
		TotalReq:    b.totalReqs,
		TotalErrors: b.totalErrors,
		ErrorRate:   errorRate,
		P50Latency:  latencyMillis(hist.Percentile(0.50)),
		P95Latency:  latencyMillis(hist.Percentile(0.95)),
		P99Latency:  latencyMillis(hist.Percentile(0.99)),
		AvgLatency:  latencyMillis(hist.Avg()),
		MaxLatency:  latencyMillis(hist.MaxLatency()),
		StatusCodes: cloneStatusCodes(b.statusCodes),
	}
	b.mu.Unlock()

	b.server.UpdateSnapshot(snap)
	b.pushState("running")
}

// SnapshotFromTelemetry converts the engine's live telemetry into a dashboard
// LiveSnapshot, filling every latency metric (P50/P95/P99/Avg/Max) plus RPS,
// error rate, active users and status codes.
func (b *EngineBridge) SnapshotFromTelemetry(tel *metrics.Telemetry) *LiveSnapshot {
	if tel == nil {
		return nil
	}
	reqs := tel.TotalRequests()
	errs := tel.TotalErrors()
	var errorRate float64
	if reqs > 0 {
		errorRate = float64(errs) / float64(reqs) * 100
	}
	lat := tel.Overall.Latency
	return &LiveSnapshot{
		Timestamp:   time.Now(),
		RPS:         tel.RPS(),
		TotalReq:    reqs,
		TotalErrors: errs,
		ErrorRate:   errorRate,
		P50Latency:  latencyMillis(lat.Percentile(0.50)),
		P95Latency:  latencyMillis(lat.Percentile(0.95)),
		P99Latency:  latencyMillis(lat.Percentile(0.99)),
		AvgLatency:  latencyMillis(lat.Avg()),
		MaxLatency:  latencyMillis(lat.MaxLatency()),
		ActiveUsers: int(tel.ActiveUsers.Load()),
		StatusCodes: tel.StatusCodes(),
	}
}

// RunComplete marks the run as finished. When the run was stopped it keeps the
// "stopped" state and still records a (partial) history entry; otherwise the
// state becomes "completed". Safe to call once per run.
func (b *EngineBridge) RunComplete() {
	b.mu.Lock()
	if b.finished {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	b.finish(false, "")
}

// RunFailed marks the run as failed, surfacing the error message on the run
// state. Nothing is added to history for a failed run.
func (b *EngineBridge) RunFailed(err error) {
	b.mu.Lock()
	if b.finished {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	b.finish(true, msg)
}

// finish records the final run state and, unless the run failed, adds a
// history entry derived from the last pushed snapshot.
func (b *EngineBridge) finish(failed bool, errMsg string) {
	b.mu.Lock()
	if b.finished || b.config == nil {
		b.mu.Unlock()
		return
	}
	b.finished = true
	stopped := b.stopped
	config := b.config
	startTime := b.startTime
	snap := b.lastSnap
	elapsed := time.Since(startTime)
	b.mu.Unlock()

	if failed {
		b.server.SetRunState(&RunState{
			Status:    "failed",
			Config:    config,
			StartTime: startTime,
			EndTime:   time.Now(),
			Elapsed:   elapsed,
			Error:     errMsg,
		})
		return
	}

	status := "completed"
	if stopped {
		status = "stopped"
	}
	// Emit attestation on completion/stopped
	_ = b.emitAttestation()

	progress := 100.0
	if config.DurationSeconds > 0 {
		p := elapsed.Seconds() / float64(config.DurationSeconds) * 100
		if p > 0 && p < 100 {
			progress = p
		}
	}

	totalReqs, totalErrors := uint64(0), uint64(0)
	var rps, p50, p95, p99, avg, maxLat float64
	statusCodes := map[int]uint64{}
	if snap != nil {
		totalReqs = snap.TotalReq
		totalErrors = snap.TotalErrors
		rps = snap.RPS
		p50 = snap.P50Latency
		p95 = snap.P95Latency
		p99 = snap.P99Latency
		avg = snap.AvgLatency
		maxLat = snap.MaxLatency
		statusCodes = snap.StatusCodes
	}

	duration := time.Duration(config.DurationSeconds) * time.Second
	b.server.SetRunState(&RunState{
		Status:    status,
		Config:    config,
		StartTime: startTime,
		EndTime:   time.Now(),
		Elapsed:   elapsed,
		Duration:  duration,
		Progress:  progress,
	})

	entry := HistoryEntry{
		ID:        fmt.Sprintf("run-%d", startTime.UnixMilli()),
		Timestamp: startTime,
		Config:    *config,
		Result: RunResult{
			TotalRequests: totalReqs,
			TotalErrors:   totalErrors,
			RPS:           rps,
			P50Latency:    p50,
			P95Latency:    p95,
			P99Latency:    p99,
			AvgLatency:    avg,
			MaxLatency:    maxLat,
			StatusCodes:   statusCodes,
		},
		Duration: elapsed.Round(time.Millisecond).String(),
	}
	b.server.AddHistoryEntry(entry)
}

// pushState broadcasts a RunState derived from the bridge's config and start
// time, computing elapsed time and progress.
func (b *EngineBridge) pushState(status string) {
	b.mu.Lock()
	config := b.config
	start := b.startTime
	b.mu.Unlock()

	elapsed := time.Since(start)
	progress := 0.0
	if config != nil && config.DurationSeconds > 0 {
		progress = elapsed.Seconds() / float64(config.DurationSeconds) * 100
		if progress > 100 {
			progress = 100
		}
	}
	var duration time.Duration
	if config != nil {
		duration = time.Duration(config.DurationSeconds) * time.Second
	}

	b.server.SetRunState(&RunState{
		Status:    status,
		Config:    config,
		StartTime: start,
		Elapsed:   elapsed,
		Duration:  duration,
		Progress:  progress,
	})
}

func latencyMillis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

func cloneStatusCodes(in map[int]uint64) map[int]uint64 {
	out := make(map[int]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func defaultWorkerIDBridge() string {
	host, err := os.Hostname()
	if err != nil || len(host) == 0 {
		host = "local"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}

func (b *EngineBridge) initAttestation(config *RunConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.collector = nil
	b.coordKey = nil
	b.workerKey = nil
	b.engineFeedsSamples = false
	b.runID = fmt.Sprintf("run-%d", time.Now().UnixMilli())

	// Determine data dir
	dataDir, err := getDashboardDataDir()
	if err != nil {
		dataDir = b.attestDataDir
	}
	if dataDir == "" {
		if h, err := os.UserHomeDir(); err == nil {
			dataDir = filepath.Join(h, ".stress-strike", "dashboard")
		} else {
			dataDir = ".stress-strike-dashboard"
		}
	}
	b.attestDataDir = dataDir
	bundlesDir := filepath.Join(dataDir, "bundles", b.runID)
	if err := os.MkdirAll(bundlesDir, 0o750); err != nil {
		return
	}

	// Load or mint coordinator key (persistent operator key)
	coordPath := filepath.Join(dataDir, "operator.key")
	var coord *attest.Keypair
	if _, err := os.Stat(coordPath); err == nil {
		if kp, err := attest.LoadKeypairPEM(coordPath); err == nil {
			coord = kp
		}
	}
	if coord == nil {
		kp, err := attest.GenerateKeypair()
		if err == nil {
			_ = attest.SaveKeypairPEM(kp, coordPath)
			coord = kp
		}
	}
	if coord == nil {
		return
	}
	b.coordKey = coord

	// Generate worker keypair (ephemeral per run)
	wkp, err := attest.GenerateKeypair()
	if err != nil {
		return
	}
	b.workerKey = wkp

	workerID := defaultWorkerIDBridge()
	coll, err := evidence.NewCollector(workerID)
	if err != nil {
		return
	}
	b.collector = coll
}

func (b *EngineBridge) emitAttestation() error {
	b.mu.Lock()
	collector := b.collector
	coordKey := b.coordKey
	workerKey := b.workerKey
	runID := b.runID
	dataDir := b.attestDataDir
	config := b.config
	startTime := b.startTime
	b.mu.Unlock()

	if collector == nil || coordKey == nil || workerKey == nil {
		return nil
	}
	if err := collector.Err(); err != nil {
		return err
	}

	bundlesDir := filepath.Join(dataDir, "bundles", runID)
	if err := os.MkdirAll(bundlesDir, 0o750); err != nil {
		return err
	}
	bundlePath := filepath.Join(bundlesDir, "bundle.json")
	sidecarPath := evidence.SidecarPath(bundlePath)

	// Build scenario-like config for bundle
	durationNS := int64(time.Since(startTime).Nanoseconds())
	if config != nil && config.DurationSeconds > 0 {
		durationNS = int64(config.DurationSeconds) * int64(time.Second)
	}

	plannedRPS := int64(0)
	if config != nil && config.RateLimit > 0 {
		plannedRPS = int64(config.RateLimit)
	}

	plannedMilli := plannedRPS * 1000
	planned, err := attest.DecimalFromMilli(plannedMilli)
	if err != nil {
		return err
	}

	tool := attest.Tool{Name: "stress-strike", Version: version.Version}
	run := attest.Run{
		Target:     config.TargetURL,
		Profile:    "dashboard",
		DurationNS: durationNS,
		PlannedRPS: planned,
	}
	if config != nil && config.Profile != "" {
		run.Profile = config.Profile
	}

	bundle, err := evidence.BuildBundle(evidence.BundleInput{
		Collector:      collector,
		WorkerKey:      workerKey,
		CoordinatorKey: coordKey,
		Tool:           tool,
		Run:            run,
		CreatedAt:      time.Now(),
		// Dashboard scenarios never set profile.coordinated_omission (see
		// cmd/stress-strike-dashboard scenarioFromConfig), so the correction is
		// withheld and the bundle records raw percentiles, co_corrected=false.
		// That is exactly what `stress-strike run --emit-bundle` does for the
		// same scenario (cmd_run.emitEvidenceBundle gates the claim on the same
		// flag), so the two producers can never disagree about it.
		COCorrected: false,
	})
	if err != nil {
		return err
	}

	if _, err := evidence.WriteBundle(bundle, collector.Records(), bundlePath); err != nil {
		return err
	}

	pubKey := attest.PublicKeyHex(coordKey.Public)
	info := AttestationInfo{
		Exists:      true,
		RunID:       runID,
		BundlePath:  bundlePath,
		SamplesPath: sidecarPath,
		PubKeyHex:   pubKey,
		Fingerprint: pubKey[:16] + "...",
		COCorrected: bundle.Aggregate.COCorrected,
	}
	b.server.SetAttestationInfo(info)
	return nil
}

// AttachEngineSink hands the run's evidence collector to the host so it can be
// passed to engine.RunOptions.Samples, and records that the engine is now the
// sample source. After this call RecordRequest no longer records evidence, so a
// request can never be counted twice (see engineFeedsSamples).
//
// It returns nil when attestation could not be initialised; the host should
// then simply run without a sample sink.
func (b *EngineBridge) AttachEngineSink() *evidence.Collector {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.collector == nil {
		return nil
	}
	b.engineFeedsSamples = true
	return b.collector
}
