package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/asadbekabdulboqiyev/sift/internal/attest"
	"github.com/asadbekabdulboqiyev/sift/internal/config"
	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/sift/internal/report"
)

// Liveness tuning for the fleet monitor. Workers stream a StatusReport
// heartbeat every 2s (see worker.go), so a worker that has sent nothing for
// livenessDeadline is either dead, partitioned, or wedged. The master probes
// it with Ping before declaring it failed.
const (
	livenessCheckInterval = 10 * time.Second
	livenessDeadline      = 30 * time.Second
)

// registerTTL is how long a self-registration stays valid without a
// re-register. Workers re-register every 10s (see cmd/Sift-worker),
// so an entry older than this belongs to a dead worker and is pruned so
// auto-discovery never waits on — or selects — a corpse.
var registerTTL = 35 * time.Second

// MasterConfig configures a distributed coordinator.
type MasterConfig struct {
	Scenario        *config.Scenario
	Workers         []string
	ListenAddr      string
	Token           string
	RunTimeout      time.Duration
	AutoWorkers     int
	RegisterTimeout time.Duration
	// ClientCreds enables TLS when the master dials workers (static fleet).
	// nil keeps plaintext dials.
	ClientCreds credentials.TransportCredentials
	Logf        func(format string, args ...any)
	// AuthorizedWorkers pins worker identities before any telemetry is
	// trusted. Keyed by worker_id, valued by lowercase hex Ed25519 public key.
	// When set and non-empty, self-registration from an unknown worker id (or
	// one whose pinned key does not match) is rejected, so a fleet can only ever
	// accept load from workers it has enrolled. This is the identity half of
	// worker attestation; the signature half for telemetry (RunProgress /
	// RunCompleted) is verified by VerifyProgressSignature and
	// VerifyReportSignature in attest.go, and pinning any key here turns it on.
	AuthorizedWorkers map[string]string
	// RequireWorkerAttestation makes signed telemetry mandatory even when no
	// worker keys are pinned here (SetWorkerKey may pin them later). With it
	// on, a RunProgress or RunCompleted whose Ed25519 signature does not verify
	// against the pinned key of the claimed worker_id is discarded and the
	// worker is marked failed. It is implied by a non-empty AuthorizedWorkers:
	// pinning anyone opts the fleet into attestation.
	RequireWorkerAttestation bool
}

// Master is the control plane: it distributes a scenario across workers,
// aggregates live telemetry, tolerates worker loss and merges the final
// reports. It is both a gRPC server (workers register/connect to it) and a gRPC
// client (it commands workers).
type Master struct {
	cfg MasterConfig
	// Embed for gRPC server implementation.
	distproto.UnimplementedMasterWorkerServer

	mu           sync.Mutex
	conns        map[string]*grpc.ClientConn
	clients      map[string]distproto.MasterWorkerClient
	streams      map[string]distproto.MasterWorker_CoordinateClient
	registered   map[string]*distproto.RegisterRequest
	registeredAt map[string]time.Time
	reports      map[string]*report.Report
	finished     map[string]bool
	failed       []string
	// lastSeen tracks the most recent event (progress, heartbeat, status)
	// per connected worker; the liveness loop uses it to spot silent workers.
	lastSeen map[string]time.Time
	// statusReports keeps the latest StatusReport per connected worker so the
	// fleet health (active runs, memory, cpu) is queryable.
	statusReports map[string]*distproto.StatusReport
	// workerPubs holds the Ed25519 public key pinned for each authorized
	// worker, keyed by worker_id. Populated from MasterConfig.AuthorizedWorkers
	// (fail-closed registration) and by SetWorkerKey (operator rotation).
	workerPubs map[string]ed25519.PublicKey
	// workerIDs binds a connection address to the worker identity that proved
	// ownership of its pinned key, so a stream cannot switch identities
	// mid-run. Keyed by remote address, valued by worker_id.
	workerIDs map[string]string
	// rejected records why a connection was dropped for failing attestation.
	// Keyed by remote address, valued by the human-readable reason.
	rejected map[string]string

	agg         *Aggregator
	runID       string
	doneCh      chan struct{}
	doneOnce    sync.Once
	runTimeout  *time.Timer
	workerCount int
	completed   int
	started     bool
}

// NewMaster builds a Master for the given configuration.
func NewMaster(cfg MasterConfig) *Master {
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	cfg.Logf = logf
	m := &Master{
		cfg:           cfg,
		conns:         make(map[string]*grpc.ClientConn),
		clients:       make(map[string]distproto.MasterWorkerClient),
		streams:       make(map[string]distproto.MasterWorker_CoordinateClient),
		registered:    make(map[string]*distproto.RegisterRequest),
		registeredAt:  make(map[string]time.Time),
		reports:       make(map[string]*report.Report),
		finished:      make(map[string]bool),
		lastSeen:      make(map[string]time.Time),
		statusReports: make(map[string]*distproto.StatusReport),
		workerPubs:    make(map[string]ed25519.PublicKey),
		workerIDs:     make(map[string]string),
		rejected:      make(map[string]string),
		agg:           NewAggregator(),
		doneCh:        make(chan struct{}),
	}
	// Seed the pin table from the static config too. Register applies the same
	// map for self-registering workers, but a static fleet never registers, so
	// without this the master would have no key to verify against and would
	// (correctly, but uselessly) reject every signed snapshot.
	for workerID, pubHex := range cfg.AuthorizedWorkers {
		pub, err := attest.ParsePublicKeyHex(pubHex)
		if err != nil {
			// Fail closed: the pin is unusable, so telemetry claiming this id
			// will be rejected until an operator fixes it.
			logf("WARNING: ignoring invalid pinned key for worker %s: %v", workerID, err)
			continue
		}
		m.workerPubs[workerID] = pub
	}
	// A configured allowlist is enough to turn signed telemetry on; the
	// Aggregator gets the same policy so it refuses unverified snapshots as a
	// second line of defence.
	m.syncAttestationModeLocked()
	return m
}

// Aggregator exposes the live fleet telemetry accumulator.
func (m *Master) Aggregator() *Aggregator { return m.agg }

// Done is closed once every worker has reported completion, failed, or the
// run deadline has elapsed.
func (m *Master) Done() <-chan struct{} { return m.doneCh }

// RunID returns the identifier of the current run.
func (m *Master) RunID() string { return m.runID }

// FailedWorkers lists workers that failed or disconnected during the run.
func (m *Master) FailedWorkers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.failed))
	copy(out, m.failed)
	return out
}

// Register implements worker self-registration for auto-discovery. Re-register
// with the same WorkerId replaces the previous entry (worker restart),
// and stale entries (no re-register within registerTTL) are pruned so a dead
// worker can never block or poison auto-discovery.
func (m *Master) Register(ctx context.Context, req *distproto.RegisterRequest) (*distproto.RegisterResponse, error) {
	if req == nil || req.Address == "" {
		return &distproto.RegisterResponse{Accepted: false, Message: "missing worker address"}, nil
	}
	m.mu.Lock()
	// Fail closed: when an operator has pinned worker identities, an
	// unlisted worker (or one claiming a listed id with a different key) is
	// rejected before it can stream any telemetry that the aggregator would
	// otherwise trust.
	if len(m.cfg.AuthorizedWorkers) > 0 {
		wantHex, ok := m.cfg.AuthorizedWorkers[req.WorkerId]
		if !ok {
			m.mu.Unlock()
			return &distproto.RegisterResponse{Accepted: false, Message: fmt.Sprintf("worker %q is not pinned by the coordinator", req.WorkerId)}, nil
		}
		pub, err := attest.ParsePublicKeyHex(wantHex)
		if err != nil {
			m.mu.Unlock()
			return &distproto.RegisterResponse{Accepted: false, Message: fmt.Sprintf("worker %q pin is invalid: %v", req.WorkerId, err)}, nil
		}
		m.workerPubs[req.WorkerId] = pub
		m.syncAttestationModeLocked()
	}
	m.registered[req.WorkerId] = req
	m.registeredAt[req.WorkerId] = time.Now()
	m.pruneRegisteredLocked()
	n := len(m.registered)
	m.mu.Unlock()
	m.cfg.Logf("worker registered: %s at %s (%d total)", req.WorkerId, req.Address, n)
	return &distproto.RegisterResponse{Accepted: true, Message: "registered"}, nil
}

// SetWorkerKey pins (or rotates) the Ed25519 public key of a worker id. An
// empty hex clears the pin. Callers must hold no lock; it takes the write lock
// itself.
func (m *Master) SetWorkerKey(workerID string, pubHex string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pubHex == "" {
		delete(m.workerPubs, workerID)
		m.syncAttestationModeLocked()
		return nil
	}
	pub, err := attest.ParsePublicKeyHex(pubHex)
	if err != nil {
		return fmt.Errorf("coordinator: pin worker %s: %w", workerID, err)
	}
	m.workerPubs[workerID] = pub
	m.syncAttestationModeLocked()
	return nil
}

// AuthorizedWorkerPub returns the pinned Ed25519 public key for workerID, if
// one is configured.
func (m *Master) AuthorizedWorkerPub(workerID string) (ed25519.PublicKey, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pub, ok := m.workerPubs[workerID]
	return pub, ok
}

// VerifyWorkerAttestation checks a worker-signed attestation (Ed25519 over a
// caller-built canonical message) against the public key pinned for workerID.
// It fails closed: an unknown worker, a bad signature, or a key that does not
// match the pinned identity is treated as unauthenticated, so callers must not
// act on telemetry that fails this check.
func (m *Master) VerifyWorkerAttestation(workerID string, pub ed25519.PublicKey, msg, sig []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	pinned, ok := m.workerPubs[workerID]
	if !ok {
		return false
	}
	if subtle.ConstantTimeCompare(pinned, pub) != 1 {
		return false
	}
	return attest.VerifySig(pinned, msg, sig)
}

// pruneRegisteredLocked drops registrations that have not been refreshed
// within registerTTL. Callers must hold m.mu.
func (m *Master) pruneRegisteredLocked() {
	cutoff := time.Now().Add(-registerTTL)
	for id, at := range m.registeredAt {
		if at.Before(cutoff) {
			delete(m.registered, id)
			delete(m.registeredAt, id)
			m.cfg.Logf("dropping stale registration %s (no re-register for %s)", id, registerTTL)
		}
	}
}

// Coordinate implements the master-side stream for workers that connect in.
func (m *Master) Coordinate(stream distproto.MasterWorker_CoordinateServer) error {
	for {
		cmd, err := stream.Recv()
		if err != nil {
			return err
		}
		switch cmd.Payload.(type) {
		case *distproto.WorkerCommand_GetStatus:
			if err := stream.Send(&distproto.WorkerEvent{
				Payload: &distproto.WorkerEvent_StatusReport{
					StatusReport: &distproto.StatusReport{
						WorkerId: "master",
						Healthy:  true,
					},
				},
			}); err != nil {
				return err
			}
		}
	}
}

// Ping implements the health probe.
func (m *Master) Ping(ctx context.Context, req *distproto.PingRequest) (*distproto.PingResponse, error) {
	return &distproto.PingResponse{Version: Version, WorkerId: "master"}, nil
}

// GetCapabilities advertises the master's capabilities.
func (m *Master) GetCapabilities(ctx context.Context, req *distproto.CapabilitiesRequest) (*distproto.CapabilitiesResponse, error) {
	maxUsers := 0
	if m.cfg.Scenario != nil {
		maxUsers = m.cfg.Scenario.Profile.Users
	}
	return &distproto.CapabilitiesResponse{
		Protocols:        []string{"http", "ws", "grpc", "tcp", "udp"},
		MaxUsers:         int32(maxUsers),
		MaxDurationSec:   7 * 24 * 3600,
		SupportsTls:      true,
		SupportsSessions: true,
	}, nil
}

// RegisteredWorkers returns the addresses of workers that self-registered.
func (m *Master) RegisteredWorkers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.registered))
	for _, r := range m.registered {
		out = append(out, r.Address)
	}
	sort.Strings(out)
	return out
}

// StatusReports returns the latest status report per connected worker (the
// heartbeat every worker streams over Coordinate). Address-keyed; each report
// carries the worker_id, active run count and system metrics. Used by the
// fleet health monitor and tests.
func (m *Master) StatusReports() map[string]*distproto.StatusReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]*distproto.StatusReport, len(m.statusReports))
	for addr, r := range m.statusReports {
		out[addr] = r
	}
	return out
}

// touch records that addr just sent an event; it keeps the liveness loop from
// declaring the worker dead.
func (m *Master) touch(addr string) {
	m.mu.Lock()
	m.lastSeen[addr] = time.Now()
	m.mu.Unlock()
}

// ResolveWorkers returns the static worker list, or waits for AutoWorkers
// registrations when auto-discovery is enabled.
func (m *Master) ResolveWorkers(ctx context.Context) ([]string, error) {
	if len(m.cfg.Workers) > 0 {
		return m.cfg.Workers, nil
	}
	if m.cfg.AutoWorkers <= 0 {
		return nil, errors.New("no workers configured: pass --workers or set --wait-workers")
	}
	timeout := m.cfg.RegisterTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		workers := m.RegisteredWorkers()
		if len(workers) >= m.cfg.AutoWorkers {
			return workers[:m.cfg.AutoWorkers], nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("timed out after %s waiting for %d workers (got %d)", timeout, m.cfg.AutoWorkers, len(workers))
		case <-ticker.C:
		}
	}
}

// Connect dials the workers, verifies each with a Ping and records the healthy
// ones. It errors only when no worker at all is reachable.
func (m *Master) Connect(ctx context.Context, workers []string) ([]string, error) {
	var healthy []string
	for _, addr := range workers {
		creds := insecure.NewCredentials()
		if m.cfg.ClientCreds != nil {
			creds = m.cfg.ClientCreds
		}
		conn, err := grpc.NewClient(addr, append([]grpc.DialOption{
			grpc.WithTransportCredentials(creds),
		}, ClientOptions(m.cfg.Token)...)...)
		if err != nil {
			m.cfg.Logf("worker %s dial failed: %v", addr, err)
			continue
		}
		client := distproto.NewMasterWorkerClient(conn)
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err = client.Ping(pingCtx, &distproto.PingRequest{})
		cancel()
		if err != nil {
			m.cfg.Logf("worker %s ping failed: %v", addr, err)
			conn.Close()
			continue
		}
		m.mu.Lock()
		m.conns[addr] = conn
		m.clients[addr] = client
		m.lastSeen[addr] = time.Now()
		m.mu.Unlock()
		healthy = append(healthy, addr)
		m.cfg.Logf("connected to worker: %s", addr)
	}
	if len(healthy) == 0 {
		return nil, errors.New("no reachable workers")
	}
	return healthy, nil
}

// StartRun opens a stream to every connected worker and dispatches the
// per-worker slice of the scenario.
func (m *Master) StartRun(ctx context.Context, runID string) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("run already started")
	}
	m.started = true
	m.runID = runID
	// Deterministic order keeps worker_index stable.
	addrs := make([]string, 0, len(m.clients))
	for addr := range m.clients {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)
	m.workerCount = len(addrs)
	if m.workerCount == 0 {
		m.mu.Unlock()
		return errors.New("no connected workers")
	}
	m.mu.Unlock()

	total := m.workerCount
	for i, addr := range addrs {
		m.mu.Lock()
		client := m.clients[addr]
		m.mu.Unlock()

		stream, err := client.Coordinate(ctx)
		if err != nil {
			return fmt.Errorf("worker %s stream: %w", addr, err)
		}
		m.mu.Lock()
		m.streams[addr] = stream
		m.mu.Unlock()

		workerScenario := SplitScenario(m.cfg.Scenario, i, total)
		if err := stream.Send(&distproto.WorkerCommand{
			Payload: &distproto.WorkerCommand_StartRun{
				StartRun: &distproto.StartRun{
					RunId:        runID,
					Scenario:     ScenarioToProto(workerScenario),
					WorkerIndex:  int32(i),
					TotalWorkers: int32(total),
					MasterAddr:   m.cfg.ListenAddr,
				},
			},
		}); err != nil {
			return fmt.Errorf("worker %s start: %w", addr, err)
		}
		m.cfg.Logf("started run %s on worker %s (%d users)", runID, addr, workerScenario.Profile.Users)
	}

	for _, addr := range addrs {
		m.mu.Lock()
		stream := m.streams[addr]
		m.mu.Unlock()
		go m.recvLoop(addr, stream)
	}
	go m.livenessLoop(addrs)

	if m.cfg.RunTimeout > 0 {
		m.mu.Lock()
		m.runTimeout = time.AfterFunc(m.cfg.RunTimeout, func() {
			m.cfg.Logf("run deadline %s exceeded; finalizing with partial results", m.cfg.RunTimeout)
			m.forceDone()
		})
		m.mu.Unlock()
	}
	return nil
}

func (m *Master) recvLoop(addr string, stream distproto.MasterWorker_CoordinateClient) {
	for {
		event, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				m.cfg.Logf("worker %s stream closed: %v", addr, err)
			}
			m.workerFinished(addr, true)
			return
		}
		switch p := event.Payload.(type) {
		case *distproto.WorkerEvent_RunProgress:
			// Verification happens before the snapshot can reach the
			// Aggregator; a rejected payload ends the connection.
			if !m.handleRunProgress(addr, p.RunProgress, stream) {
				return
			}
			m.touch(addr)
		case *distproto.WorkerEvent_RunCompleted:
			if !m.handleRunCompleted(addr, p.RunCompleted, stream) {
				return
			}
			m.cfg.Logf("worker %s completed run", addr)
			if p.RunCompleted != nil {
				m.storeReport(addr, p.RunCompleted.Report)
			}
			m.touch(addr)
			m.workerFinished(addr, false)
			return
		case *distproto.WorkerEvent_RunFailed:
			msg := ""
			if p.RunFailed != nil {
				msg = p.RunFailed.Error
			}
			m.cfg.Logf("worker %s run failed: %s", addr, msg)
			m.touch(addr)
			m.workerFinished(addr, true)
			return
		case *distproto.WorkerEvent_RunStarted:
			m.cfg.Logf("worker %s run started", addr)
			m.touch(addr)
		case *distproto.WorkerEvent_StatusReport:
			if p.StatusReport != nil {
				// Same fail-closed posture as progress/final-report: verify the
				// heartbeat signature before keeping it for the fleet monitor.
				if !m.handleStatusReport(addr, p.StatusReport, stream) {
					return
				}
				m.storeStatus(addr, p.StatusReport)
			}
			m.touch(addr)
		}
	}
}

// storeStatus keeps the worker's latest heartbeat for the fleet monitor.
func (m *Master) storeStatus(addr string, sr *distproto.StatusReport) {
	if sr == nil {
		return
	}
	m.mu.Lock()
	m.statusReports[addr] = sr
	m.mu.Unlock()
}

func (m *Master) storeReport(addr string, protoReport *distproto.Report) {
	rep := ReportFromProto(protoReport)
	if rep == nil {
		return
	}
	m.mu.Lock()
	m.reports[addr] = rep
	m.mu.Unlock()
}

func (m *Master) workerFinished(addr string, failed bool) {
	m.mu.Lock()
	if m.finished[addr] {
		m.mu.Unlock()
		return
	}
	m.finished[addr] = true
	m.completed++
	if failed {
		m.failed = append(m.failed, addr)
		m.agg.Forget(addr)
	}
	done := m.completed >= m.workerCount
	m.mu.Unlock()
	if done {
		m.finish()
	}
}

func (m *Master) finish() {
	m.mu.Lock()
	if m.runTimeout != nil {
		m.runTimeout.Stop()
	}
	m.mu.Unlock()
	m.doneOnce.Do(func() { close(m.doneCh) })
}

func (m *Master) forceDone() {
	m.doneOnce.Do(func() { close(m.doneCh) })
}

// livenessLoop runs for the duration of a run and watches for workers that
// stopped sending events (progress or heartbeats). Combined with a direct
// Ping probe this catches workers that are dead, partitioned or wedged with a
// still-open stream — which stream-close detection alone would miss.
func (m *Master) livenessLoop(addrs []string) {
	ticker := time.NewTicker(livenessCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.doneCh:
			return
		case <-ticker.C:
			m.checkLiveness(addrs)
		}
	}
}

func (m *Master) checkLiveness(addrs []string) {
	var stale []string
	now := time.Now()
	m.mu.Lock()
	for _, addr := range addrs {
		if m.finished[addr] {
			continue
		}
		last, ok := m.lastSeen[addr]
		if !ok || now.Sub(last) > livenessDeadline {
			stale = append(stale, addr)
		}
	}
	m.mu.Unlock()

	for _, addr := range stale {
		if m.probeWorker(addr) {
			// Alive, just quiet (e.g. a worker between runs). Reset the clock.
			m.cfg.Logf("worker %s was silent >%s but Ping succeeded; keeping it", addr, livenessDeadline)
			m.mu.Lock()
			m.lastSeen[addr] = time.Now()
			m.mu.Unlock()
			continue
		}
		m.cfg.Logf("worker %s DEAD: no heartbeat for %s and Ping failed", addr, livenessDeadline)
		m.mu.Lock()
		if s, ok := m.streams[addr]; ok {
			// Closing the send side unblocks recvLoop, which then marks the
			// worker finished through the normal path (idempotent).
			_ = s.CloseSend()
		}
		m.mu.Unlock()
		m.workerFinished(addr, true)
	}
}

// probeWorker asks a worker for its Ping response with a bounded deadline.
// A nil client (never connected) counts as unreachable.
func (m *Master) probeWorker(addr string) bool {
	m.mu.Lock()
	client := m.clients[addr]
	m.mu.Unlock()
	if client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Ping(ctx, &distproto.PingRequest{})
	return err == nil
}

// StopRun asks the workers to stop the run.
func (m *Master) StopRun(runID string, graceful bool) {
	m.mu.Lock()
	streams := make(map[string]distproto.MasterWorker_CoordinateClient, len(m.streams))
	for addr, s := range m.streams {
		streams[addr] = s
	}
	m.mu.Unlock()
	for addr, stream := range streams {
		if err := stream.Send(&distproto.WorkerCommand{
			Payload: &distproto.WorkerCommand_StopRun{
				StopRun: &distproto.StopRun{RunId: runID, Graceful: graceful},
			},
		}); err != nil {
			m.cfg.Logf("stop command to %s failed: %v", addr, err)
		}
	}
}

// FinalReport merges the reports received so far. It may be called before Done
// to inspect partial results.
func (m *Master) FinalReport() *report.Report {
	m.mu.Lock()
	list := make([]*report.Report, 0, len(m.reports))
	order := make([]string, 0, len(m.reports))
	for addr := range m.reports {
		order = append(order, addr)
	}
	sort.Strings(order)
	for _, addr := range order {
		list = append(list, m.reports[addr])
	}
	scenario := m.cfg.Scenario
	m.mu.Unlock()
	return MergeReports(scenario, list)
}

// Close releases all worker connections.
func (m *Master) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, conn := range m.conns {
		conn.Close()
	}
	m.conns = make(map[string]*grpc.ClientConn)
	m.clients = make(map[string]distproto.MasterWorkerClient)
}
