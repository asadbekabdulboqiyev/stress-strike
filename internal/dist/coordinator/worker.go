package coordinator

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

const (
	progressInterval  = 200 * time.Millisecond
	heartbeatInterval = 2 * time.Second
)

// WorkerConfig configures a load-generating worker.
type WorkerConfig struct {
	ID                string
	MaxUsers          int
	MaxConcurrentRuns int
	Token             string
	Logf              func(format string, args ...any)
}

type runContext struct {
	runID     string
	engine    *engine.Engine
	cancel    context.CancelFunc
	startTime time.Time
}

// Worker receives commands from a master, executes the engine and streams live
// telemetry plus the final report back.
type Worker struct {
	cfg WorkerConfig
	distproto.UnimplementedMasterWorkerServer

	mu         sync.Mutex
	activeRuns map[string]*runContext
	sendMu     sync.Mutex

	// CPU sampler state: last rusage sample + wall-clock timestamp. Used to
	// fill SystemMetrics.CpuPercent in heartbeats (process CPU, % of one core).
	cpuMu    sync.Mutex
	lastCPU  syscall.Rusage
	lastCPUT time.Time
}

// NewWorker builds a worker from the configuration.
func NewWorker(cfg WorkerConfig) *Worker {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Worker{
		cfg:        cfg,
		activeRuns: make(map[string]*runContext),
	}
}

// ID returns the worker identifier.
func (w *Worker) ID() string { return w.cfg.ID }

// ActiveRuns returns the number of runs currently executing.
func (w *Worker) ActiveRuns() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.activeRuns)
}

// Coordinate implements the worker-side command loop.
func (w *Worker) Coordinate(stream distproto.MasterWorker_CoordinateServer) error {
	for {
		cmd, err := stream.Recv()
		if err != nil {
			return err
		}
		switch p := cmd.Payload.(type) {
		case *distproto.WorkerCommand_StartRun:
			w.handleStartRun(p.StartRun, stream)
		case *distproto.WorkerCommand_StopRun:
			w.handleStopRun(p.StopRun)
		case *distproto.WorkerCommand_GetStatus:
			w.sendStatus(stream)
		case *distproto.WorkerCommand_MigrateSession:
			// Session migration is a planned control-plane feature. Until it is
			// implemented inside the engine, sessions are NOT transferred
			// between workers; the command is acknowledged by logging only.
			// See docs/DISTRIBUTED.md → "Session migration (planned)".
			w.cfg.Logf("session migration requested: %s -> %s (planned feature; not implemented yet)", p.MigrateSession.SessionId, p.MigrateSession.TargetWorker)
		}
	}
}

// send serializes writes to a single gRPC stream, which is not safe for
// concurrent use.
func (w *Worker) send(stream distproto.MasterWorker_CoordinateServer, event *distproto.WorkerEvent) error {
	w.sendMu.Lock()
	defer w.sendMu.Unlock()
	return stream.Send(event)
}

func (w *Worker) sendFailure(stream distproto.MasterWorker_CoordinateServer, runID, msg string) {
	_ = w.send(stream, &distproto.WorkerEvent{
		Payload: &distproto.WorkerEvent_RunFailed{
			RunFailed: &distproto.RunFailed{
				RunId:     runID,
				Timestamp: time.Now().UnixMilli(),
				Error:     msg,
			},
		},
	})
}

func (w *Worker) handleStartRun(start *distproto.StartRun, stream distproto.MasterWorker_CoordinateServer) {
	if start == nil {
		return
	}
	w.cfg.Logf("starting run %s (worker %d/%d)", start.RunId, start.WorkerIndex, start.TotalWorkers)

	scenario, ok := ScenarioFromProto(start.Scenario)
	if !ok {
		w.sendFailure(stream, start.RunId, "invalid scenario")
		return
	}
	if w.cfg.MaxUsers > 0 && scenario.Profile.Users > w.cfg.MaxUsers {
		w.sendFailure(stream, start.RunId, fmt.Sprintf("requested %d users exceeds max-users %d", scenario.Profile.Users, w.cfg.MaxUsers))
		return
	}

	w.mu.Lock()
	if w.cfg.MaxConcurrentRuns > 0 && len(w.activeRuns) >= w.cfg.MaxConcurrentRuns {
		w.mu.Unlock()
		w.sendFailure(stream, start.RunId, "worker at max concurrent runs")
		return
	}
	if _, exists := w.activeRuns[start.RunId]; exists {
		w.mu.Unlock()
		w.sendFailure(stream, start.RunId, "run id already active")
		return
	}
	w.mu.Unlock()

	eng, err := engine.New(scenario)
	if err != nil {
		w.sendFailure(stream, start.RunId, err.Error())
		return
	}

	runCtx, cancel := context.WithCancel(context.Background())
	rc := &runContext{runID: start.RunId, engine: eng, cancel: cancel, startTime: time.Now()}
	w.mu.Lock()
	w.activeRuns[start.RunId] = rc
	w.mu.Unlock()

	if err := w.send(stream, &distproto.WorkerEvent{
		Payload: &distproto.WorkerEvent_RunStarted{
			RunStarted: &distproto.RunStarted{RunId: start.RunId, Timestamp: time.Now().UnixMilli()},
		},
	}); err != nil {
		cancel()
		w.removeRun(start.RunId)
		return
	}

	go w.runStream(runCtx, start, stream, eng, scenario)
}

func (w *Worker) removeRun(runID string) {
	w.mu.Lock()
	delete(w.activeRuns, runID)
	w.mu.Unlock()
}

func (w *Worker) runStream(runCtx context.Context, start *distproto.StartRun, stream distproto.MasterWorker_CoordinateServer, eng *engine.Engine, scenario *config.Scenario) {
	defer w.removeRun(start.RunId)

	type runResult struct {
		tel *metrics.Telemetry
		err error
	}
	resultCh := make(chan runResult, 1)
	go func() {
		tel, err := eng.Run(runCtx, engine.RunOptions{Quiet: true})
		resultCh <- runResult{tel: tel, err: err}
	}()

	progress := time.NewTicker(progressInterval)
	defer progress.Stop()
	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-progress.C:
			tel := eng.Telemetry()
			if tel == nil {
				continue
			}
			snap := TelemetryToProto(tel, tel.Overall.Latency.Snapshot())
			if err := w.send(stream, &distproto.WorkerEvent{
				Payload: &distproto.WorkerEvent_RunProgress{
					RunProgress: &distproto.RunProgress{
						RunId:     start.RunId,
						Timestamp: time.Now().UnixMilli(),
						Telemetry: snap,
					},
				},
			}); err != nil {
				w.cfg.Logf("progress send failed for %s: %v", start.RunId, err)
				w.cancelRun(start.RunId)
				return
			}
		case <-heartbeat.C:
			w.sendStatus(stream)
		case res := <-resultCh:
			if res.err != nil && res.tel == nil {
				w.cfg.Logf("run %s failed: %v", start.RunId, res.err)
				w.sendFailure(stream, start.RunId, res.err.Error())
				return
			}
			if res.err != nil {
				w.cfg.Logf("run %s ended with error: %v", start.RunId, res.err)
			}
			r := report.Build(res.tel, scenario)
			if err := w.send(stream, &distproto.WorkerEvent{
				Payload: &distproto.WorkerEvent_RunCompleted{
					RunCompleted: &distproto.RunCompleted{
						RunId:     start.RunId,
						Timestamp: time.Now().UnixMilli(),
						Report:    ReportToProto(&r),
					},
				},
			}); err != nil {
				w.cfg.Logf("final report send failed for %s: %v", start.RunId, err)
			}
			return
		}
	}
}

func (w *Worker) cancelRun(runID string) {
	w.mu.Lock()
	rc := w.activeRuns[runID]
	w.mu.Unlock()
	if rc != nil {
		rc.cancel()
	}
}

func (w *Worker) handleStopRun(stop *distproto.StopRun) {
	if stop == nil {
		return
	}
	w.cancelRun(stop.RunId)
}

func (w *Worker) sendStatus(stream distproto.MasterWorker_CoordinateServer) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	_ = w.send(stream, &distproto.WorkerEvent{
		Payload: &distproto.WorkerEvent_StatusReport{
			StatusReport: &distproto.StatusReport{
				WorkerId:   w.cfg.ID,
				Healthy:    true,
				ActiveRuns: int64(w.ActiveRuns()),
				System: &distproto.SystemMetrics{
					CpuPercent:  w.cpuPercent(),
					MemoryBytes: int64(m.Alloc),
					Goroutines:  int64(runtime.NumGoroutine()),
				},
			},
		},
	})
}

// cpuPercent returns the worker process's CPU usage since the previous sample
// as a percentage of one core (e.g. 250 = 2.5 cores on a multi-core host).
// The first sample returns 0 because there is no baseline yet.
func (w *Worker) cpuPercent() float64 {
	w.cpuMu.Lock()
	defer w.cpuMu.Unlock()
	var now syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &now); err != nil {
		return 0
	}
	nowT := time.Now()
	if w.lastCPUT.IsZero() {
		w.lastCPU = now
		w.lastCPUT = nowT
		return 0
	}
	wall := nowT.Sub(w.lastCPUT).Seconds()
	if wall <= 0 {
		return 0
	}
	cpuDelta := rusageCPUSeconds(&now) - rusageCPUSeconds(&w.lastCPU)
	w.lastCPU = now
	w.lastCPUT = nowT
	pct := cpuDelta / wall * 100
	if pct < 0 {
		return 0
	}
	return pct
}

func rusageCPUSeconds(ru *syscall.Rusage) float64 {
	return float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6 +
		float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
}

// Ping implements the health probe.
func (w *Worker) Ping(ctx context.Context, req *distproto.PingRequest) (*distproto.PingResponse, error) {
	return &distproto.PingResponse{Version: Version, WorkerId: w.cfg.ID}, nil
}

// GetCapabilities advertises what this worker can run.
func (w *Worker) GetCapabilities(ctx context.Context, req *distproto.CapabilitiesRequest) (*distproto.CapabilitiesResponse, error) {
	return w.Capabilities(), nil
}

// Capabilities returns the worker's advertised limits.
func (w *Worker) Capabilities() *distproto.CapabilitiesResponse {
	return &distproto.CapabilitiesResponse{
		Protocols:        []string{"http", "ws", "grpc", "tcp", "udp"},
		MaxUsers:         int32(w.cfg.MaxUsers),
		MaxDurationSec:   7 * 24 * 3600,
		SupportsTls:      true,
		SupportsSessions: true,
	}
}
