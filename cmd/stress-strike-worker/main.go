package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/engine"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

var (
	listenAddr = flag.String("listen", ":0", "Worker listen address")
	masterAddr = flag.String("master", "", "Master address to register with (optional)")
	workerID   = flag.String("id", "", "Worker ID (auto-generated)")
	maxUsers   = flag.Int("max-users", 100000, "Max virtual users")
)

func main() {
	flag.Parse()

	if *workerID == "" {
		hostname, _ := os.Hostname()
		*workerID = fmt.Sprintf("%s-%d", hostname, os.Getpid())
	}

	log.Printf("Starting worker %s on %s", *workerID, *listenAddr)

	// Start gRPC server
	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	*listenAddr = lis.Addr().String()

	grpcServer := grpc.NewServer()
	worker := &Worker{
		id:         *workerID,
		maxUsers:   *maxUsers,
		activeRuns: make(map[string]*runContext),
	}
	distproto.RegisterMasterWorkerServer(grpcServer, worker)

	go func() {
		log.Printf("Worker gRPC listening on %s", lis.Addr())
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("Worker gRPC server error: %v", err)
		}
	}()

	// Register with master if provided
	if *masterAddr != "" {
		go registerWithMaster(*masterAddr, *workerID, *listenAddr)
	}

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down worker...")
	grpcServer.GracefulStop()
}

func registerWithMaster(masterAddr, workerID, workerAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, masterAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect to master %s: %v", masterAddr, err)
		return
	}
	defer conn.Close()

	client := distproto.NewMasterWorkerClient(conn)
	_, err = client.Ping(ctx, &distproto.PingRequest{})
	if err != nil {
		log.Printf("Master ping failed: %v", err)
		return
	}

	// Register worker via GetCapabilities (used as registration)
	_, err = client.GetCapabilities(ctx, &distproto.CapabilitiesRequest{})
	if err != nil {
		log.Printf("Registration failed: %v", err)
	} else {
		log.Printf("Registered with master %s", masterAddr)
	}
}

// runContext holds state for an active run
type runContext struct {
	runID     string
	engine    *engine.Engine
	cancel    context.CancelFunc
	startTime time.Time
}

type Worker struct {
	id         string
	maxUsers   int
	activeRuns map[string]*runContext
	mu         sync.Mutex
	// Embed for gRPC
	distproto.UnimplementedMasterWorkerServer
}

// Implement MasterWorkerServer interface
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
			w.handleMigrateSession(p.MigrateSession)
		}
	}
}

func (w *Worker) handleStartRun(start *distproto.StartRun, stream distproto.MasterWorker_CoordinateServer) {
	log.Printf("Starting run %s (worker %d/%d)", start.RunId, start.WorkerIndex, start.TotalWorkers)

	scenario := w.protoToScenario(start.Scenario)
	if scenario == nil {
		log.Printf("Invalid scenario for run %s", start.RunId)
		stream.Send(&distproto.WorkerEvent{
			Payload: &distproto.WorkerEvent_RunFailed{
				RunFailed: &distproto.RunFailed{
					RunId: start.RunId,
					Error: "invalid scenario",
				},
			},
		})
		return
	}

	eng, err := engine.New(scenario)
	if err != nil {
		log.Printf("Engine creation failed for run %s: %v", start.RunId, err)
		stream.Send(&distproto.WorkerEvent{
			Payload: &distproto.WorkerEvent_RunFailed{
				RunFailed: &distproto.RunFailed{
					RunId: start.RunId,
					Error: err.Error(),
				},
			},
		})
		return
	}

	runCtx, cancel := context.WithCancel(context.Background())
	rc := &runContext{
		runID:     start.RunId,
		engine:    eng,
		cancel:    cancel,
		startTime: time.Now(),
	}

	w.mu.Lock()
	w.activeRuns[start.RunId] = rc
	w.mu.Unlock()

	// Notify master run started
	stream.Send(&distproto.WorkerEvent{
		Payload: &distproto.WorkerEvent_RunStarted{
			RunStarted: &distproto.RunStarted{
				RunId:     start.RunId,
				Timestamp: time.Now().UnixMilli(),
			},
		},
	})

	// Run engine with progress streaming
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()

		runDone := make(chan *metrics.Telemetry, 1)
		go func() {
			tel, err := eng.Run(runCtx, engine.RunOptions{
				Out:   nil,
				Quiet: true,
			})
			if err != nil {
				log.Printf("Run %s error: %v", start.RunId, err)
			}
			runDone <- tel
		}()

		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				// Telemetry is collected after run completes
				// For now, just send basic progress
				stream.Send(&distproto.WorkerEvent{
					Payload: &distproto.WorkerEvent_RunProgress{
						RunProgress: &distproto.RunProgress{
							RunId:     start.RunId,
							Timestamp: time.Now().UnixMilli(),
						},
					},
				})
			case tel := <-runDone:
				r := report.Build(tel, scenario)

				stream.Send(&distproto.WorkerEvent{
					Payload: &distproto.WorkerEvent_RunCompleted{
						RunCompleted: &distproto.RunCompleted{
							RunId:  start.RunId,
							Report: w.reportToProto(&r),
						},
					},
				})

				w.mu.Lock()
				delete(w.activeRuns, start.RunId)
				w.mu.Unlock()
				return
			}
		}
	}()
}

func (w *Worker) handleStopRun(stop *distproto.StopRun) {
	w.mu.Lock()
	rc, ok := w.activeRuns[stop.RunId]
	w.mu.Unlock()

	if !ok {
		return
	}

	if stop.Graceful {
		// Engine handles graceful drain
	}
	rc.cancel()
}

func (w *Worker) sendStatus(stream distproto.MasterWorker_CoordinateServer) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	w.mu.Lock()
	active := len(w.activeRuns)
	w.mu.Unlock()

	stream.Send(&distproto.WorkerEvent{
		Payload: &distproto.WorkerEvent_StatusReport{
			StatusReport: &distproto.StatusReport{
				WorkerId:   w.id,
				Healthy:    true,
				ActiveRuns: int64(active),
				System: &distproto.SystemMetrics{
					MemoryBytes: int64(m.Alloc),
					Goroutines:  int64(runtime.NumGoroutine()),
				},
			},
		},
	})
}

func (w *Worker) handleMigrateSession(mig *distproto.MigrateSession) {
	log.Printf("Session migration: %s -> %s", mig.SessionId, mig.TargetWorker)
}

func (w *Worker) protoToScenario(p *distproto.Scenario) *config.Scenario {
	if p == nil {
		return nil
	}

	sc := &config.Scenario{
		Name:      p.Name,
		BaseURL:   p.BaseUrl,
		Variables: p.Variables,
	}

	if p.Profile != nil {
		sc.Profile = config.Profile{
			Type:        p.Profile.Type,
			Users:       int(p.Profile.Users),
			Duration:    int(p.Profile.Duration),
			RampUp:      int(p.Profile.RampUp),
			SpikeUsers:  int(p.Profile.SpikeUsers),
			SpikeWarmup: int(p.Profile.SpikeWarmup),
			SpikeHold:   int(p.Profile.SpikeHold),
			WavePeriod:  int(p.Profile.WavePeriod),
			RPS:         int(p.Profile.Rps),
			Timeout:     int(p.Profile.Timeout),
			KeepAlive:   &p.Profile.KeepAlive,
		}
	}

	sc.Steps = make([]config.Step, len(p.Steps))
	for i, step := range p.Steps {
		sc.Steps[i] = config.Step{
			Name:          step.Name,
			Type:          step.Type,
			Method:        step.Method,
			URL:           step.Url,
			Headers:       step.Headers,
			Body:          step.Body,
			Timeout:       int(step.Timeout),
			FrameType:     step.FrameType,
			GrpcMethod:    step.GrpcMethod,
			AwaitResponse: step.AwaitResponse,
			Session:       step.Session,
		}
		for _, ext := range step.Extract {
			sc.Steps[i].Extract = append(sc.Steps[i].Extract, config.Extract{
				Name: ext.Name,
				From: ext.From,
				Path: ext.Path,
			})
		}
		for _, ass := range step.Assertions {
			sc.Steps[i].Assertions = append(sc.Steps[i].Assertions, config.Assertion{
				Type:  ass.Type,
				Value: ass.Value,
			})
		}
	}

	if p.Sla != nil {
		sc.SLA = &config.SLA{
			MaxP99Ms:        p.Sla.MaxP99Ms,
			MaxAvgMs:        p.Sla.MaxAvgMs,
			MaxErrorRatePct: p.Sla.MaxErrorRatePct,
			MinRPS:          p.Sla.MinRps,
		}
	}

	return sc
}

func (w *Worker) telemetryToProto(tel *metrics.Telemetry, snap metrics.HistogramSnapshot) *distproto.TelemetrySnapshot {
	return &distproto.TelemetrySnapshot{
		Timestamp:     time.Now().UnixMilli(),
		ElapsedMs:     tel.Elapsed().Milliseconds(),
		TotalRequests: int64(tel.TotalRequests()),
		TotalErrors:   int64(tel.TotalErrors()),
		Rps:           tel.RPS(),
		ActiveUsers:   tel.ActiveUsers.Load(),
		StatusCodes:   convertStatusCodes(tel.StatusCodes()),
		ErrorTypes:    convertErrors(tel.Errors()),
		Latency: &distproto.LatencyPercentiles{
			P50Ms: snap.Percentile(0.50).Milliseconds(),
			P95Ms: snap.Percentile(0.95).Milliseconds(),
			P99Ms: snap.Percentile(0.99).Milliseconds(),
			AvgMs: snap.Average.Milliseconds(),
			MinMs: snap.Min.Milliseconds(),
			MaxMs: snap.Max.Milliseconds(),
		},
	}
}

func (w *Worker) reportToProto(r *report.Report) *distproto.Report {
	return &distproto.Report{
		Name:          r.Name,
		BaseUrl:       r.BaseURL,
		LoadProfile:   r.LoadProfile,
		StartedAt:     r.StartedAt.UnixMilli(),
		EndedAt:       r.EndedAt.UnixMilli(),
		DurationMs:    r.Duration.Milliseconds(),
		ActiveUsers:   r.ActiveUsers,
		TotalRequests: int64(r.TotalRequests),
		TotalErrors:   int64(r.TotalErrors),
		ErrorRatePct:  r.ErrorRatePct,
		Rps:           r.RPS,
		StatusCodes:   convertStatusCodes(r.Status),
		Errors:        convertErrors(r.Errors),
		Overall:       w.stepReportToProto(&r.Overall),
		Steps:         w.stepsToProto(r.Steps),
		Sla:           w.slaResultsToProto(r.SLA),
		Timeline:      w.timelineToProto(r.Timeline),
	}
}

func (w *Worker) stepReportToProto(s *report.StepReport) *distproto.StepReport {
	return &distproto.StepReport{
		Name:        s.Name,
		Requests:    int64(s.Requests),
		Errors:      int64(s.Errors),
		StatusCodes: convertStatusCodes(s.Status),
		ErrorTypes:  convertErrors(s.ErrorTypes),
		MinMs:       s.Min.Milliseconds(),
		AvgMs:       s.Avg.Milliseconds(),
		MaxMs:       s.Max.Milliseconds(),
		P50Ms:       s.P50.Milliseconds(),
		P95Ms:       s.P95.Milliseconds(),
		P99Ms:       s.P99.Milliseconds(),
	}
}

func (w *Worker) stepsToProto(steps []report.StepReport) []*distproto.StepReport {
	out := make([]*distproto.StepReport, len(steps))
	for i, s := range steps {
		out[i] = w.stepReportToProto(&s)
	}
	return out
}

func (w *Worker) slaResultsToProto(results []report.SLAResult) []*distproto.SLAResult {
	out := make([]*distproto.SLAResult, len(results))
	for i, r := range results {
		out[i] = &distproto.SLAResult{
			Metric: r.Metric,
			Target: r.Target,
			Actual: r.Actual,
			Pass:   r.Pass,
		}
	}
	return out
}

func (w *Worker) timelineToProto(samples []metrics.TimelineSample) []*distproto.TimelineSample {
	out := make([]*distproto.TimelineSample, len(samples))
	for i, s := range samples {
		out[i] = &distproto.TimelineSample{
			Second:        int32(s.Second),
			RequestsTotal: int64(s.Requests),
			RequestsDelta: 0,
			ErrorsTotal:   int64(s.Errors),
			ErrorsDelta:   0,
			ActiveUsers:   s.ActiveUsers,
		}
	}
	return out
}

func convertStatusCodes(m map[int]uint64) map[int32]int64 {
	out := make(map[int32]int64, len(m))
	for k, v := range m {
		out[int32(k)] = int64(v)
	}
	return out
}

func convertErrors(m map[string]uint64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = int64(v)
	}
	return out
}

// Ping implements health check
func (w *Worker) Ping(ctx context.Context, req *distproto.PingRequest) (*distproto.PingResponse, error) {
	return &distproto.PingResponse{
		Version:  "0.2.0",
		WorkerId: w.id,
	}, nil
}

func (w *Worker) GetCapabilities(ctx context.Context, req *distproto.CapabilitiesRequest) (*distproto.CapabilitiesResponse, error) {
	return &distproto.CapabilitiesResponse{
		Protocols:        []string{"http", "ws", "grpc", "tcp", "udp"},
		MaxUsers:         int32(w.maxUsers),
		MaxDurationSec:   7 * 24 * 3600,
		SupportsTls:      true,
		SupportsSessions: true,
	}, nil
}

// Must embed for gRPC
func (w *Worker) mustEmbedUnimplementedMasterWorkerServer() {}
