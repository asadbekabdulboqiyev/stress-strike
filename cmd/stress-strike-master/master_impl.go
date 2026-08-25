package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"stress-strike/internal/config"
	distproto "stress-strike/internal/dist/proto"
	"stress-strike/internal/report"
)

type Master struct {
	scenario    *config.Scenario
	workerAddrs []string
	listenAddr  string
	regressPct  float64
	comparePath string
	timeline    bool

	mu            sync.Mutex
	workerConns   map[string]*grpc.ClientConn
	workerClients map[string]distproto.MasterWorkerClient
	workerStreams map[string]distproto.MasterWorker_CoordinateClient

	runID       string
	doneCh      chan struct{}
	doneOnce    sync.Once
	finalReport *report.Report
	telemetry   *aggregatedTelemetry
	// Embed for gRPC
	distproto.UnimplementedMasterWorkerServer
}

type aggregatedTelemetry struct {
	mu             sync.Mutex
	totalRequests  uint64
	totalErrors    uint64
	activeUsers    int64
	statusCodes    map[int]uint64
	errors         map[string]uint64
	latencySamples []int64
	stepTelemetry  map[string]*stepAgg
	startTime      time.Time
}

type stepAgg struct {
	requests    uint64
	errors      uint64
	latencies   []int64
	statusCodes map[int]uint64
	errorsMap   map[string]uint64
}

func NewMaster(scenario *config.Scenario, workers []string, listenAddr string, regressPct float64, comparePath string, timeline bool) *Master {
	return &Master{
		scenario:      scenario,
		workerAddrs:   workers,
		listenAddr:    listenAddr,
		regressPct:    regressPct,
		comparePath:   comparePath,
		timeline:      timeline,
		workerConns:   make(map[string]*grpc.ClientConn),
		workerClients: make(map[string]distproto.MasterWorkerClient),
		workerStreams: make(map[string]distproto.MasterWorker_CoordinateClient),
		doneCh:        make(chan struct{}),
		telemetry: &aggregatedTelemetry{
			statusCodes:    make(map[int]uint64),
			errors:         make(map[string]uint64),
			latencySamples: make([]int64, 0, 10000),
			stepTelemetry:  make(map[string]*stepAgg),
			startTime:      time.Now(),
		},
	}
}

func (m *Master) ConnectWorkers(ctx context.Context) error {
	for _, addr := range m.workerAddrs {
		conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("worker %s: %v", addr, err)
		}
		m.workerConns[addr] = conn
		m.workerClients[addr] = distproto.NewMasterWorkerClient(conn)
		log.Printf("Connected to worker: %s", addr)
	}
	return nil
}

func (m *Master) StartRun(ctx context.Context, runID string) error {
	m.runID = runID

	// Distribute users across workers
	usersPerWorker := m.scenario.Profile.Users / len(m.workerAddrs)
	if usersPerWorker == 0 {
		usersPerWorker = 1
	}
	remainder := m.scenario.Profile.Users % len(m.workerAddrs)

	completedWorkers := 0
	var completeMu sync.Mutex

	for i, addr := range m.workerAddrs {
		client := m.workerClients[addr]
		stream, err := client.Coordinate(ctx)
		if err != nil {
			return fmt.Errorf("worker %s stream: %v", addr, err)
		}
		m.workerStreams[addr] = stream

		workerUsers := usersPerWorker
		if i < remainder {
			workerUsers++
		}

		workerScenario := m.scenarioForWorker(workerUsers)
		protoScen := m.scenarioToProto(workerScenario)

		err = stream.Send(&distproto.WorkerCommand{
			Payload: &distproto.WorkerCommand_StartRun{
				StartRun: &distproto.StartRun{
					RunId:        runID,
					Scenario:     protoScen,
					WorkerIndex:  int32(i),
					TotalWorkers: int32(len(m.workerAddrs)),
					MasterAddr:   m.listenAddr,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("worker %s start: %v", addr, err)
		}
		log.Printf("Started run %s on worker %s (%d users)", runID, addr, workerUsers)
	}

	// Collect results from all workers
	for addr, stream := range m.workerStreams {
		go func(a string, s distproto.MasterWorker_CoordinateClient) {
			for {
				event, err := s.Recv()
				if err != nil {
					log.Printf("Worker %s stream closed: %v", a, err)
					return
				}

				switch p := event.Payload.(type) {
				case *distproto.WorkerEvent_RunProgress:
					if p.RunProgress.Telemetry != nil {
						m.aggregateTelemetry(p.RunProgress.Telemetry)
					}
				case *distproto.WorkerEvent_RunCompleted:
					log.Printf("Worker %s completed run", a)
					m.mu.Lock()
					if m.finalReport == nil {
						m.finalReport = m.buildFinalReport(p.RunCompleted.Report)
					} else {
						m.mergeReport(p.RunCompleted.Report)
					}
					m.mu.Unlock()

					completeMu.Lock()
					completedWorkers++
					if completedWorkers == len(m.workerAddrs) {
						close(m.doneCh)
					}
					completeMu.Unlock()
				case *distproto.WorkerEvent_RunFailed:
					log.Printf("Worker %s run failed: %s", a, p.RunFailed.Error)
					completeMu.Lock()
					completedWorkers++
					if completedWorkers == len(m.workerAddrs) {
						close(m.doneCh)
					}
					completeMu.Unlock()
				case *distproto.WorkerEvent_RunStarted:
					log.Printf("Worker %s run started", a)
				case *distproto.WorkerEvent_StatusReport:
				}
			}
		}(addr, stream)
	}

	return nil
}

func (m *Master) StopRun(runID string, graceful bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for addr, stream := range m.workerStreams {
		err := stream.Send(&distproto.WorkerCommand{
			Payload: &distproto.WorkerCommand_StopRun{
				StopRun: &distproto.StopRun{
					RunId:    runID,
					Graceful: graceful,
				},
			},
		})
		if err != nil {
			log.Printf("Stop command to %s failed: %v", addr, err)
		}
	}
}

func (m *Master) aggregateTelemetry(t *distproto.TelemetrySnapshot) {
	m.telemetry.mu.Lock()
	defer m.telemetry.mu.Unlock()

	m.telemetry.totalRequests += uint64(t.TotalRequests)
	m.telemetry.totalErrors += uint64(t.TotalErrors)
	m.telemetry.activeUsers = t.ActiveUsers

	for code, count := range t.StatusCodes {
		m.telemetry.statusCodes[int(code)] += uint64(count)
	}
	for err, count := range t.ErrorTypes {
		m.telemetry.errors[err] += uint64(count)
	}

	m.telemetry.latencySamples = append(m.telemetry.latencySamples, t.Latency.P50Ms)
	m.telemetry.latencySamples = append(m.telemetry.latencySamples, t.Latency.P95Ms)
	m.telemetry.latencySamples = append(m.telemetry.latencySamples, t.Latency.P99Ms)

	for _, step := range t.Steps {
		if m.telemetry.stepTelemetry[step.Name] == nil {
			m.telemetry.stepTelemetry[step.Name] = &stepAgg{
				statusCodes: make(map[int]uint64),
				errorsMap:   make(map[string]uint64),
			}
		}
		sa := m.telemetry.stepTelemetry[step.Name]
		sa.requests += uint64(step.Requests)
		sa.errors += uint64(step.Errors)
		sa.latencies = append(sa.latencies, step.Latency.P50Ms)
		sa.latencies = append(sa.latencies, step.Latency.P95Ms)
		sa.latencies = append(sa.latencies, step.Latency.P99Ms)
		for code, count := range step.StatusCodes {
			sa.statusCodes[int(code)] += uint64(count)
		}
		for errName, count := range step.ErrorTypes {
			sa.errorsMap[errName] += uint64(count)
		}
	}
}

func (m *Master) buildFinalReport(r *distproto.Report) *report.Report {
	return &report.Report{
		Name:          r.Name,
		BaseURL:       r.BaseUrl,
		LoadProfile:   r.LoadProfile,
		StartedAt:     time.UnixMilli(r.StartedAt),
		EndedAt:       time.UnixMilli(r.EndedAt),
		Duration:      time.Duration(r.DurationMs) * time.Millisecond,
		ActiveUsers:   r.ActiveUsers,
		TotalRequests: uint64(r.TotalRequests),
		TotalErrors:   uint64(r.TotalErrors),
		ErrorRatePct:  r.ErrorRatePct,
		RPS:           r.Rps,
		Status:        convertProtoStatus(r.StatusCodes),
		Errors:        convertProtoErrors(r.Errors),
		Overall: report.StepReport{
			Name:       r.Overall.Name,
			Requests:   uint64(r.Overall.Requests),
			Errors:     uint64(r.Overall.Errors),
			Status:     convertProtoStatus(r.Overall.StatusCodes),
			ErrorTypes: convertProtoErrors(r.Overall.ErrorTypes),
			Min:        time.Duration(r.Overall.MinMs) * time.Millisecond,
			Avg:        time.Duration(r.Overall.AvgMs) * time.Millisecond,
			Max:        time.Duration(r.Overall.MaxMs) * time.Millisecond,
			P50:        time.Duration(r.Overall.P50Ms) * time.Millisecond,
			P95:        time.Duration(r.Overall.P95Ms) * time.Millisecond,
			P99:        time.Duration(r.Overall.P99Ms) * time.Millisecond,
		},
	}
}

func (m *Master) mergeReport(r *distproto.Report) {
	if m.finalReport == nil {
		m.finalReport = m.buildFinalReport(r)
		return
	}
	m.finalReport.TotalRequests += uint64(r.TotalRequests)
	m.finalReport.TotalErrors += uint64(r.TotalErrors)
	m.finalReport.ErrorRatePct = float64(m.finalReport.TotalErrors) / float64(m.finalReport.TotalRequests) * 100
	m.finalReport.RPS = float64(m.finalReport.TotalRequests) / m.finalReport.Duration.Seconds()

	for code, count := range r.StatusCodes {
		m.finalReport.Status[int(code)] += uint64(count)
	}
	for err, count := range r.Errors {
		m.finalReport.Errors[err] += uint64(count)
	}
}

func (m *Master) GetFinalReport() *report.Report {
	m.doneOnce.Do(func() {
		close(m.doneCh)
	})
	return m.finalReport
}

// Implement MasterWorkerServer interface for worker registration
func (m *Master) Coordinate(stream distproto.MasterWorker_CoordinateServer) error {
	// Handle worker registration and health checks
	for {
		cmd, err := stream.Recv()
		if err != nil {
			return err
		}
		switch cmd.Payload.(type) {
		case *distproto.WorkerCommand_GetStatus:
			stream.Send(&distproto.WorkerEvent{
				Payload: &distproto.WorkerEvent_StatusReport{
					StatusReport: &distproto.StatusReport{
						WorkerId:   "master",
						Healthy:    true,
						ActiveRuns: 0,
					},
				},
			})
		}
	}
}

func (m *Master) Ping(ctx context.Context, req *distproto.PingRequest) (*distproto.PingResponse, error) {
	return &distproto.PingResponse{
		Version:  "0.2.0",
		WorkerId: "master",
	}, nil
}

func (m *Master) GetCapabilities(ctx context.Context, req *distproto.CapabilitiesRequest) (*distproto.CapabilitiesResponse, error) {
	return &distproto.CapabilitiesResponse{
		Protocols:        []string{"http", "ws", "grpc", "tcp", "udp"},
		MaxUsers:         int32(m.scenario.Profile.Users),
		MaxDurationSec:   7 * 24 * 3600,
		SupportsTls:      true,
		SupportsSessions: true,
	}, nil
}

func (m *Master) scenarioForWorker(users int) *config.Scenario {
	sc := *m.scenario
	sc.Profile.Users = users
	return &sc
}

func (m *Master) scenarioToProto(sc *config.Scenario) *distproto.Scenario {
	return &distproto.Scenario{
		Name:      sc.Name,
		BaseUrl:   sc.BaseURL,
		Variables: sc.Variables,
		Profile: &distproto.LoadProfile{
			Type:        sc.Profile.Type,
			Users:       int32(sc.Profile.Users),
			Duration:    int32(sc.Profile.Duration),
			RampUp:      int32(sc.Profile.RampUp),
			SpikeUsers:  int32(sc.Profile.SpikeUsers),
			SpikeWarmup: int32(sc.Profile.SpikeWarmup),
			SpikeHold:   int32(sc.Profile.SpikeHold),
			WavePeriod:  int32(sc.Profile.WavePeriod),
			Rps:         int32(sc.Profile.RPS),
			Timeout:     int32(sc.Profile.Timeout),
			KeepAlive:   sc.Profile.KeepAlive != nil && *sc.Profile.KeepAlive,
		},
		Steps: m.stepsToProto(sc.Steps),
		Sla:   m.slaToProto(sc.SLA),
	}
}

func (m *Master) stepsToProto(steps []config.Step) []*distproto.Step {
	out := make([]*distproto.Step, len(steps))
	for i, s := range steps {
		out[i] = &distproto.Step{
			Name:          s.Name,
			Type:          s.Type,
			Method:        s.Method,
			Url:           s.URL,
			Headers:       s.Headers,
			Body:          s.Body,
			Timeout:       int32(s.Timeout),
			FrameType:     s.FrameType,
			GrpcMethod:    s.GrpcMethod,
			AwaitResponse: s.AwaitResponse,
			Session:       s.Session,
		}
		for _, ext := range s.Extract {
			out[i].Extract = append(out[i].Extract, &distproto.Extract{
				Name: ext.Name,
				From: ext.From,
				Path: ext.Path,
			})
		}
		for _, ass := range s.Assertions {
			out[i].Assertions = append(out[i].Assertions, &distproto.Assertion{
				Type:  ass.Type,
				Value: ass.Value,
			})
		}
	}
	return out
}

func (m *Master) slaToProto(sla *config.SLA) *distproto.SLA {
	if sla == nil || slaEmpty(sla) {
		return nil
	}
	return &distproto.SLA{
		MaxP99Ms:        sla.MaxP99Ms,
		MaxAvgMs:        sla.MaxAvgMs,
		MaxErrorRatePct: sla.MaxErrorRatePct,
		MinRps:          sla.MinRPS,
	}
}

func convertProtoStatus(m map[int32]int64) map[int]uint64 {
	out := make(map[int]uint64, len(m))
	for k, v := range m {
		out[int(k)] = uint64(v)
	}
	return out
}

func convertProtoErrors(m map[string]int64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = uint64(v)
	}
	return out
}

// Must embed for gRPC
func (m *Master) mustEmbedUnimplementedMasterWorkerServer() {}
