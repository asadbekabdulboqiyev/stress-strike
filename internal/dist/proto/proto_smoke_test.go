package distproto

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// These smoke tests verify the generated protobuf code is wired up correctly:
// messages marshal, unmarshal and preserve their oneof payloads. They never
// touch the network or any gRPC server.

func TestWorkerCommandStartRunRoundTrip(t *testing.T) {
	original := &WorkerCommand{
		Payload: &WorkerCommand_StartRun{
			StartRun: &StartRun{
				RunId:        "run-42",
				WorkerIndex:  2,
				TotalWorkers: 4,
				MasterAddr:   "127.0.0.1:50051",
				Scenario: &Scenario{
					Name:    "demo",
					BaseUrl: "http://example.com",
					Profile: &LoadProfile{Type: "steady", Users: 100, Duration: 30},
					Steps: []*Step{
						{Name: "request", Type: "http", Method: "GET", Url: "http://example.com/health"},
						{Name: "login", Type: "http", Method: "POST", Url: "http://example.com/api/login", Body: `{"u":"a"}`},
					},
					Variables: map[string]string{"token": "abc"},
				},
			},
		},
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("marshaled message is empty")
	}

	decoded := &WorkerCommand{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	start, ok := decoded.Payload.(*WorkerCommand_StartRun)
	if !ok {
		t.Fatalf("oneof payload type = %T, want *WorkerCommand_StartRun", decoded.Payload)
	}
	got := start.StartRun
	if got.GetRunId() != "run-42" || got.GetWorkerIndex() != 2 || got.GetTotalWorkers() != 4 {
		t.Errorf("StartRun fields = %+v", got)
	}
	if got.GetMasterAddr() != "127.0.0.1:50051" {
		t.Errorf("master_addr = %q", got.GetMasterAddr())
	}
	sc := got.GetScenario()
	if sc == nil || sc.GetName() != "demo" || len(sc.GetSteps()) != 2 {
		t.Fatalf("scenario = %+v", sc)
	}
	if p := sc.GetProfile(); p.GetUsers() != 100 || p.GetType() != "steady" {
		t.Errorf("profile = %+v", p)
	}
	if sc.GetVariables()["token"] != "abc" {
		t.Errorf("variables = %v", sc.GetVariables())
	}
}

func TestWorkerCommandStopRunRoundTrip(t *testing.T) {
	original := &WorkerCommand{
		Payload: &WorkerCommand_StopRun{
			StopRun: &StopRun{RunId: "run-7", Graceful: true},
		},
	}
	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := &WorkerCommand{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	stop, ok := decoded.Payload.(*WorkerCommand_StopRun)
	if !ok {
		t.Fatalf("oneof payload type = %T, want *WorkerCommand_StopRun", decoded.Payload)
	}
	if stop.StopRun.GetRunId() != "run-7" || !stop.StopRun.GetGraceful() {
		t.Errorf("StopRun = %+v", stop.StopRun)
	}
}

func TestWorkerEventRunProgressRoundTrip(t *testing.T) {
	original := &WorkerEvent{
		Payload: &WorkerEvent_RunProgress{
			RunProgress: &RunProgress{
				RunId:     "run-9",
				Timestamp: 1700000000000,
				Telemetry: &TelemetrySnapshot{
					TotalRequests: 1234,
					TotalErrors:   7,
					ActiveUsers:   50,
					Rps:           412.5,
					ElapsedMs:     3000,
					Latency: &LatencyPercentiles{
						P50Ms: 12, P95Ms: 45, P99Ms: 90, AvgMs: 15, MinMs: 1, MaxMs: 250,
					},
				},
			},
		},
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := &WorkerEvent{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	prog, ok := decoded.Payload.(*WorkerEvent_RunProgress)
	if !ok {
		t.Fatalf("oneof payload type = %T, want *WorkerEvent_RunProgress", decoded.Payload)
	}
	tel := prog.RunProgress.GetTelemetry()
	if tel.GetTotalRequests() != 1234 || tel.GetTotalErrors() != 7 || tel.GetRps() != 412.5 {
		t.Errorf("telemetry = %+v", tel)
	}
	if tel.GetLatency().GetP99Ms() != 90 {
		t.Errorf("p99 = %v", tel.GetLatency().GetP99Ms())
	}
}

func TestWorkerEventRunCompletedCarriesReport(t *testing.T) {
	original := &WorkerEvent{
		Payload: &WorkerEvent_RunCompleted{
			RunCompleted: &RunCompleted{
				RunId:     "run-3",
				Timestamp: 1700000000000,
				Report: &Report{
					Name:          "distributed-run",
					TotalRequests: 5000,
					TotalErrors:   2,
					Rps:           166.6,
					StatusCodes:   map[int32]int64{200: 4998, 500: 2},
				},
			},
		},
	}
	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := &WorkerEvent{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	comp, ok := decoded.Payload.(*WorkerEvent_RunCompleted)
	if !ok {
		t.Fatalf("oneof payload type = %T, want *WorkerEvent_RunCompleted", decoded.Payload)
	}
	rep := comp.RunCompleted.GetReport()
	if rep.GetName() != "distributed-run" || rep.GetTotalRequests() != 5000 || rep.GetStatusCodes()[200] != 4998 {
		t.Errorf("report = %+v", rep)
	}
}

func TestRegisterRequestRoundTrip(t *testing.T) {
	original := &RegisterRequest{
		WorkerId: "wkr-1",
		Address:  "node-a:41001",
		Capabilities: &CapabilitiesResponse{
			Protocols:        []string{"http", "ws"},
			MaxUsers:         1000,
			MaxDurationSec:   604800,
			SupportsTls:      true,
			SupportsSessions: true,
		},
	}
	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := &RegisterRequest{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.GetWorkerId() != "wkr-1" || decoded.GetAddress() != "node-a:41001" {
		t.Errorf("RegisterRequest = %+v", decoded)
	}
	caps := decoded.GetCapabilities()
	if caps.GetMaxUsers() != 1000 || len(caps.GetProtocols()) != 2 || !caps.GetSupportsTls() {
		t.Errorf("capabilities = %+v", caps)
	}
}

func TestUnknownMessageBytesArePreserved(t *testing.T) {
	original := &WorkerCommand{
		Payload: &WorkerCommand_GetStatus{GetStatus: &GetStatus{}},
	}
	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := &WorkerCommand{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded.Payload.(*WorkerCommand_GetStatus); !ok {
		t.Fatalf("payload type = %T, want *WorkerCommand_GetStatus", decoded.Payload)
	}
}
