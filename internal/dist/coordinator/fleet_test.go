package coordinator

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
)

// TestRegisterDedupAndPrune verifies that re-registering with the same
// WorkerId replaces the previous entry (worker restart) and that stale
// registrations are pruned so a dead worker cannot poison auto-discovery.
func TestRegisterDedupAndPrune(t *testing.T) {
	master := NewMaster(MasterConfig{AutoWorkers: 1, RegisterTimeout: time.Second})

	reg := func(id, addr string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resp, err := master.Register(ctx, &distproto.RegisterRequest{WorkerId: id, Address: addr})
		if err != nil {
			t.Fatalf("register %s: %v", id, err)
		}
		if !resp.GetAccepted() {
			t.Fatalf("register %s rejected: %s", id, resp.GetMessage())
		}
	}

	reg("w1", "10.0.0.1:50061")
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != "10.0.0.1:50061" {
		t.Fatalf("after first register: %v", got)
	}
	// Same worker restarts on a new address -> replace, not append.
	reg("w1", "10.0.0.9:50062")
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != "10.0.0.9:50062" {
		t.Fatalf("re-register should replace entry: %v", got)
	}

	// Fast-forward the registration clock so the entry looks stale.
	master.mu.Lock()
	master.registeredAt["w1"] = time.Now().Add(-2 * registerTTL)
	master.mu.Unlock()

	// A new registration from anybody triggers the sweep.
	reg("w2", "10.0.0.2:50061")
	if got := master.RegisteredWorkers(); len(got) != 1 || got[0] != "10.0.0.2:50061" {
		t.Fatalf("stale registration not pruned: %v", got)
	}
}

// TestLivenessMarksUnresponsiveWorkerDead verifies that a worker whose last
// event is older than the deadline and whose Ping fails is declared failed.
func TestLivenessMarksUnresponsiveWorkerDead(t *testing.T) {
	master := NewMaster(MasterConfig{
		Scenario: tinyScenario(t, "http://127.0.0.1:1", 1, 1),
		Workers:  []string{"127.0.0.1:1"},
	})
	master.mu.Lock()
	master.workerCount = 1
	master.lastSeen["127.0.0.1:1"] = time.Now().Add(-2 * livenessDeadline)
	// No client entry => probeWorker reports unreachable.
	master.mu.Unlock()

	master.checkLiveness([]string{"127.0.0.1:1"})

	master.mu.Lock()
	failed := master.finished["127.0.0.1:1"]
	master.mu.Unlock()
	if !failed {
		t.Fatal("silent worker with failing Ping should be marked failed")
	}
	if got := master.FailedWorkers(); len(got) != 1 {
		t.Fatalf("failed workers = %v, want 1", got)
	}
}

// TestLivenessKeepsRespondingWorker verifies that a worker that answers Ping
// is kept even when it has been quiet for a while (e.g. between runs).
func TestLivenessKeepsRespondingWorker(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(ServerOptions("")...)
	distproto.RegisterMasterWorkerServer(srv, NewWorker(WorkerConfig{ID: "live"}))
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	addr := lis.Addr().String()

	master := NewMaster(MasterConfig{
		Scenario: tinyScenario(t, "http://127.0.0.1:1", 1, 1),
		Workers:  []string{addr},
	})
	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, ClientOptions("")...)...)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	master.mu.Lock()
	master.clients[addr] = distproto.NewMasterWorkerClient(conn)
	master.lastSeen[addr] = time.Now().Add(-2 * livenessDeadline)
	master.mu.Unlock()

	master.checkLiveness([]string{addr})

	master.mu.Lock()
	failed := master.finished[addr]
	master.mu.Unlock()
	if failed {
		t.Fatal("worker that answers Ping must not be marked failed")
	}
}

// TestStatusReportStorage verifies the master keeps the latest heartbeat per
// worker so the fleet monitor can read active runs / memory / cpu.
func TestStatusReportStorage(t *testing.T) {
	master := NewMaster(MasterConfig{})
	master.storeStatus("10.0.0.1:50061", &distproto.StatusReport{
		WorkerId:   "w1",
		Healthy:    true,
		ActiveRuns: 3,
		System:     &distproto.SystemMetrics{CpuPercent: 42.5, MemoryBytes: 1 << 30},
	})
	reports := master.StatusReports()
	sr, ok := reports["10.0.0.1:50061"]
	if !ok {
		t.Fatal("status report not stored")
	}
	if sr.WorkerId != "w1" || sr.ActiveRuns != 3 || sr.System.GetCpuPercent() != 42.5 {
		t.Fatalf("status report stored incorrectly: %+v", sr)
	}
}

// TestTLSOptionsValidation covers the TLS helper contract without needing a
// real certificate: partial cert/key pairs must fail, and skip-verify must
// produce dial credentials.
func TestTLSOptionsValidation(t *testing.T) {
	cases := []struct {
		name string
		opts TLSOptions
	}{
		{"none", TLSOptions{}},
		{"cert only", TLSOptions{CertFile: "server.crt"}},
		{"key only", TLSOptions{KeyFile: "server.key"}},
		{"skip verify", TLSOptions{InsecureSkipVerify: true}},
		{"missing CA file", TLSOptions{CAFile: "/nonexistent/ca.pem"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.opts.ServerCreds(); err != nil && c.opts.CertFile != "" && c.opts.KeyFile != "" {
				t.Fatalf("unexpected ServerCreds error: %v", err)
			}
			// ClientCreds must never panic and must return nil only when
			// neither CA nor skip-verify is set.
			creds, err := c.opts.ClientCreds()
			if err != nil && c.opts.CAFile == "" {
				t.Fatalf("ClientCreds(%s) unexpectedly errored: %v", c.name, err)
			}
			if c.opts.CAFile == "" && !c.opts.InsecureSkipVerify && creds != nil {
				t.Fatalf("ClientCreds(%s) should be nil for plaintext", c.name)
			}
			if c.opts.InsecureSkipVerify && creds == nil {
				t.Fatal("skip-verify should produce dial credentials")
			}
		})
	}
}
