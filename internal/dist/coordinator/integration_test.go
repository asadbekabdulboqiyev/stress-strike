package coordinator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
)

func startWorker(t *testing.T, cfg WorkerConfig) (string, *grpc.Server) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(ServerOptions(cfg.Token)...)
	distproto.RegisterMasterWorkerServer(srv, NewWorker(cfg))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), srv
}

func tinyScenario(t *testing.T, url string, users, duration int) *config.Scenario {
	t.Helper()
	sc := &config.Scenario{
		Name: "it",
		Profile: config.Profile{
			Type:     "steady",
			Users:    users,
			Duration: duration,
			Timeout:  5,
		},
		Steps: []config.Step{{Name: "req", Method: "GET", URL: url}},
	}
	if err := sc.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return sc
}

func TestDistributedRunAggregatesAcrossWorkers(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	addr1, _ := startWorker(t, WorkerConfig{ID: "w1", MaxUsers: 1000})
	addr2, _ := startWorker(t, WorkerConfig{ID: "w2", MaxUsers: 1000})

	master := NewMaster(MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 6, 1),
		Workers:    []string{addr1, addr2},
		ListenAddr: "127.0.0.1:0",
		RunTimeout: 20 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	workers, err := master.Connect(ctx, master.cfg.Workers)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(workers) != 2 {
		t.Fatalf("expected 2 workers, got %d", len(workers))
	}

	if err := master.StartRun(ctx, "run-it"); err != nil {
		t.Fatalf("start run: %v", err)
	}

	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("timed out waiting for run completion")
	}

	if got := len(master.FailedWorkers()); got != 0 {
		t.Fatalf("unexpected failed workers: %v", master.FailedWorkers())
	}

	rep := master.FinalReport()
	if rep == nil {
		t.Fatal("nil final report")
	}
	if rep.TotalRequests == 0 {
		t.Fatal("no requests recorded")
	}
	if rep.RPS <= 0 {
		t.Fatalf("expected positive RPS, got %f", rep.RPS)
	}
	if rep.Status[200] == 0 {
		t.Fatalf("expected 200 responses, got status map %v", rep.Status)
	}
	if len(rep.Steps) != 1 || rep.Steps[0].Requests == 0 {
		t.Fatalf("expected one populated step, got %+v", rep.Steps)
	}
	if rep.Duration <= 0 {
		t.Fatalf("expected positive duration, got %s", rep.Duration)
	}
	if hits.Load() == 0 {
		t.Fatal("target server was never hit")
	}

	agg := master.Aggregator().Snapshot()
	if agg.Workers != 2 {
		t.Fatalf("expected 2 live workers in aggregate, got %d", agg.Workers)
	}
}

func TestMasterAutoDiscovery(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	addr, _ := startWorker(t, WorkerConfig{ID: "auto1", MaxUsers: 100})

	// Worker registers itself with the master via the Register RPC.
	master := NewMaster(MasterConfig{
		Scenario:        tinyScenario(t, target.URL, 2, 1),
		AutoWorkers:     1,
		RegisterTimeout: 5 * time.Second,
	})
	defer master.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, ClientOptions("")...)...)
	if err != nil {
		t.Fatalf("dial worker: %v", err)
	}
	defer conn.Close()

	// Register through a directly constructed master server.
	serverLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(ServerOptions("")...)
	distproto.RegisterMasterWorkerServer(srv, master)
	go func() { _ = srv.Serve(serverLis) }()
	defer srv.Stop()

	mconn, err := grpc.NewClient(serverLis.Addr().String(), append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, ClientOptions("")...)...)
	if err != nil {
		t.Fatalf("dial master: %v", err)
	}
	defer mconn.Close()
	if _, err := distproto.NewMasterWorkerClient(mconn).Register(ctx, &distproto.RegisterRequest{
		WorkerId: "auto1",
		Address:  addr,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	resolved, err := master.ResolveWorkers(ctx)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(resolved) != 1 || resolved[0] != addr {
		t.Fatalf("expected [%s], got %v", addr, resolved)
	}
}

func TestAuthTokenEnforced(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	addr, _ := startWorker(t, WorkerConfig{ID: "secured", Token: "s3cr3t"})

	// Wrong token: worker rejects Ping, so Connect reports no reachable workers.
	wrong := NewMaster(MasterConfig{Scenario: tinyScenario(t, target.URL, 1, 1), Workers: []string{addr}, Token: "wrong"})
	defer wrong.Close()
	if _, err := wrong.Connect(context.Background(), []string{addr}); err == nil {
		t.Fatal("expected connect to fail with wrong token")
	}

	// Correct token succeeds.
	right := NewMaster(MasterConfig{Scenario: tinyScenario(t, target.URL, 1, 1), Workers: []string{addr}, Token: "s3cr3t"})
	defer right.Close()
	if _, err := right.Connect(context.Background(), []string{addr}); err != nil {
		t.Fatalf("connect with correct token: %v", err)
	}
}

func TestMasterToleratesDeadWorker(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	addr1, _ := startWorker(t, WorkerConfig{ID: "live", MaxUsers: 1000})

	master := NewMaster(MasterConfig{
		Scenario:   tinyScenario(t, target.URL, 4, 1),
		Workers:    []string{addr1, "127.0.0.1:1"},
		RunTimeout: 20 * time.Second,
	})
	defer master.Close()

	ctx := context.Background()
	workers, err := master.Connect(ctx, master.cfg.Workers)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(workers) != 1 {
		t.Fatalf("expected 1 reachable worker, got %d", len(workers))
	}

	if err := master.StartRun(ctx, "run-dead"); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-master.Done():
	case <-time.After(25 * time.Second):
		t.Fatal("run never completed despite one live worker")
	}
	if master.FinalReport().TotalRequests == 0 {
		t.Fatal("expected partial report from live worker")
	}
}
