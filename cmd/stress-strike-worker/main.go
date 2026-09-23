package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/dist/coordinator"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
)

var version = "0.12.0"

var (
	listenAddr = flag.String("listen", ":0", "Worker listen address")
	advertise  = flag.String("advertise", "", "Address advertised to the master (defaults to listen address)")
	masterAddr = flag.String("master", "", "Master address to self-register with (optional)")
	workerID   = flag.String("id", "", "Worker ID (auto-generated)")
	maxUsers   = flag.Int("max-users", 100000, "Max virtual users this worker will accept")
	maxRuns    = flag.Int("max-runs", 4, "Max concurrent runs this worker will accept")
	token      = flag.String("token", "", "Shared control-plane token (must match master)")
)

func main() {
	// Friendly flag errors + consistent help (exit 2 on usage errors).
	flag.CommandLine.Init("stress-strike-worker", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	workerHelp := func() {
		cliux.BoxHelp(os.Stderr,
			"stress-strike worker — distributed load-test worker node",
			[]string{
				"stress-strike worker --listen :50052",
				"stress-strike worker --listen :50052 --master coordinator:50051",
			},
			[]string{
				"# Start a worker on the default ephemeral port",
				"stress-strike worker",
				"",
				"# Fixed port, self-register with a master",
				"stress-strike worker --listen :50052 --master coordinator:50051",
				"",
				"# Shared control-plane token (must match master)",
				"stress-strike worker --listen :50052 --token secret",
			},
			flag.CommandLine)
	}
	cliux.Parse(flag.CommandLine, os.Args[1:], workerHelp, cliux.Options{
		Command: "worker",
		FlagSet: flag.CommandLine,
		Examples: []string{
			"stress-strike worker --listen :50052",
		},
	})
	coordinator.Version = version

	if *workerID == "" {
		hostname, _ := os.Hostname()
		*workerID = fmt.Sprintf("%s-%d", hostname, os.Getpid())
	}

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	*listenAddr = lis.Addr().String()
	advertised := resolveAdvertise(*advertise, lis)
	log.Printf("Starting worker %s on %s (advertised as %s)", *workerID, *listenAddr, advertised)

	worker := coordinator.NewWorker(coordinator.WorkerConfig{
		ID:                *workerID,
		MaxUsers:          *maxUsers,
		MaxConcurrentRuns: *maxRuns,
		Token:             *token,
	})

	grpcServer := grpc.NewServer(coordinator.ServerOptions(*token)...)
	distproto.RegisterMasterWorkerServer(grpcServer, worker)
	go func() {
		log.Printf("Worker gRPC listening on %s", lis.Addr())
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("Worker gRPC server error: %v", err)
		}
	}()

	stop := make(chan struct{})
	if *masterAddr != "" {
		go registrationLoop(*masterAddr, *workerID, advertised, *token, worker.Capabilities(), stop)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	close(stop)

	log.Println("Shutting down worker...")
	grpcServer.GracefulStop()
}

// resolveAdvertise decides which address to tell the master about. When the
// worker binds to a wildcard address, the hostname is substituted so the master
// can reach it.
func resolveAdvertise(explicit string, lis net.Listener) string {
	if explicit != "" {
		return explicit
	}
	tcp, ok := lis.Addr().(*net.TCPAddr)
	if !ok {
		return lis.Addr().String()
	}
	host := tcp.IP.String()
	if tcp.IP.IsUnspecified() {
		hostname, err := os.Hostname()
		if err != nil {
			host = "127.0.0.1"
		} else {
			host = hostname
		}
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", tcp.Port))
}

// registrationLoop keeps this worker visible to the master via the Register
// RPC, retrying periodically so a master restart re-discovers it.
func registrationLoop(masterAddr, id, advertised, token string, caps *distproto.CapabilitiesResponse, stop <-chan struct{}) {
	opts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, coordinator.ClientOptions(token)...)
	conn, err := grpc.NewClient(masterAddr, opts...)
	if err != nil {
		log.Printf("Failed to connect to master %s: %v", masterAddr, err)
		return
	}
	defer conn.Close()

	client := distproto.NewMasterWorkerClient(conn)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	lastErr := ""
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := client.Register(ctx, &distproto.RegisterRequest{
			WorkerId:     id,
			Address:      advertised,
			Capabilities: caps,
		})
		cancel()
		switch {
		case err != nil:
			if err.Error() != lastErr {
				log.Printf("Registration with master %s failed: %v", masterAddr, err)
				lastErr = err.Error()
			}
		case resp.GetAccepted():
			if lastErr != "" {
				log.Printf("Re-registered with master %s", masterAddr)
				lastErr = ""
			}
		default:
			log.Printf("Master %s rejected registration: %s", masterAddr, resp.GetMessage())
		}

		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}
