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
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/cliux"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/dist/coordinator"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
)

var version = "0.14.3"

var (
	listenAddr = flag.String("listen", ":0", "Worker listen address")
	advertise  = flag.String("advertise", "", "Address advertised to the master (defaults to listen address)")
	masterAddr = flag.String("master", "", "Master address to self-register with (optional)")
	workerID   = flag.String("id", "", "Worker ID (auto-generated)")
	maxUsers   = flag.Int("max-users", 100000, "Max virtual users this worker will accept")
	maxRuns    = flag.Int("max-runs", 4, "Max concurrent runs this worker will accept")
	token      = flag.String("token", "", "Shared control-plane token (must match master)")
	tlsCert    = flag.String("tls-cert", "", "TLS server certificate (serve over TLS; pair with -tls-key)")
	tlsKey     = flag.String("tls-key", "", "TLS server private key (pair with -tls-cert)")
	tlsCA      = flag.String("tls-ca", "", "CA bundle used to verify the master this worker registers with")
	tlsSkip    = flag.Bool("tls-skip-verify", false, "Disable master verification when self-registering (self-signed demo fleets only)")
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

	// Optional TLS: serve over TLS when a cert/key pair is supplied, and dial
	// the master over TLS when -tls-ca or -tls-skip-verify is supplied.
	tlsOpts := coordinator.TLSOptions{
		CertFile:           *tlsCert,
		KeyFile:            *tlsKey,
		CAFile:             *tlsCA,
		InsecureSkipVerify: *tlsSkip,
	}
	serverCreds, err := tlsOpts.ServerCreds()
	if err != nil {
		log.Fatal(err)
	}
	clientCreds, err := tlsOpts.ClientCreds()
	if err != nil {
		log.Fatal(err)
	}
	if tlsOpts.Enabled() && clientCreds == nil {
		log.Printf("WARNING: -tls-cert/-tls-key enable incoming TLS only; registration dials to the master stay plaintext unless -tls-ca or -tls-skip-verify is passed")
	}

	serverOpts := coordinator.ServerOptions(*token)
	if serverCreds != nil {
		serverOpts = append(serverOpts, grpc.Creds(serverCreds))
		log.Printf("Worker gRPC serving with TLS (cert=%s)", *tlsCert)
	}
	grpcServer := grpc.NewServer(serverOpts...)
	distproto.RegisterMasterWorkerServer(grpcServer, worker)
	go func() {
		log.Printf("Worker gRPC listening on %s", lis.Addr())
		if err := grpcServer.Serve(lis); err != nil {
			log.Printf("Worker gRPC server error: %v", err)
		}
	}()

	stop := make(chan struct{})
	if *masterAddr != "" {
		go registrationLoop(*masterAddr, *workerID, advertised, *token, clientCreds, worker.Capabilities(), stop)
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

// Registration retry policy. The worker re-registers every regSteadyInterval
// so a restarted master re-discovers it quickly, but after a failure it backs
// off through a fixed sequence (1s, 2s, 5s, 10s, 20s, then 30s forever) so a
// down master is not hammered from a large fleet.
const (
	regSteadyInterval = 10 * time.Second
	regBackoffMax     = 30 * time.Second
)

var regBackoffSeq = [...]time.Duration{1 * time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}

// nextRegBackoff returns the wait for the given attempt index and the index
// for the following attempt (clamped at the maximum backoff).
func nextRegBackoff(i int) (time.Duration, int) {
	if i >= len(regBackoffSeq)-1 {
		return regBackoffSeq[len(regBackoffSeq)-1], len(regBackoffSeq) - 1
	}
	return regBackoffSeq[i], i + 1
}

// registrationLoop keeps this worker visible to the master via the Register
// RPC. The dial is deliberately re-created when the backoff saturates so a
// master that moved addresses (or a stale connection) is retried from a clean
// state, not just retried over a dead pipe.
func registrationLoop(masterAddr, id, advertised, token string, clientCreds credentials.TransportCredentials, caps *distproto.CapabilitiesResponse, stop <-chan struct{}) {
	creds := insecure.NewCredentials()
	if clientCreds != nil {
		creds = clientCreds
	}
	dial := func() *grpc.ClientConn {
		conn, err := grpc.NewClient(masterAddr, append([]grpc.DialOption{
			grpc.WithTransportCredentials(creds),
		}, coordinator.ClientOptions(token)...)...)
		if err != nil {
			return nil
		}
		return conn
	}
	conn := dial()
	if conn == nil {
		log.Printf("Failed to create client for master %s", masterAddr)
		return
	}
	defer conn.Close()

	client := distproto.NewMasterWorkerClient(conn)
	lastErr := ""
	wait := regSteadyInterval
	backoffIdx := 0
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
			wait, backoffIdx = nextRegBackoff(backoffIdx)
			if wait >= regBackoffMax {
				// Clean-slate re-dial: close the stale connection and open a
				// fresh one so a restarted/moved master is picked up.
				_ = conn.Close()
				conn = dial()
				if conn == nil {
					log.Printf("Failed to re-dial master %s; will retry", masterAddr)
					wait = regBackoffMax
				} else {
					client = distproto.NewMasterWorkerClient(conn)
				}
			}
		case resp.GetAccepted():
			if lastErr != "" {
				log.Printf("Re-registered with master %s", masterAddr)
				lastErr = ""
			}
			wait = regSteadyInterval
			backoffIdx = 0
		default:
			log.Printf("Master %s rejected registration: %s", masterAddr, resp.GetMessage())
			wait, backoffIdx = nextRegBackoff(backoffIdx)
		}

		select {
		case <-stop:
			return
		case <-time.After(wait):
		}
	}
}
