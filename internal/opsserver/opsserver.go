// Package opsserver serves the platform operations endpoints that
// orchestrators depend on:
//
//	GET /healthz  liveness  — always 200 while the process is up
//	GET /readyz   readiness — 200 only when every registered check passes
//	GET /metrics  Prometheus text exposition
//
// It is intentionally tiny and dependency-free so the master, the worker and
// the all-in-one binary can all embed the same server behind a `-http-addr`
// flag. The health/metrics endpoints are never authenticated: a locked-down
// process must still be probeable and scrapeable by the platform.
package opsserver

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/health"
)

// Options configures the operations server.
type Options struct {
	// Addr is the TCP listen address (e.g. "0.0.0.0:9090"). Required.
	Addr string

	// Readiness backs /readyz. When nil a fresh, always-ready checker is used.
	Readiness *health.Checker

	// Metrics is the /metrics handler. When nil /metrics answers 404.
	Metrics http.Handler

	// Logf receives lifecycle messages. Defaults to the standard logger.
	Logf func(format string, args ...any)
}

// Server is a minimal, always-on operations HTTP server.
type Server struct {
	srv  *http.Server
	ln   net.Listener
	logf func(format string, args ...any)
}

// New builds the server. It does not bind until Start is called.
func New(opt Options) *Server {
	checker := opt.Readiness
	if checker == nil {
		checker = health.NewChecker()
	}
	logf := opt.Logf
	if logf == nil {
		logf = log.Printf
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", checker.LivenessHandler())
	mux.HandleFunc("/readyz", checker.ReadinessHandler())
	if opt.Metrics != nil {
		mux.Handle("/metrics", opt.Metrics)
	} else {
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}

	return &Server{
		srv: &http.Server{
			Addr:              opt.Addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		logf: logf,
	}
}

// Handler exposes the routed handler (useful in tests and for embedding).
func (s *Server) Handler() http.Handler { return s.srv.Handler }

// Start binds the listen address and serves in a background goroutine. The
// returned error is a bind failure only; serve errors are reported through
// Logf and never crash the process.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logf("ops server: serve error: %v", err)
		}
	}()
	return nil
}

// Addr returns the bound address, or nil before Start.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Shutdown gracefully drains in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
