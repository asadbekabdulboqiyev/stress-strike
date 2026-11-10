package http3

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestCheckAltSvcAdvertisesH3(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	got, err := checkAltSvc(host, port)
	if err != nil {
		t.Fatalf("checkAltSvc: %v", err)
	}
	if !got {
		t.Error("server with Alt-Svc h3= must be detected as H3-capable")
	}
}

func TestCheckAltSvcNoH3(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	got, err := checkAltSvc(host, port)
	if err != nil {
		t.Fatalf("checkAltSvc: %v", err)
	}
	if got {
		t.Error("server without Alt-Svc must not be flagged")
	}
}

func TestCheckAltSvcUnreachable(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	got, err := checkAltSvc(host, port)
	if err == nil || got {
		t.Fatalf("unreachable target must produce an error, got reachable=%v err=%v", got, err)
	}
}

func TestProbeUnreachableTarget(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	res, err := Probe(host, port)
	if err != nil {
		t.Fatalf("Probe must not error on an unreachable target: %v", err)
	}
	if res.H3Reachable {
		t.Error("H3 must not be reachable on a closed port")
	}
	if res.Error == "" {
		t.Error("expected an error message on the probe result")
	}
}
