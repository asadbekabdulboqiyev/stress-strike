package main

// registration_test.go — coverage for the worker's master re-registration
// policy and loop. A fake in-process gRPC master drives the accepted, rejected
// and transport-error branches without any real fleet.

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	distproto "github.com/asadbekabdulboqiyev/sift/internal/dist/proto"
)

func TestNextRegBackoffSequence(t *testing.T) {
	idx := 0
	var got []time.Duration
	for i := 0; i < 8; i++ {
		var d time.Duration
		d, idx = nextRegBackoff(idx)
		got = append(got, d)
	}
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 5 * time.Second,
		10 * time.Second, 20 * time.Second, 30 * time.Second,
		30 * time.Second, 30 * time.Second,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backoff[%d] = %v, want %v (seq=%v)", i, got[i], want[i], got)
		}
	}
}

func TestNextRegBackoffClampsIndex(t *testing.T) {
	d, next := nextRegBackoff(len(regBackoffSeq) - 1)
	if d != regBackoffMax || next != len(regBackoffSeq)-1 {
		t.Errorf("nextRegBackoff(max) = (%v, %d), want (%v, %d)",
			d, next, regBackoffMax, len(regBackoffSeq)-1)
	}
}

// fakeMaster answers Register with a programmable verdict.
type fakeMaster struct {
	distproto.UnimplementedMasterWorkerServer
	calls    atomic.Int32
	accept   bool
	errFirst bool
}

func (f *fakeMaster) Register(context.Context, *distproto.RegisterRequest) (*distproto.RegisterResponse, error) {
	n := f.calls.Add(1)
	if f.errFirst && n == 1 {
		return nil, status.Error(codes.Unavailable, "master restarting")
	}
	return &distproto.RegisterResponse{Accepted: f.accept, Message: "rejected by test"}, nil
}

func startFakeMaster(t *testing.T, fm *fakeMaster) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	distproto.RegisterMasterWorkerServer(srv, fm)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// runRegistration drives registrationLoop until stop is closed and reports how
// many Register calls the master saw.
func runRegistration(t *testing.T, masterAddr string, fm *fakeMaster, settle time.Duration) int32 {
	t.Helper()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		registrationLoop(masterAddr, "worker-test", "127.0.0.1:50052", "tok", nil, &distproto.CapabilitiesResponse{
			Protocols:      []string{"http"},
			MaxUsers:       100,
			MaxDurationSec: 60,
		}, stop)
		close(done)
	}()
	time.Sleep(settle)
	close(stop)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("registrationLoop did not return after stop closed")
	}
	return fm.calls.Load()
}

func TestRegistrationLoopAcceptedThenStop(t *testing.T) {
	fm := &fakeMaster{accept: true}
	addr := startFakeMaster(t, fm)
	if got := runRegistration(t, addr, fm, 150*time.Millisecond); got < 1 {
		t.Errorf("Register calls = %d, want at least 1", got)
	}
}

func TestRegistrationLoopRejectedBacksOff(t *testing.T) {
	fm := &fakeMaster{accept: false}
	addr := startFakeMaster(t, fm)
	// The first rejection waits 1s; settling for 1.3s yields a second attempt.
	if got := runRegistration(t, addr, fm, 1300*time.Millisecond); got < 2 {
		t.Errorf("Register calls = %d, want at least 2 across a backoff", got)
	}
}

func TestRegistrationLoopRecoversAfterError(t *testing.T) {
	fm := &fakeMaster{accept: true, errFirst: true}
	addr := startFakeMaster(t, fm)
	// First attempt errors, retry after 1s succeeds (and logs "Re-registered").
	if got := runRegistration(t, addr, fm, 1500*time.Millisecond); got < 2 {
		t.Errorf("Register calls = %d, want at least 2 (error then success)", got)
	}
}

func TestRegistrationLoopUnreachableMaster(t *testing.T) {
	// A loopback port with nothing listening: every Register fails, so the loop
	// keeps backing off until stop closes.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		registrationLoop(addr, "worker-test", "127.0.0.1:50052", "", nil, nil, stop)
		close(done)
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("registrationLoop did not return after stop closed")
	}
}
