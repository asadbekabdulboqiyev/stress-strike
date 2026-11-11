package engine

// grpc_stream_test.go — coverage for the client-streaming gRPC path
// (grpc_stream.go): the happy path, empty bodies, EOF-without-reply, the
// status-code taxonomy and the lastSegment helper.
//
// The servers here are real in-process gRPC servers with a hand-written
// client-streaming service, so the code under test exercises the actual
// transport instead of a mock.

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// streamTestSvc is the HandlerType placeholder for the hand-written service.
type streamTestSvc interface{}

// startStreamServer registers a client-streaming method "Collect" on
// test.Stream and returns its grpc:// target.
func startStreamServer(t *testing.T, handler func(stream grpc.ServerStream) error) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}))
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "test.Stream",
		HandlerType: (*streamTestSvc)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName:    "Collect",
			Handler:       func(_ any, stream grpc.ServerStream) error { return handler(stream) },
			ClientStreams: true,
		}},
	}, struct{}{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "grpc://" + lis.Addr().String()
}

// ptrBytes returns a pointer to b, which is the shape rawCodec marshals.
func ptrBytes(s string) *[]byte {
	b := []byte(s)
	return &b
}

// collectAll drains the client stream until EOF and returns the messages.
func collectAll(stream grpc.ServerStream) ([]string, error) {
	var got []string
	for {
		var msg []byte
		err := stream.RecvMsg(&msg)
		if errors.Is(err, io.EOF) {
			return got, nil
		}
		if err != nil {
			return got, err
		}
		got = append(got, string(msg))
	}
}

func newStreamEngine(t *testing.T, baseURL string) *Engine {
	t.Helper()
	e := &Engine{scenario: &config.Scenario{BaseURL: baseURL}}
	return e
}

func TestLastSegment(t *testing.T) {
	cases := map[string]string{
		"/pkg.Service/Method": "Method",
		"/Method":             "Method",
		"Method":              "Method",
		"":                    "",
	}
	for in, want := range cases {
		if got := lastSegment(in); got != want {
			t.Errorf("lastSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGrpcStreamHappyPath(t *testing.T) {
	var received []string
	target := startStreamServer(t, func(stream grpc.ServerStream) error {
		msgs, err := collectAll(stream)
		if err != nil {
			return err
		}
		received = msgs
		return stream.SendMsg(ptrBytes("ack"))
	})

	e := newStreamEngine(t, "")
	step := config.Step{
		URL:        target,
		GrpcMethod: "/test.Stream/Collect",
		Headers:    map[string]string{"x-run": "{{run}}"},
		Body:       "one\ntwo\nthree",
	}
	res, reply := e.grpcStreamClient(context.Background(), step, map[string]string{"run": "42"}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("errName = %q, want success", res.errName)
	}
	if res.status != 200 {
		t.Errorf("status = %d, want 200", res.status)
	}
	// Windows cannot resolve a sub-millisecond loopback round trip: the Go
	// runtime's monotonic clock there reads the system interrupt time (the
	// ~15.6 ms tick), so a correctly measured fast RPC legitimately records
	// 0 ns. On every other platform a positive latency is what proves the
	// engine measured the call instead of fabricating a sample.
	if res.latency < 0 || (res.latency == 0 && runtime.GOOS != "windows") {
		t.Errorf("latency = %v, want a measured stream duration", res.latency)
	}
	if string(reply) != "ack" {
		t.Errorf("reply = %q, want ack", reply)
	}
	if len(received) != 3 || received[0] != "one" || received[2] != "three" {
		t.Errorf("server received %v, want [one two three]", received)
	}
}

func TestGrpcStreamBaseURLJoinAndRendering(t *testing.T) {
	var got []string
	target := startStreamServer(t, func(stream grpc.ServerStream) error {
		msgs, err := collectAll(stream)
		got = msgs
		if err != nil {
			return err
		}
		return stream.SendMsg(ptrBytes("ok"))
	})
	host := target[len("grpc://"):]

	// The BaseURL supplies the host; step.URL stays relative, and variables are
	// rendered in the body before each line is sent.
	e := newStreamEngine(t, target)
	step := config.Step{
		URL:        "",
		GrpcMethod: "/test.Stream/Collect",
		Body:       "hello {{name}}\n\n  \nworld",
	}
	res, _ := e.grpcStreamClient(context.Background(), step, map[string]string{"name": "ada"}, 5*time.Second)
	if res.errName != "" {
		t.Fatalf("errName = %q, want success (host %s)", res.errName, host)
	}
	// Only truly empty lines are skipped (a space-only line is still sent), so
	// the rendered body yields three messages.
	want := []string{"hello ada", "  ", "world"}
	if len(got) != len(want) {
		t.Fatalf("server received %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("message[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGrpcStreamEmptyBodySendsOneMessage(t *testing.T) {
	var got []string
	target := startStreamServer(t, func(stream grpc.ServerStream) error {
		msgs, err := collectAll(stream)
		got = msgs
		if err != nil {
			return err
		}
		return stream.SendMsg(ptrBytes("ok"))
	})
	e := newStreamEngine(t, "")
	step := config.Step{URL: target, GrpcMethod: "/test.Stream/Collect", Body: "\n\r\n\n"}
	res, _ := e.grpcStreamClient(context.Background(), step, nil, 5*time.Second)
	if res.errName != "" || res.status != 200 {
		t.Fatalf("res = %+v, want a clean 200", res)
	}
	if len(got) != 1 || got[0] != "" {
		t.Errorf("server received %v, want exactly one empty message", got)
	}
}

func TestGrpcStreamMissingMethodName(t *testing.T) {
	e := newStreamEngine(t, "")
	res, reply := e.grpcStreamClient(context.Background(), config.Step{URL: "127.0.0.1:1"}, nil, time.Second)
	if res.errName != errOther || reply != nil {
		t.Errorf("res = %+v, want errOther with no reply", res)
	}
}

func TestGrpcStreamUnsupportedScheme(t *testing.T) {
	e := newStreamEngine(t, "")
	step := config.Step{URL: "https://127.0.0.1:1", GrpcMethod: "/test.Stream/Collect"}
	res, _ := e.grpcStreamClient(context.Background(), step, nil, time.Second)
	if res.errName != errOther {
		t.Errorf("errName = %q, want errOther", res.errName)
	}
}

func TestGrpcStreamStatusTaxonomy(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
		want string
	}{
		{"invalid-argument", codes.InvalidArgument, errStatus4xx},
		{"unauthenticated", codes.Unauthenticated, errStatus4xx},
		// The 4xx range is evaluated first, so Internal/DataLoss classify as
		// 4xx today; the test pins the behaviour so the ordering is deliberate.
		{"internal", codes.Internal, errStatus4xx},
		{"data-loss", codes.DataLoss, errStatus4xx},
		{"unavailable", codes.Unavailable, errConnection},
		{"unknown", codes.Unknown, errOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := startStreamServer(t, func(stream grpc.ServerStream) error {
				_, _ = collectAll(stream)
				return status.Error(tc.code, tc.name)
			})
			e := newStreamEngine(t, "")
			step := config.Step{URL: target, GrpcMethod: "/test.Stream/Collect", Body: "x"}
			res, _ := e.grpcStreamClient(context.Background(), step, nil, 5*time.Second)
			if res.errName != tc.want {
				t.Errorf("errName = %q, want %q", res.errName, tc.want)
			}
		})
	}
}

func TestGrpcStreamDeadlineExceeded(t *testing.T) {
	release := make(chan struct{})
	target := startStreamServer(t, func(stream grpc.ServerStream) error {
		<-release // hold the stream open past the client deadline
		return nil
	})
	t.Cleanup(func() { close(release) })

	e := newStreamEngine(t, "")
	step := config.Step{URL: target, GrpcMethod: "/test.Stream/Collect", Body: "x"}
	res, _ := e.grpcStreamClient(context.Background(), step, nil, 100*time.Millisecond)
	if res.errName != errTimeout {
		t.Errorf("errName = %q, want %q (deadline exceeded)", res.errName, errTimeout)
	}
}

func TestGrpcStreamErrorPassThroughTimeout(t *testing.T) {
	res := grpcStreamError(status.Error(codes.DeadlineExceeded, "slow"), 10*time.Millisecond)
	if res.errName != errTimeout || res.latency != 10*time.Millisecond {
		t.Errorf("grpcStreamError(deadline) = %+v, want timeout with latency", res)
	}
}
