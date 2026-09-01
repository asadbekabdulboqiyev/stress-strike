package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

func init() {
	// Register a pass-through codec so generic Invoke can carry raw payloads
	// for user-specified grpc_method steps. It only activates when a call
	// explicitly requests it via grpc.ForceCodec(rawCodec{}); normal proto
	// calls are unaffected.
	encoding.RegisterCodec(rawCodec{})
}

type rawCodec struct{}

func (rawCodec) Name() string { return "raw" }

func (rawCodec) Marshal(v interface{}) ([]byte, error) {
	switch b := v.(type) {
	case *[]byte:
		if b == nil || *b == nil {
			return []byte{}, nil
		}
		return *b, nil
	default:
		return nil, fmt.Errorf("raw codec: unsupported type %T", v)
	}
}

func (rawCodec) Unmarshal(data []byte, v interface{}) error {
	switch b := v.(type) {
	case *[]byte:
		out := make([]byte, len(data))
		copy(out, data)
		*b = out
		return nil
	default:
		return fmt.Errorf("raw codec: unsupported type %T", v)
	}
}

const (
	grpcKeepAliveTime    = 30 * time.Second
	grpcKeepAliveTimeout = 10 * time.Second
)

// splitGRPCTarget separates the grpc:// / grpcs:// scheme from host:port and
// reports whether TLS was requested. A bare host:port is treated as plaintext.
func splitGRPCTarget(target string) (host string, useTLS bool, err error) {
	switch {
	case strings.HasPrefix(target, "grpcs://"):
		return strings.TrimRight(strings.TrimPrefix(target, "grpcs://"), "/"), true, nil
	case strings.HasPrefix(target, "grpc://"):
		return strings.TrimRight(strings.TrimPrefix(target, "grpc://"), "/"), false, nil
	case strings.Contains(target, "://"):
		return "", false, fmt.Errorf("unsupported gRPC scheme in %q", target)
	default:
		return strings.TrimRight(target, "/"), false, nil
	}
}

// sharedGRPCConn returns a pooled ClientConn for the target, dialing lazily on
// first use. Reusing one HTTP/2 connection across iterations removes per-call
// handshake overhead and mirrors how real clients talk to gRPC servers. With
// keep-alive disabled every call dials a fresh, throwaway connection.
func (e *Engine) sharedGRPCConn(ctx context.Context, host string, useTLS bool, timeout time.Duration) (*grpc.ClientConn, error) {
	key := host
	if useTLS {
		key = "tls:" + host
	}

	e.sessMu.Lock()
	if e.grpcConns != nil {
		if conn, ok := e.grpcConns[key]; ok {
			e.sessMu.Unlock()
			return conn, nil
		}
	}
	e.sessMu.Unlock()

	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                grpcKeepAliveTime,
			Timeout:             grpcKeepAliveTimeout,
			PermitWithoutStream: true,
		}),
	}
	if useTLS {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, err
	}

	e.sessMu.Lock()
	e.initSessionMaps()
	if e.grpcConns == nil {
		e.grpcConns = make(map[string]*grpc.ClientConn)
	}
	// A concurrent worker may have dialed the same target meanwhile; keep one.
	if existing, ok := e.grpcConns[key]; ok {
		e.sessMu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	e.grpcConns[key] = conn
	e.sessMu.Unlock()
	return conn, nil
}

// grpcClient checks the health of a gRPC service via the standard
// grpc.health.v1.Health/Check RPC. The target may use a grpc:// (plaintext) or
// grpcs:// (TLS) scheme; a bare host:port is treated as plaintext. It reports
// status 200 when the service is SERVING and 503 otherwise.
func (e *Engine) grpcClient(ctx context.Context, target string, timeout time.Duration) (stepResult, []byte) {
	host, useTLS, err := splitGRPCTarget(target)
	if err != nil {
		return stepResult{errName: errOther}, nil
	}

	conn, err := e.sharedGRPCConn(ctx, host, useTLS, timeout)
	if err != nil {
		return classifyError(err, 0), nil
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	client := grpc_health_v1.NewHealthClient(conn)
	resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	latency := time.Since(start)
	if err != nil {
		if status.Code(err) == codes.DeadlineExceeded {
			return stepResult{latency: latency, errName: errTimeout}, nil
		}
		return classifyError(err, latency), nil
	}

	switch resp.GetStatus() {
	case grpc_health_v1.HealthCheckResponse_SERVING:
		return stepResult{latency: latency, status: 200}, []byte(resp.GetStatus().String())
	default:
		return stepResult{latency: latency, status: 503, errName: errStatus5xx}, []byte(resp.GetStatus().String())
	}
}

// grpcMethodClient invokes an arbitrary unary method (step.GrpcMethod, e.g.
// "/pkg.Service/Method") carrying step.Body as the raw request payload.
// step.Headers become outgoing metadata. Responses are returned as raw bytes,
// so assertions (regex/json_path) work against real payloads.
func (e *Engine) grpcMethodClient(ctx context.Context, target string, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	host, useTLS, err := splitGRPCTarget(target)
	if err != nil {
		return stepResult{errName: errOther}, nil
	}

	conn, err := e.sharedGRPCConn(ctx, host, useTLS, timeout)
	if err != nil {
		return classifyError(err, 0), nil
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	md := metadata.New(nil)
	for k, v := range step.Headers {
		md.Set(k, render(v, vars))
	}
	if md.Len() > 0 {
		callCtx = metadata.NewOutgoingContext(callCtx, md)
	}

	payload := []byte(renderBody(step.Body, vars))
	var reply []byte

	start := time.Now()
	err = conn.Invoke(callCtx, step.GrpcMethod, &payload, &reply, grpc.ForceCodec(rawCodec{}))
	latency := time.Since(start)
	if err != nil {
		if status.Code(err) == codes.DeadlineExceeded {
			return stepResult{latency: latency, errName: errTimeout}, nil
		}
		res := classifyError(err, latency)
		// Map gRPC error codes onto status families so assertions/reporting
		// stay consistent with HTTP semantics where sensible.
		if code := status.Code(err); code == codes.Unavailable {
			res.errName = errConnection
		} else if code >= codes.InvalidArgument && code <= codes.Unauthenticated {
			res.errName = errStatus4xx
		} else if code >= codes.Internal && code <= codes.DataLoss {
			res.errName = errStatus5xx
		} else {
			res.errName = errOther
		}
		return res, nil
	}
	return stepResult{latency: latency, status: 200}, reply
}
