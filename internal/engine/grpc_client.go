package engine

import (
	"context"
	"crypto/tls"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// grpcClient checks the health of a gRPC service via the standard
// grpc.health.v1.Health/Check RPC. The target may use a grpc:// (plaintext) or
// grpcs:// (TLS) scheme; a bare host:port is treated as plaintext. It reports
// status 200 when the service is SERVING and 503 otherwise.
func (e *Engine) grpcClient(ctx context.Context, target string, timeout time.Duration) (stepResult, []byte) {
	useTLS := false
	switch {
	case strings.HasPrefix(target, "grpcs://"):
		useTLS = true
		target = strings.TrimPrefix(target, "grpcs://")
	case strings.HasPrefix(target, "grpc://"):
		target = strings.TrimPrefix(target, "grpc://")
	}

	opts := []grpc.DialOption{}
	if useTLS {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	start := time.Now()
	conn, err := grpc.NewClient(strings.TrimRight(target, "/"), opts...)
	if err != nil {
		return classifyError(err, time.Since(start)), nil
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

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
