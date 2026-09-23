package engine

// grpc_stream.go — client-streaming gRPC support for the step flow.
//
// A grpc step with grpc_stream: true (or type: grpc-stream) performs a
// client-streaming RPC instead of a unary call: every non-empty line of the
// rendered body is sent as one SendMsg, the stream is half-closed with
// CloseSend and a single response is read with RecvMsg. Latency covers the
// whole streaming exchange; assertions and extract work against the reply.
//
// This file is deliberately self-contained (no edits to grpc_client.go), so
// it cannot conflict with the protocol team's work on the existing clients.

import (
	"context"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

// grpcStreamClient performs one client-streaming RPC on the pooled connection.
func (e *Engine) grpcStreamClient(ctx context.Context, step config.Step, vars map[string]string, timeout time.Duration) (stepResult, []byte) {
	// Resolve the target exactly like runStepForUser does for regular steps
	// (BaseURL prefix + variable rendering).
	target := step.URL
	if e.scenario.BaseURL != "" {
		target = strings.TrimRight(e.scenario.BaseURL, "/") + "/" + strings.TrimLeft(step.URL, "/")
	}
	target = render(target, vars)

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

	if step.GrpcMethod == "" {
		return stepResult{errName: errOther}, nil
	}
	desc := &grpc.StreamDesc{
		StreamName:    lastSegment(step.GrpcMethod),
		ClientStreams: true,
		ServerStreams: false,
	}
	cs, err := conn.NewStream(callCtx, desc, step.GrpcMethod, grpc.ForceCodec(rawCodec{}))
	if err != nil {
		return classifyError(err, 0), nil
	}

	start := time.Now()
	sent := 0
	for _, line := range strings.Split(renderBody(step.Body, vars), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue // blank separators are not messages
		}
		payload := []byte(line)
		if err := cs.SendMsg(&payload); err != nil {
			return grpcStreamError(err, time.Since(start)), nil
		}
		sent++
	}
	if sent == 0 {
		// A completely empty body still sends one empty message so the RPC
		// is well-formed.
		payload := []byte{}
		if err := cs.SendMsg(&payload); err != nil {
			return grpcStreamError(err, time.Since(start)), nil
		}
	}
	if err := cs.CloseSend(); err != nil {
		return grpcStreamError(err, time.Since(start)), nil
	}

	var reply []byte
	if err := cs.RecvMsg(&reply); err != nil {
		latency := time.Since(start)
		// Some client-streaming APIs close the stream without a reply.
		if err == io.EOF {
			return stepResult{latency: latency, status: 200}, nil
		}
		return grpcStreamError(err, latency), nil
	}
	return stepResult{latency: time.Since(start), status: 200}, reply
}

// grpcStreamError maps an RPC error onto the same taxonomy as the unary gRPC
// client (timeout / connection / 4xx / 5xx) so reporting stays consistent.
func grpcStreamError(err error, latency time.Duration) stepResult {
	if status.Code(err) == codes.DeadlineExceeded {
		return stepResult{latency: latency, errName: errTimeout}
	}
	res := classifyError(err, latency)
	switch code := status.Code(err); {
	case code == codes.Unavailable:
		res.errName = errConnection
	case code >= codes.InvalidArgument && code <= codes.Unauthenticated:
		res.errName = errStatus4xx
	case code >= codes.Internal && code <= codes.DataLoss:
		res.errName = errStatus5xx
	}
	return res
}

// lastSegment returns the method name after the last '/' ("/pkg.Svc/Method" →
// "Method"), used to name the stream.
func lastSegment(fullMethod string) string {
	if i := strings.LastIndex(fullMethod, "/"); i >= 0 {
		return fullMethod[i+1:]
	}
	return fullMethod
}
