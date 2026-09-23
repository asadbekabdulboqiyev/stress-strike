package coordinator

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const authHeader = "authorization"

// bearerToken extracts the bearer token from incoming metadata, accepting both
// the "Bearer <token>" and the bare "<token>" forms.
func bearerToken(md metadata.MD) string {
	vals := md.Get(authHeader)
	if len(vals) == 0 {
		return ""
	}
	v := strings.TrimSpace(vals[0])
	if len(v) >= 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return v
}

func constantTimeEqual(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// UnaryAuthInterceptor rejects unary calls that do not carry the shared token.
// An empty token disables authentication (local/trusted deployments).
func UnaryAuthInterceptor(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if token == "" {
			return handler(ctx, req)
		}
		md, _ := metadata.FromIncomingContext(ctx)
		if !constantTimeEqual(bearerToken(md), token) {
			return nil, status.Error(codes.Unauthenticated, "invalid or missing control-plane token")
		}
		return handler(ctx, req)
	}
}

// StreamAuthInterceptor rejects streaming calls that do not carry the token.
func StreamAuthInterceptor(token string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if token == "" {
			return handler(srv, ss)
		}
		md, _ := metadata.FromIncomingContext(ss.Context())
		if !constantTimeEqual(bearerToken(md), token) {
			return status.Error(codes.Unauthenticated, "invalid or missing control-plane token")
		}
		return handler(srv, ss)
	}
}

// ServerOptions bundles the server-side auth interceptors.
func ServerOptions(token string) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(UnaryAuthInterceptor(token)),
		grpc.ChainStreamInterceptor(StreamAuthInterceptor(token)),
	}
}

// ClientOptions bundles the client-side token attachment interceptors.
func ClientOptions(token string) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(unaryAuthClientInterceptor(token)),
		grpc.WithChainStreamInterceptor(streamAuthClientInterceptor(token)),
	}
}

func unaryAuthClientInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, authHeader, "Bearer "+token)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func streamAuthClientInterceptor(token string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, authHeader, "Bearer "+token)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}
