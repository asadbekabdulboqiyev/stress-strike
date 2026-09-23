package coordinator

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// TLSOptions describes optional TLS termination for the control plane. Both
// master and worker act as a gRPC server (they accept control traffic) and as
// a gRPC client (master dials workers, workers register with the master), so
// the same options struct is used for both directions:
//
//   - CertFile + KeyFile  turn on TLS on the serving side.
//   - CAFile              makes outgoing dials verify the peer against your
//     own CA (recommended for fleets with a shared CA).
//   - InsecureSkipVerify  disables peer verification for self-signed demo
//     fleets. Never combine with real credentials on untrusted networks.
//
// When CertFile/KeyFile are empty the server stays plaintext; when CAFile and
// InsecureSkipVerify are both empty outgoing dials stay plaintext. A fleet
// must agree on TLS or not — a TLS client dialing a plaintext server (or the
// reverse) fails fast with a handshake error, which is intentional.
type TLSOptions struct {
	CertFile           string
	KeyFile            string
	CAFile             string
	InsecureSkipVerify bool
}

// Enabled reports whether a certificate pair was supplied for serving.
func (o TLSOptions) Enabled() bool { return o.CertFile != "" && o.KeyFile != "" }

// ServerCreds builds transport credentials for the gRPC server. It returns
// nil when TLS serving is not configured (the caller keeps plaintext).
func (o TLSOptions) ServerCreds() (credentials.TransportCredentials, error) {
	if o.CertFile == "" && o.KeyFile == "" {
		return nil, nil
	}
	if o.CertFile == "" || o.KeyFile == "" {
		return nil, fmt.Errorf("-tls-cert and -tls-key must be provided together")
	}
	creds, err := credentials.NewServerTLSFromFile(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS server cert/key: %w", err)
	}
	return creds, nil
}

// ClientCreds builds transport credentials for outgoing dials. It returns nil
// (plaintext) when neither -tls-ca nor -tls-skip-verify is configured.
func (o TLSOptions) ClientCreds() (credentials.TransportCredentials, error) {
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read -tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-tls-ca %s contained no parseable certificates", o.CAFile)
		}
		return credentials.NewClientTLSFromCert(pool, ""), nil
	}
	if o.InsecureSkipVerify {
		return credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}), nil // #nosec G402 — documented self-signed-demo escape hatch
	}
	return nil, nil
}
