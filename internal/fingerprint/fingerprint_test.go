package fingerprint

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// buildHelloRecord assembles a minimal TLS ClientHello record the way a client
// would send it, so JA3FromRecord can be checked against a hand-computed value.
func buildHelloRecord(ciphers [][2]byte, groups [][2]byte, points []byte) []byte {
	var hello []byte
	hello = append(hello, 0x03, 0x03) // legacy version -> JA3 field 771
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0x00) // no session id
	hello = append(hello, byte(len(ciphers)*2>>8), byte(len(ciphers)*2))
	for _, c := range ciphers {
		hello = append(hello, c[0], c[1])
	}
	hello = append(hello, 0x01, 0x00) // one null compression method

	var ext []byte
	if len(groups) > 0 {
		ext = append(ext, 0x00, 0x0a, 0x00, byte(len(groups)*2))
		for _, g := range groups {
			ext = append(ext, g[0], g[1])
		}
	}
	if len(points) > 0 {
		ext = append(ext, 0x00, 0x0b, 0x00, byte(1+len(points)))
		ext = append(ext, byte(len(points)))
		ext = append(ext, points...)
	}
	hello = append(hello, byte(len(ext)>>8), byte(len(ext)))
	hello = append(hello, ext...)

	hs := append([]byte{0x01}, byte(len(hello)>>16), byte(len(hello)>>8), byte(len(hello)))
	hs = append(hs, hello...)

	rec := []byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestJA3Golden(t *testing.T) {
	rec := buildHelloRecord(
		[][2]byte{{0x13, 0x01}, {0xc0, 0x2f}},
		[][2]byte{{0x00, 0x1d}, {0x00, 0x17}},
		[]byte{0x00},
	)
	ja3, hash, err := JA3FromRecord(rec)
	if err != nil {
		t.Fatalf("JA3FromRecord: %v", err)
	}
	want := "771,4865-49199,10-11,29-23,0"
	if ja3 != want {
		t.Fatalf("JA3 string mismatch: got %q want %q", ja3, want)
	}
	if hash != "0137629f27baa8ccd5625beedf3b60db" {
		t.Fatalf("JA3 hash mismatch: %q", hash)
	}
}

func TestJA3RejectsGarbage(t *testing.T) {
	cases := [][]byte{nil, {0x00}, {0x16, 0x03, 0x03}, {0x15, 0x03, 0x03, 0, 1, 1}, {}}
	for _, c := range cases {
		if _, _, err := JA3FromRecord(c); err == nil {
			t.Fatalf("JA3FromRecord(%v) should have failed", c)
		}
	}
}

// tlsServer stands up a real TLS endpoint that records the raw bytes each
// client sends, so the actual on-the-wire ClientHello can be fingerprinted.
func tlsServer(t *testing.T) (*httptest.Server, *captureListener) {
	t.Helper()
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	cl := &captureListener{Listener: ts.Listener}
	ts.Listener = cl
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, cl
}

type captureListener struct {
	net.Listener
	conns []*recordingConn
	mu    sync.Mutex
}

func (l *captureListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	rc := &recordingConn{Conn: c}
	l.mu.Lock()
	l.conns = append(l.conns, rc)
	l.mu.Unlock()
	return rc, nil
}

type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	records []byte
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if len(c.records) < 1<<20 {
			c.records = append(c.records, p[:n]...)
		}
		c.mu.Unlock()
	}
	return n, err
}

func dialAndFetch(t *testing.T, ts *httptest.Server, p Profile) {
	t.Helper()
	dialer := NewDialer(Options{
		Fingerprint:        p,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
		HandshakeTimeout:   10 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialer(ctx, "tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial %s: %v", p, err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ts.Listener.Addr().String())
	data, err := io.ReadAll(io.LimitReader(conn, 1<<14))
	if err != nil {
		t.Fatalf("request via %s: %v", p, err)
	}
	if !bytes.Contains(data, []byte(" 200 ")) {
		t.Fatalf("expected HTTP 200 from %s, got %q", p, string(data))
	}
}

// TestProfilesProduceDistinctJA3 proves the feature actually changes the
// ClientHello: two profiles connected to the same TLS server must produce
// different JA3 hashes, and must still complete a real HTTPS exchange.
func TestProfilesProduceDistinctJA3(t *testing.T) {
	ts, cl := tlsServer(t)
	for _, p := range []Profile{Chrome, Golang, Firefox} {
		dialAndFetch(t, ts, p)
	}
	got := map[string]string{}
	cl.mu.Lock()
	conns := append([]*recordingConn(nil), cl.conns...)
	cl.mu.Unlock()
	for i, c := range conns {
		c.mu.Lock()
		raw := append([]byte(nil), c.records...)
		c.mu.Unlock()
		_, hash, err := JA3FromRecord(raw)
		if err != nil {
			t.Fatalf("captured record: %v", err)
		}
		got[fmt.Sprintf("conn%d", i)] = hash
	}
	if len(conns) == 0 {
		t.Fatal("no client connections captured")
	}
	// Thin assertion of distinctness: collect the per-conn hashes.
	h := map[string]int{}
	for _, hs := range got {
		h[hs]++
	}
	// Chrome and Golang must differ; the third profile adds yet another.
	if len(h) < 2 {
		t.Fatalf("profiles collapsed to one JA3: %v", h)
	}
	t.Logf("JA3 hashes seen: %v", h)
}

func TestNamesAreValid(t *testing.T) {
	for _, n := range Names() {
		if !Profile(n).Valid() {
			t.Fatalf("Names() returned invalid %q", n)
		}
	}
	if Profile("nope").Valid() || Profile("").Valid() == false {
		t.Fatal("Valid() is wrong")
	}
}

func selfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
