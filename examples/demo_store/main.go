// Command demo_store runs VoltStore — a realistic e-commerce demo target for
// stress-strike, protected by the VeriGate middleware (rate limit +
// proof-of-work challenge + IP blocking) which can be toggled at runtime.
//
// Usage:
//
//	go run ./examples/demo_store                # unprotected target
//	go run ./examples/demo_store -protect       # VeriGate protection ON
//	curl -X POST localhost:8090/admin/protect -d '{"enabled":false}'
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/verigate"
)

//go:embed templates/*.html
var viewsFS embed.FS

//go:embed static
var staticFS embed.FS

func main() {
	var (
		addr         = flag.String("addr", "127.0.0.1:8090", "listen address")
		protect      = flag.Bool("protect", false, "enable VeriGate protection at startup")
		rateLimit    = flag.Int("rate-limit", 100, "VeriGate: requests/sec per IP")
		burst        = flag.Int("burst", 300, "VeriGate: burst capacity per IP")
		difficulty   = flag.Int("difficulty", 4, "VeriGate: proof-of-work hex-zero digits")
		blockAfter   = flag.Int("block-after", 6, "VeriGate: challenges before an IP is blocked")
		blockFor     = flag.Duration("block-for", 90*time.Second, "VeriGate: IP block duration")
		challengeTTL = flag.Duration("challenge-ttl", 10*time.Minute, "VeriGate: solved-challenge cookie TTL")
		secret       = flag.String("secret", "", "VeriGate: HMAC secret (random when empty)")
	)
	flag.Parse()

	store := NewStore()

	gate, err := verigate.New(verigate.Options{
		Enabled:       *protect,
		RateLimit:     *rateLimit,
		Burst:         *burst,
		Difficulty:    *difficulty,
		BlockAfter:    *blockAfter,
		BlockDuration: *blockFor,
		ChallengeTTL:  *challengeTTL,
		Secret:        []byte(*secret),
		Exempt: func(r *http.Request) bool {
			p := r.URL.Path
			// Exact control-plane/probe paths only — a prefix match here
			// would also exempt look-alike URLs like /administrator.
			return p == "/health" ||
				p == "/admin" ||
				p == "/admin/protect" ||
				p == "/admin/stats" ||
				p == "/admin/reset" ||
				strings.HasPrefix(p, "/static/")
		},
	})
	if err != nil {
		log.Fatalf("verigate: %v", err)
	}

	srv, err := NewDemoServer(store, gate)
	if err != nil {
		log.Fatalf("demo store: %v", err)
	}

	mux := http.NewServeMux()
	srv.Routes(mux)

	// Static assets are embedded with the "static/" prefix; expose them as a
	// sub-filesystem so /static/styles.css resolves to styles.css.
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("static sub-fs: %v", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	handler := securityHeaders(gate.Handler(mux))

	lnAddr := *addr
	if !strings.Contains(lnAddr, ":") {
		lnAddr = ":" + lnAddr
	}
	log.Printf("VoltStore listening on http://%s  (VeriGate protection: %v)", *addr, gate.Enabled())
	log.Printf("  admin control plane:  GET/POST http://%s/admin/protect", *addr)
	if err := http.ListenAndServe(lnAddr, handler); err != nil {
		log.Fatal(err)
	}
}

// securityHeaders applies production-grade response headers, matching what a
// real hardened web property ships. CSP intentionally allows inline scripts:
// the VeriGate challenge page embeds its proof-of-work solver inline.
// HSTS is only advertised when the request actually arrived over TLS.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
