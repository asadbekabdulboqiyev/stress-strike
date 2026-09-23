# VeriGate — WAF-style Protection Gate

VeriGate is a reusable, embeddable request-protection layer built into
stress-strike's `internal/verigate` package. It gives any HTTP service a
production-grade defense stack that browsers and API clients can pass through
without friction — and that bots and hammering tools cannot.

It ships with **VoltStore** (`examples/demo_store`), a full real-world
e-commerce demo built specifically to be attacked. Flip VeriGate on, throw
stress-strike at the store, and watch the difference; flip it off and the
store takes the full storm.

## The three layers

| Layer         | What it does                                                        | Response |
|---------------|---------------------------------------------------------------------|----------|
| Rate limiting | Token-bucket per IP (rate + burst)                                  | `429`    |
| PoW challenge | Stateless HMAC-SHA-256 proof-of-work page (browser solves in JS)    | `403`    |
| IP blocking   | IPs that fail challenges (or exceed limits) get a temporary block   | `403`    |

Requests are classified by client type:

- **API clients** (request `Accept: application/json`) get straight `429`
  responses — fast, machine-readable, cheap to serve.
- **Browsers** (HTML `Accept`) get a `403` challenge page with an inline
  JavaScript solver that does real SHA-256 proof-of-work, then retries
  automatically with a signed cookie. Humans never notice; bots do real work.

The challenge mechanism itself is **stateless**: the prefix is an
HMAC-signed token bound to the client IP and a timestamp, so no per-challenge
state needs storing, and a solved proof cannot be replayed from another IP or
later. Only the rate-limit buckets / blocks / failure counters are held in
memory (per-IP, lazily expired). The whole gate is safe to re-run (the demo
restarts with a fresh secret each time).

## Live control plane

Two ways to toggle protection, both demonstrated in the demo:

**1. CLI flag** on startup:

```bash
go run ./examples/demo_store -protect            # protection ON
go run ./examples/demo_store                     # protection OFF (default)
```

**2. Runtime endpoint** — no restart needed:

```bash
curl -s -X POST http://127.0.0.1:8090/admin/protect \
  -H 'Content-Type: application/json' -d '{"enabled":true}'   # ON
curl -s -X POST http://127.0.0.1:8090/admin/protect \
  -H 'Content-Type: application/json' -d '{"enabled":false}'  # OFF
```

Additional control-plane endpoints:

```bash
curl http://127.0.0.1:8090/admin/stats   # live counters (JSON)
curl -X POST http://127.0.0.1:8090/admin/reset   # clear counters + unblock IPs
```

The `/admin` page itself renders a live dashboard for all of the above.

`/health`, `/static/*` and `/admin*` are always exempt from the gate so health
probes, assets and the control plane itself keep working even under attack.

## The SLA verify gate

"VeriGate" has a second meaning in this project: the **SLA verify gate** in
stress-strike (`--expect-error-rate`, `--expect-min-rps`, `--expect-p99`).
It turns a load test into a CI gate that exits non-zero when an SLO is
violated. `scripts/demo-store-sla.sh` combines both meanings into one
proof:

```
PHASE 1 — VeriGate ON   → hammer 500 users at the store
  VeriGate throttles ~99.9% of requests
  → error rate 99.9% > 5% → SLA FAIL (stress-strike exits 2)

  toggle VeriGate OFF via POST /admin/protect

PHASE 2 — VeriGate OFF  → same attack, same store
  store absorbs ~16k req/s
  → error rate < 5%      → SLA PASS (stress-strike exits 0)

VERDICT: VeriGate WORKS — protection flips the CI gate.
```

Run it yourself:

```bash
./scripts/demo-store-sla.sh        # prints both phases + verdict
make demo-sla                      # same thing via Make
```

A hardening system that flips an automated SLA gate this decisively is
exactly what a WAF is for — one command proves the protection is real.

## VoltStore demo

`examples/demo_store` is a complete e-commerce storefront:

- **12 products in 5 categories** with computed accents, ratings and SVG
  product art — no external images, everything embeds into one binary
- **Accounts**: register, login (cookies, no JS-visible secrets), demo users
  `alice@volt.store` / `bob@volt.store` with password `demo1234`
- **Cart + checkout**: add/remove lines, live totals, stock decrement,
  order history per account
- **Pages**: home, catalog (category/search/sort), product, cart, login,
  register, checkout, account, VeriGate admin dashboard
- **API**: JSON endpoints for auth, products, cart and checkout
- **One binary**: `go:embed` carries the HTML templates, CSS, JS and the
  VeriGate challenge pages — `go build` produces a single self-contained
  executable

```bash
make demo-store            # protection OFF — attack target
make demo-store-protect    # protection ON  — protected target
```

### What to try

1. `go run ./examples/demo_store -protect`
2. Open `http://127.0.0.1:8090` — browse, sign in as `alice@volt.store`,
   add to cart, check out.
3. In another terminal: `make demo-sla` or hit it with
   `stress-strike run --url http://127.0.0.1:8090/ --users 500 --duration 10`.
4. Watch `/admin` — requests, rate-limited, challenges served/solved,
   blocked requests and blocked IPs tick up live.
5. Toggle protection off on the same panel; run the identical attack again
   and watch the store take it.

## Embedding VeriGate in your own service

```go
import "github.com/asadbekabdulboqiyev/stress-strike/internal/verigate"

gate, err := verigate.New(verigate.Options{
    Enabled:       flag.Bool("protect", false, ...), // CLI toggle
    RateLimit:     100,                              // tokens / second / IP
    Burst:         300,                              // burst allowance
    Difficulty:    5,                                // PoW leading-zero bits
    BlockAfter:    6,                                // failures before IP block
    BlockDuration: 10 * time.Minute,
    Exempt: func(r *http.Request) bool {             // health/probes/control
        p := r.URL.Path
        return p == "/health" || strings.HasPrefix(p, "/admin")
    },
})

// mount: gate wraps your mux
http.ListenAndServe(addr, gate.Handler(mux))
```

The gate implements `http.Handler`, so it composes with any router. It is
safe for concurrent use — `SetEnabled`/`Reset` are atomic and race-free
(verified by `TestConcurrentToggleAndTraffic` under `-race`).

## Tests

```bash
go test -count=1 -timeout 120s ./internal/verigate/   # 10 tests: rate limit,
                                                       # challenge flow, block,
                                                       # toggle, exempt, race
go test -count=1 -timeout 120s ./examples/demo_store/  # 7 tests: store logic,
                                                       # pages, auth, cart,
                                                       # protected-store attack
```