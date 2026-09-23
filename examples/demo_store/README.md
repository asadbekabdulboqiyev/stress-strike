# VoltStore — e-commerce demo target for stress-strike

VoltStore is a complete, production-shaped e-commerce storefront that exists
for one reason: to be **attacked**. It is the reference demo for the
[VeriGate](docs/VERIGATE.md) protection system — flip protection on and hit
it with stress-strike; flip it off and watch it take the full storm.

## Run

```bash
go run .                    # protection OFF (default) — open target
go run . -protect           # protection ON  — WAF-style gate active
go run . -addr 127.0.0.1:8090 -protect -rate-limit 100 -burst 300 -block-after 6
```

| Flag          | Default | Meaning                                        |
|---------------|---------|------------------------------------------------|
| `-addr`       | `127.0.0.1:8090` | listen address                         |
| `-protect`    | `false` | enable VeriGate protection                    |
| `-rate-limit` | `100`   | tokens/second per IP                          |
| `-burst`      | `300`   | burst allowance                               |
| `-difficulty` | `5`     | proof-of-work leading-zero bits               |
| `-block-after`| `6`     | failed challenges before an IP block          |
| `-block-duration` | `10m` | how long a block lasts                    |

## What's inside

- **Catalog** — 12 products, 5 categories (`laptops`, `audio`, `wearables`,
  `e-readers`, `accessories`), computed accent colors, inline SVG product art
  (no external images; everything embeds into one binary via `go:embed`)
- **Accounts** — register / login / logout with cookie sessions; demo users
  `alice@volt.store` / `bob@volt.store`, password `demo1234`
- **Cart & checkout** — add/remove lines, live totals, stock decrement,
  order history per account
- **Pages** — home, catalog (category/search/sort), product, cart, login,
  register, checkout, account, and the VeriGate admin dashboard
- **API** — `/api/products`, `/api/auth/register|login|logout`,
  `/api/cart`, `/api/cart/items`, `/api/checkout`
- **Control plane** — `GET/POST /admin/protect`, `GET /admin/stats`,
  `POST /admin/reset`; `/health` for probes

## Try the SLA verify gate

```bash
../../scripts/demo-store-sla.sh
```

Runs the same stress-strike SLA gate twice: with VeriGate ON the attack
produces ~99.9% errors (exit 2); toggled OFF the store absorbs ~16k req/s
(exit 0). One command proves the protection flips a CI gate.

## Tests

```bash
cd ../..
go test -count=1 -timeout 120s ./examples/demo_store/
```

Coverage: store logic (catalog, search, sort, auth, cart, checkout,
stock/history), page rendering for every route, API auth + cart + checkout,
and the VeriGate integration (rate-limit on attack, live toggle via
`/admin/protect`, stats shape).