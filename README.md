# Sift

[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Version](https://img.shields.io/badge/Version-0.14.14-green.svg)]()

**Sift** — Go tilida yozilgan, ko‘p protokolli yuklama testi (load testing), trafik replay, xavfsizlik skanerlash va tekshiriladigan dalil (attestation) vositasi.

> **Faqat ruxsat etilgan testlar uchun.** O‘zingizga tegishli yoki yozma ruxsat olingan tizimlarda ishlating. Ruxsatsiz yuklama/DDoS noqonuniy.

## Mundarija
- [Imkoniyatlar](#imkoniyatlar)
- [Tez boshlash](#tez-boshlash)
- [O‘rnatish](#ornatish)
- [Interaktiv rejim](#interaktiv-rejim)
- [Buyruqlar](#buyruqlar)
- [Load test (`run`) va YAML stsenariylar](#load-test-run-va-yaml-stsenariylar)
- [Xavfsizlik skanerlari va pentest](#xavfsizlik-skanerlari-va-pentest)
- [Replay va Scan](#replay-va-scan)
- [Web dashboard](#web-dashboard)
- [Distributed rejim (master/worker)](#distributed-rejim-masterworker)
- [Avtorizatsiya, audit, sertifikat va dalil](#avtorizatsiya-audit-sertifikat-va-dalil)
- [VPMP dalil va verifikatsiya](#vpmp-dalil-va-verifikatsiya)
- [VeriGate va demo](#verigate-va-demo)
- [Go kutubxona API](#go-kutubxona-api)
- [Hisobotlar, SLA va chiqish kodlari](#hisobotlar-sla-va-chiqish-kodlari)
- [Loyiha tuzilmasi va hujjatlar](#loyiha-tuzilmasi-va-hujjatlar)
- [Build, test va rivojlantirish](#build-test-va-rivojlantirish)
- [Litsenziya va mualliflar](#litsenziya-va-mualliflar)

## Imkoniyatlar

### Load testing va trafik
- **Protokollar:** HTTP/HTTPS, WebSocket (`ws`/`wss`), gRPC (`grpc`/`grpcs`), TCP, UDP (stsenariy `type` orqali).
- **Load profillar:** `steady`, `soak`, `linear-ramp`, `spike`, `wave`, `constant-rps`.
- **Stsenariylar:** YAML/JSON ko‘p bosqichli oqimlar, `{{var}}` o‘zgaruvchilar, stepdan qiymat ajratib olish (`extract`), `assertions` (`status`, `json_path`, `regex`).
- **Boshqaruv:** virtual userlar, duration, ramp-up, timeout, keep-alive, global RPS, pre-warm, TLS fingerprint (`chrome`, `firefox`, `safari`, `edge`, `ios`, `android_okhttp`, `randomized`, `golang`).
- **Aniqlik va tahlil:** coordinated omission tuzatish (`--coordinated-omission`, mos profillarda), warmup/debug capture, payload pool, timeline CSV, baseline taqqoslash va regressiya gati.
- **Replay:** PCAP/HAR trafikni qayta ijro etish (tezlik, concurrency, filterlar, validatsiya).

### Xavfsizlik va tekshiruv
- **`pentest`:** 1-click professional baholash (recon/fingerprint, port/subdomain, auth, crawl, headers/TLS/WAF, deep vuln scan, CVE/NVD, OWASP Top 10, compliance mapping, reportlar) — `--dry-run` mavjud.
- **Alohida skanerlar (scope-gate bilan):** `fuzz`, `dirbust`, `jwt` (offline), `graphql`, `websocket`, `crawl`, `subdomain`, `portscan`, `sslscan`.
- **`scan`:** TLS/WAF/HTTP fingerprint va xavfsizlik headerlari tekshiruvi.
- **Scope va himoya:** `authorize`/`audit` siyosati, ruxsat/ticket, allowlist, rate/budget, dry-run; tekshirilmagan kategoriya `PASS` emas, `NOT TESTED` sifatida ko‘rsatiladi.

### Dashboard, distributed va ishonch
- **Web dashboard:** real-time RPS/latency/error grafiklari, run boshqaruvi, tarix, scanner panellari, `/healthz` `/readyz` `/metrics`.
- **Distributed:** `master`/`worker` (gRPC), statik yoki auto-discovery fleet, token/TLS/attestation imkoniyatlari.
- **Dalil va sertifikat:** `keygen`, `verify` (VPMP/v1), `certificate` (issue/verify), har run uchun attestatsiya bundle va brauzer/verifier orqali tekshiruv.
- **VeriGate:** rate-limit + proof-of-work challenge + IP blocking, `demo-store` (VoltStore) bilan jonli demo/SLA tekshiruvi.

### Dasturchilar uchun
- **Go API:** `github.com/asadbekabdulboqiyev/sift/api`
- **Chiqishlar:** terminal hisobot, JSON/TXT reportlar, timeline CSV, scan/pentest eksportlari.
- **CI/CD:** SLA va regressiya gate’lari (`exit 2`).

## Tez boshlash

```bash
# Repodan (birinchi ishga tushirishda build qiladi)
./start.sh
# Dashboard: http://127.0.0.1:8888 (brauzerda Start bosing)

# Yoki o‘rnatilgan CLI bilan
Sift                       # interaktiv menyu
Sift run --url http://127.0.0.1:8080/health --users 100 --duration 30
Sift dashboard             # http://127.0.0.1:8888
```

Lokal demo target:
```bash
# Terminal 1
go run ./examples/demo_server.go

# Terminal 2
Sift run --url http://localhost:8080/health --users 200 --duration 30
```

## O‘rnatish

Talab: **Go 1.26+** (to‘liq Go, CGO/libpcap talab qilinmaydi).

```bash
# Go install (asosiy va yordamchi binarylar)
go install github.com/asadbekabdulboqiyev/sift/cmd/sift@latest

# Yoki repo ichidan build
git clone https://github.com/asadbekabdulboqiyev/sift.git
cd sift
make build   # bin/ ichiga binarylar
```

`Sift` topilmasa PATH ga qo‘shing:
```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

Convenience installer (skriptni avval ko‘rib chiqing):
```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/asadbekabdulboqiyev/sift/v0.14.14/scripts/install.sh
less install.sh
./install.sh v0.14.14
```

## Interaktiv rejim

`Sift` ni argumentsiz terminalda ishga tushirsangiz menyu ochiladi:

- **1) CLI** — load testni shu yerda ishga tushirish va hisobot olish
- **2) WEB** — real-time dashboardni brauzerda ochish
- **3) AUTH** — certificate, authorize, audit, verify
- **4) TOOLS** — GitOps (PR/issue report), AI fuzzing (Ollama), SIEM/Telegram alertlar
- **0) Quit**

> Eslatma: WEB rejimi dashboardni darhol tayyor holatda ochadi (default/oxirgi sozlamalar bilan), sozlamalarni brauzerda o‘zgartirasiz.

## Buyruqlar

```bash
Sift <command> [flags]
```

| Guruh | Buyruq | Vazifa |
|---|---|---|
| Load/Replay/Scan | `run` | HTTP/gRPC/WebSocket/TCP/UDP load test |
|  | `replay` | PCAP/HAR trafik replay |
|  | `scan` | TLS/WAF/HTTP/security scanner |
|  | `pentest` | 1-click professional security assessment |
| Dashboard/Distributed | `dashboard` | Real-time web dashboard |
|  | `master` | Distributed coordinator |
|  | `worker` | Distributed worker |
| Skanerlar | `fuzz`, `dirbust`, `jwt`, `graphql`, `websocket`, `crawl`, `subdomain`, `portscan`, `sslscan` | Alohida xavfsizlik tekshiruvlari |
| Trust/Dalil | `authorize`, `audit`, `keygen`, `verify`, `certificate` | Ruxsat, audit trail, kalit, dalil/sertifikat |
| Boshqa | `demo-store`, `admin`, `help`, `version` | Demo, lokal admin, yordam, versiya |

Yordam: `Sift --help`, `Sift <command> --help` (buyruqqa qarab).

## Load test (`run`) va YAML stsenariylar

### Tez misollar
```bash
# Oddiy test
Sift run --url https://api.example.com --users 100 --duration 60

# Constant RPS
Sift run --url https://api.example.com --profile constant-rps --target-rps 1000 --duration 30

# Ramp + SLA
Sift run --url https://api.example.com --profile linear-ramp --users 1000 --ramp-up 30 --duration 90 \
  --expect-p99-ms 200 --expect-error-rate 1

# Baseline bilan taqqoslash
Sift run --url https://api.example.com --users 50 --duration 30 \
  --compare reports/baseline.json --regress-pct 20

# Dashboard rejimida ishga tushirish
Sift run --url https://api.example.com --users 50 --duration 60 --mode dashboard --listen 127.0.0.1:8888
```

### Asosiy `run` flaglari
- Target/config: `--url`, `--config`, `--name`
- Load: `--users`, `--duration`, `--ramp-up`, `--profile`, `--target-rps`, `--spike-users`, `--spike-warmup`, `--spike-hold`, `--wave-period`
- So‘rov: `--method`, `--data`, `--header "Key: Value"` (takrorlanuvchi), `--timeout`, `--keep-alive`
- Sifat/chiqish: `--coordinated-omission`, `--expect-p99-ms`, `--expect-error-rate`, `--expect-min-rps`, `--compare`, `--regress-pct`, `--timeline`, `--report-dir`, `--quiet`
- Rejim: `--mode cli|dashboard`, `--listen`

> To‘liq va aniq flaglar ro‘yxati: `Sift --help` va `Sift run --help`.

### YAML stsenariya (namuna)
```yaml
name: login-flow
base_url: http://localhost:8080
variables:
  username: user1
  password: pass1
load_profile:
  type: linear-ramp
  users: 100
  duration: 60
  ramp_up: 20
  timeout: 10
steps:
  - name: login
    method: POST
    url: /api/login
    headers:
      Content-Type: application/json
    body: '{"username":"{{username}}","password":"{{password}}"}'
    extract:
      - name: token
        from: json
        path: data.token
    assertions:
      - type: status
        value: "200"
      - type: json_path
        value: data.token
  - name: profile
    method: GET
    url: /api/profile
    headers:
      Authorization: "Bearer {{token}}"
sla:
  max_p99_ms: 300
  max_error_rate_pct: 1
```

Qo‘llab-quvvatlanadigan step turlari: HTTP (default), `ws`, `grpc`, `tcp`, `udp` (stsenariyaga mos maydonlar bilan). Namunalarga qarang: `examples/*.yaml`.

## Xavfsizlik skanerlari va pentest

### `pentest`
```bash
Sift pentest --target https://example.com
Sift pentest --target https://example.com --depth 3 --format all --verbose
Sift pentest --target https://example.com --dry-run   # tarmoq so‘rovlari yuborilmaydi (reja)
```
Asosiy imkoniyatlar: fingerprinting, port/subdomain, auth (form/cookie/header/browser), crawl (shu jumladan SPA uchun `--use-browser`), headers/TLS/WAF, chuqur vuln tekshiruvlari, CVE/NVD, OWASP Top 10, compliance (PCI DSS/SOC2/ISO27001), hisobotlar (html/json/md/pdf/professional), CI-friendly chiqish kodlari.

### Alohida skanerlar
- `fuzz` — HTTP fuzzing
- `dirbust` — katalog/fayl brute-force
- `jwt` — JWT tahlili (offline)
- `graphql` — introspection tekshiruvi
- `websocket` — WebSocket xavfsizlik tekshiruvi
- `crawl` — sayt/link/form/endpoint yig‘ish
- `subdomain` — passive subdomain enumeration
- `portscan` — TCP port/service scan
- `sslscan` — TLS sertifikat/konfiguratsiya tahlili

Umumiy gate/chiqish flaglari (buyruqqa qarab): `--authorized`, `--policy`, `--audit-log`, `--notify-webhook`, `--allow`, `--allow-all`, `--dry-run`, `--rate`, `--budget`, `--json`, `--output-json`.

## Replay va Scan

### `replay`
```bash
Sift replay -input traffic.har -rate 10x
Sift replay -input capture.pcap -rate 50x -concurrency 50 -methods GET
Sift replay -input traffic.har -base-url https://staging.example.com -validate -assert-status 200
```
Asosiy flaglar: `-input`, `-rate`, `-concurrency`, `-duration`, `-base-url`, filterlar (`-filter-methods`, `-filter-urls`, `-filter-min-status`, `-filter-max-status`), validatsiya (`-validate`, `-assert-status`, `-assert-regex`), TLS kalitlar, `-output-json`, `-report-dir`.

### `scan`
```bash
Sift scan -target example.com -all
Sift scan -target example.com -tls
Sift scan -target example.com -all -output-json scan.json
```
Tekshiruvlar: TLS, WAF, HTTP fingerprint, security headers, risk-scored topilmalar.

## Web dashboard

```bash
Sift dashboard                         # 127.0.0.1:8888
Sift dashboard -listen 0.0.0.0:8888    # tashqi tarmoq uchun auth/insecure siyosatiga e'tibor bering
Sift run --mode dashboard --listen 127.0.0.1:8888 --url https://api.example.com --users 50 --duration 60
```

Imkoniyatlar:
- Jonli metrikalar (RPS, latency p50/p95/p99, xatoliklar), run boshqaruvi, tarix
- Scanner panellari (OWASP, pentest, crawl, fuzz, subdomain, portscan, dirbust, sslscan, jwt, graphql, websocket)
- Operatsion endpointlar: `/healthz`, `/readyz`, `/metrics`
- Har run uchun attestatsiya ma’lumotlari va bundle yuklab olish/verifikatsiya (dashboard UI orqali)

Xavfsizlik: loopbackdan tashqarida autentifikatsiyasiz control API ishlatish cheklangan; token/API key/origin/rate-limit flaglari mavjud (batafsil: `Sift dashboard --help`).

## Distributed rejim (master/worker)

```bash
# Workerlar
Sift worker --listen :50052 --id worker-a
Sift worker --listen :50052 --id worker-b

# Master (statik fleet)
Sift master --workers host-a:50052,host-b:50052 --url https://api.example.com --users 3000 --duration 60
```

Imkoniyatlar: user/RPS taqsimoti, jonli agregatsiya, worker uzilganda davom etish, token/TLS va (mos sozlamalarda) attestation. Qo‘shimcha: auto-discovery, Linux paketlar, systemd/Docker deploy.

Qo‘llanmalar: `docs/DISTRIBUTED.md`, `docs/DEPLOY-REMOTE.md`, `docs/K8S.md`, `deploy/`, `scripts/deploy-fleet.sh`.

## Avtorizatsiya, audit, sertifikat va dalil

```bash
# Ruxsat berish (policyga yozish)
Sift authorize add --pattern example.com --approver ciso@corp --ticket SEC-77 --until 2026-12-01T00:00:00Z --reason "approved test"

# Ruxsat bilan ishga tushirish
Sift run --url https://example.com --users 100 --duration 30 --authorized SEC-77
Sift pentest --target https://example.com --authorized SEC-77

# Audit
Sift audit show --limit 20
Sift audit verify

# Sertifikat va verifikatsiya
Sift certificate --help
Sift verify --help
Sift keygen --help
```

Barcha xavfsizlik/test amallari scope va policyga bo‘ysunadi; qarorlar audit trail’da saqlanadi. Batafsil: `docs/AUTHORIZATION.md`.

## VPMP dalil va verifikatsiya

Sift run natijalarini kriptografik dalil sifatida saqlash va tekshirish mumkin (VPMP/v1, Ed25519, Merkle tree).

```bash
# Kalit
Sift keygen --out operator.key

# Dalil bilan run
Sift run --url http://localhost:8080/health --profile steady --target-rps 100 --users 20 --duration 30 \
  --coordinated-omission --emit-bundle run.bundle.json --bundle-key operator.key

# Tekshiruv
Sift verify --bundle run.bundle.json --samples run.bundle.json.samples.jsonl
```

Dashboard ham runlar uchun bundle yaratadi va UI orqali download/verify imkonini beradi. Brauzerda mustaqil tekshiruvchi: `docs/VERIFIER.html` (offline), CLI verifier: `node web/verifier/verify-cli.mjs` (agar Node mavjud bo‘lsa). Batafsil: `docs/VPMP-RFC.md`, `docs/EXPLAINER.md`.

## VeriGate va demo

```bash
Sift demo-store                  # VoltStore demo (VeriGate yoqilgan)
Sift demo-store status|stop
make demo-store-protect          # (repo ichida) himoyalangan demo
```

VeriGate: rate limiting, proof-of-work challenge va IP blocking; jonli holat va boshqaruv endpointlari demo ichida mavjud. Batafsil: `docs/VERIGATE.md`, `examples/demo_store`.

## Go kutubxona API

```go
package main

import (
	"context"
	"log"
	"time"

	"github.com/asadbekabdulboqiyev/sift/api"
)

func main() {
	res, err := api.Run(context.Background(), api.Config{
		URL:      "http://localhost:8080/health",
		Users:    100,
		Duration: 30 * time.Second,
		Profile:  "steady",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("RPS=%.2f P99=%s Errors=%.2f%%", res.RPS, res.P99, res.ErrorRatePct)
}
```

Natija maydonlari va SLA integratsiyasi uchun `api` hamda `internal/config` (kutubxona sifatida ishlatilganda) paketlariga qarang.

## Hisobotlar, SLA va chiqish kodlari

- **Hisobotlar:** har run uchun `reports/` ichida JSON va TXT (va sozlamaga ko‘ra timeline CSV, capture). Pentest uchun html/json/md/pdf/professional chiqishlar.
- **SLA gate:** `--expect-p99-ms`, `--expect-error-rate`, `--expect-min-rps` (yoki stsenariyadagi `sla`) — buzilsa gate fail.
- **Regressiya:** `--compare <baseline.json>` va `--regress-pct`.
- **Chiqish kodlari (umumiy):** `0` muvaffaqiyat, `1` xato, `2` SLA/regressiya buzilishi, ba’zi auth/buyruqlarda maxsus kodlar (masalan, policy rad etishi).

## Loyiha tuzilmasi va hujjatlar

Asosiy kataloglar:
- `cmd/` — CLI va yordamchi binarylar (`sift`, `sift-dashboard`, `sift-master`, `sift-worker`, `sift-replay`, `sift-scan`)
- `api/` — ommaviy Go API
- `internal/` — engine, config, metrics, report, scanner, dashboard, dist, authz, attest va boshqalar
- `examples/` — stsenariylar va demo ilovalar
- `web/`, `website/` — web/verifier va sayt materiallari
- `docs/` — batafsil hujjatlar
- `deploy/`, `packaging/`, `scripts/` — deploy, paketlash va yordamchi skriptlar

Foydali hujjatlar: `docs/AUTHORIZATION.md`, `docs/DISTRIBUTED.md`, `docs/DEPLOY-REMOTE.md`, `docs/K8S.md`, `docs/OWASP-SCANNER.md`, `docs/VERIGATE.md`, `docs/VPMP-RFC.md`, `docs/VERIFIER.html`, `docs/COMPLIANCE.md`, `SECURITY.md`, `CONTRIBUTING.md`.

## Build, test va rivojlantirish

```bash
make build           # bin/ ichiga barcha binarylar
make test            # race detector bilan testlar
go test ./...        # to‘liq testlar
go build ./...       # build tekshiruvi
make lint            # go vet + format tekshiruvlari
make release         # cross-platform release artefaktlari (skript/konfigga ko‘ra)
./scripts/build-all.sh 0.14.14
```

Lokal ishga tushirish (sorsdan): `go run ./cmd/sift ...`

## Litsenziya va mualliflar

- **Litsenziya:** Apache-2.0 (`LICENSE`). Qo‘shimcha ma’lumot: `LICENSING.md`, uchinchi tomon komponentlar: `NOTICE`.
- **Mualliflik/maintainer:** `README` va `MAINTAINERS.md` dagi ma’lumotlarga qarang (joriy lead maintainer: Asadbek Abdulboqiyev).
- **Xavfsizlik:** zaifliklarni mas’uliyat bilan xabar qilish tartibi `SECURITY.md` va `CONTRIBUTING.md` da ko‘rsatilgan.

---

*Sift — ruxsat etilgan muhitlarda ishlash, natijalarni tekshiriladigan dalil bilan taqdim etish va xavfsizlikni tekshirish uchun mo‘ljallangan vosita.*
