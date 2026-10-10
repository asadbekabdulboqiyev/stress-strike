# stress-strike — CI/CD, Docker, Release va Distribution Audit

**Auditor:** TechCorp DevOps Muhandis
**Sana:** 2026-10-01
**Tizim:** Go 1.26, AGPL-3.0, 6 ta binary, modul `github.com/asadbekabdulboqiyev/stress-strike`
**Tekshirilgan:** `.github/workflows/*`, `Makefile`, `scripts/*` (10 ta), `Dockerfile*` (3 ta),
`deploy/*` (5 ta), `start.sh`, `.dockerignore`, `.gitignore`, `dist/`, `go.mod`/`go.sum`, `VERSION`

---

## 1. HOZIRGI HOLAT

### 1.1 CI/CD

| Element | Holat | Baho |
|---|---|---|
| GitHub Actions (CI) | `ci.yml` bor: lint (vet+gofmt), test (race+coverage), build (3 platforma), docker (2 platforma) | 6/10 |
| GitHub Actions (release) | `release.yml` bor: 5 platforma, **faqat 1 binary**, sha256, softprops gh-release | 4/10 |
| Unit testlar | 59 ta fayl, 745 ta `Test`, 7 ta `Benchmark` — yaxshi | 8/10 |
| Lint (golangci-lint) | **YO'Q.** faqat `go vet` + `gofmt -l` | 3/10 |
| `go vet` | bor, ishlaydi (libpcap'siz ham, tekshirildi) | 8/10 |
| Race detector | bor (`-race`), 3 ta OS'da | 8/10 |
| Coverage | `coverage.out` artifact sifatida — lekin **ishlatilmaydi**: codecov yo'q, gate yo'q, `-coverpkg` yo'q | 3/10 |
| Build matrix | 3 ta: darwin/arm64, linux/amd64, windows/amd64. **Yo'q:** linux/arm64, darwin/amd64, windows/arm64 | 4/10 |
| 6 binary build | **faqat `./cmd/stress-strike`** build qilinadi — 5 tasi yo'q | 2/10 |
| GoReleaser | **YO'Q** | 1/10 |
| SBOM (SPDX/CycloneDX) | **YO'Q** | 1/10 |
| cosign / imzolash | **YO'Q** | 1/10 |
| govulncheck | **YO'Q** (go.mod'da `x/crypto`, `x/net` bor) | 1/10 |
| gosec | **YO'Q** | 1/10 |
| CodeQL | **YO'Q** | 1/10 |
| Dependabot / Renovate | **YO'Q** | 1/10 |
| gitleaks | **YO'Q** | 1/10 |
| Trivy / image scan | **YO'Q** | 1/10 |
| Concurrency limit | **YO'Q** | 3/10 |
| `timeout-minutes` | **YO'Q** (default 360) | 4/10 |
| Shell script lint (shellcheck) | **YO'Q** (10 ta script bor) | 2/10 |

### 1.2 Docker

| Element | Holat | Baho |
|---|---|---|
| Multi-stage build | bor — `Dockerfile` (alpine builder → alpine runtime), `.master`/`.worker` (golang → distroless) | 8/10 |
| Non-root | bor — `USER stress` (uid 10001) va `distroless:nonroot` (65532) | 9/10 |
| Base image | alpine:3.21, golang:1.26-alpine, `gcr.io/distroless/static-debian12:nonroot` | 8/10 |
| CGO | `Dockerfile` replay'ni `CGO_ENABLED=1` + `libpcap-dev` bilan quradi — **keraksiz** (replay `pcapgo` ishlatadi, pure Go) | 4/10 |
| Binary hajmi | 6 binary jami **70.2 MB** (tar.gz ~28 MB); `dist/` worker tar'zlari 9-10 MB/don | 5/10 |
| Image hajmi (taxminiy) | ~78-80 MB (70.2 + alpine 8 + libpcap/ca 2) — **o'lchov qilinmagan**, Docker daemon o'lmaydi | 5/10 |
| HEALTHCHECK | **3 ta Dockerfile'da ham yo'q** | 1/10 |
| SIGTERM / graceful | Go kodda `signal.Notify` bor (7 ta joy) — lekin Dockerfile'da `STOPSIGNAL` ko'rsatilmagan | 7/10 |
| `.dockerignore` | bor, lekin **`LICENSE` ni exclude qilgan** → AGPL-3.0 §4 buziladi | 3/10 |
| `*.env` pattern | `.dockerignore`'da `*.env` `worker.env.example`'ni ham yeydi | 5/10 |
| Docker image push | `<secrets.DOCKER_USERNAME>/stress-strike`, fallback `stress-strike/stress-strike` — **bu repo yo'q**, push ishlamaydi | 2/10 |
| `VERSION` build-arg | `VERSION=${{ github.ref_name }}` — main'da bu `main` literali, image label'ga yoziladi | 3/10 |
| master/worker image CI | **CI'da umuman build qilinmaydi** (faqat `Dockerfile`) | 2/10 |
| Resource limits (compose) | faqat `ulimits.nofile`; CPU/memory limit yo'q | 4/10 |
| Image provenance / SBOM attest | **YO'Q** | 1/10 |

### 1.3 Release

| Element | Holat | Baho |
|---|---|---|
| `scripts/release.sh` | bor, lekin **`rm -rf dist`** — worker paketlari va generated compose'ni yo'qotadi | 2/10 |
| `scripts/build-all.sh` | bor; `RELEASE=1` rejimi 1 binary, 5 platforma | 5/10 |
| `scripts/build-worker-linux.sh` | bor, linux/amd64+arm64, systemd unit bilan | 7/10 |
| Versiya **kodda** | `cmd/stress-strike`, `-master`, `-worker`, `internal/dist/coordinator` → `0.14.3` | 8/10 |
| Versiya **README** | `v0.14.2` (4 marta) — **mos emas** | 3/10 |
| Versiya `Dockerfile` | `ARG VERSION=0.11.0` — **2 minor eskirgan** | 2/10 |
| Versiya `Dockerfile.master/worker` | `ARG VERSION=0.14.0` — eskirgan | 3/10 |
| Versiya `cmd/stress-strike/main.go:14` | izohda `0.14.2` | 3/10 |
| Versiya `build-all.sh` / `build-worker-linux.sh` / `deploy-fleet.sh` / `bench.sh` / `bootstrap-worker.sh` | default `0.14.0` | 3/10 |
| `VERSION` fayl | **YO'Q** | 1/10 |
| `.goreleaser.yaml` | **YO'Q** | 1/10 |
| Checksums | bor (sha256sums.txt / checksums.txt) — lekin release script'ga bog'liq | 5/10 |
| Imzolash (cosign) | **YO'Q** | 1/10 |
| Checksum fayl checksum'i | **YO'Q** | 1/10 |
| `dist/` holati | faqat `v0.11.0` worker tar'zlari (3 tagdan eski). **Aniqlandi: v0.5.1 emas, v0.11.0.** Gitignore qilingan, `git ls-files dist/` = 0 → lokal qoldiq, commit emas | 2/10 |
| `dist/` tozalanishi | `make release` va `make clean` `dist/` ni butunlay o'chiradi | 2/10 |

### 1.4 Distribution

| Element | Holat | Baho |
|---|---|---|
| `scripts/install.sh` | bor, `go install` asosida — xavfsizroq, lekin README'da `curl \| bash` bilan `main` branch'dan tortiladi | 5/10 |
| Checksum tekshiruvi (install) | **YO'Q** | 1/10 |
| Homebrew formula | **YO'Q** | 1/10 |
| Scoop manifest | **YO'Q** | 1/10 |
| winget manifest | **YO'Q** | 1/10 |
| Docker Hub image | konfiguratsiya bor, lekin noto'g'ri | 2/10 |
| GHCR image | **YO'Q** | 1/10 |
| deb/rpm paket | **YO'Q** (systemd unit bor, paketlash yo'q) | 2/10 |
| `docs/` | 7 ta fayl (DEPLOY-REMOTE, DISTRIBUTED, POWER-FEATURES, STUDY-GUIDE, VERIGATE, PDF) — mazmunli | 8/10 |
| `README` install bo'limi | `brew install libpcap` degan **noto'g'ri** tavsiya (pure Go loyiha) | 6/10 |

### 1.5 Reproducibility

| Element | Holat | Baho |
|---|---|---|
| `go mod verify` | **OK** — "all modules verified" | 9/10 |
| `go.sum` | 66 qator, to'liq | 9/10 |
| `vendor/` | **YO'Q** — `go install` uchun kerak emas, lekin build uchun stabil emas | 5/10 |
| `-trimpath` | bor (`Dockerfile`da yo'q, `.master`/`.worker`'da bor) | 7/10 |
| `-buildvcs=false` | scriptlarda bor, `Dockerfile`da yo'q | 5/10 |
| Tool versiyalari pinned | `GO_VERSION: "1.26"` pinned; golangci-lint/gosec/trivy **pinned emas** | 5/10 |
| `go mod tidy` tekshiruvi | **YO'Q** | 3/10 |

---

## 2. KAMCHILIKLAR (muammo → oqibat → yechim)

### P0 — darhol tuzatilishi kerak

**K-01. `scripts/release.sh` `dist/` butunlay o'chiradi**
`rm -rf "${DIST_DIR}"` — bu `dist/linux-worker/` (worker tar'zlari) va
`dist/docker-compose.generated.yml` (`deploy-docker.sh` yozadigan fayl) ni ham o'chiradi.
**Oqibat:** `make release` dan keyin `make docker-down` ishlamaydi; ishlaydigan fleet'ni
boshqarib bo'lmaydi. v0.11.0 worker paketlari shu sababdan "eskirgan" holatda qolgan bo'lishi mumkin.
**Yechim:** faqat `dist/release` tozalanadi; compose fayl `.generated/` ga ko'chiriladi
(`patches/0001-audit-fixes.patch`).

**K-02. Release 6 dan 1 binary**
`release.yml`, `release.sh`, `build-all.sh` — hammasi faqat `./cmd/stress-strike`.
**Oqibat:** distributed feature (master/worker), replay, scan, dashboard — release'dan
**faqat manba orqali** (`go install`) olinadi, arxiv yuklab olib ishlatib bo'lmaydi.
Bu AGPL-3.0 bo'yicha ham muammo: foydalanuvchi binary'ni yuklab olsa ham qo'shimcha
komponentlar yo'q. **Yechim:** `.goreleaser.yaml` (6 build × 6 platforma = 36 artefakt).

**K-03. Docker push noto'g'ri registry**
`registry=${DOCKER_USERNAME}` → `<username>/stress-strike`; fallback `stress-strike/stress-strike`.
Docker Hub'da bunday repo yo'q → push xatosi.
**Oqibat:** hech qanday image published bo'lmaydi.
**Yechim:** `.github/workflows/docker.yml` — GHCR (`ghcr.io/${{ github.repository_owner }}`)
doimiy, Docker Hub `secrets` bo'lsa qo'shimcha.

**K-04. `VERSION` build-arg `main` literali bo'lib ketadi**
`build-args: VERSION=${{ github.ref_name }}` — main branch push'ida `ref_name=main`.
**Oqibat:** image label `version="main"`, binary `--version` `vmain` ko'rsatadi.
**Yechim:** `docker/metadata-action` + tag'da `ref_name`, branch'da `$(cat VERSION)-$(sha)`.

**K-05. AGPL-3.0 §4 buzilishi — LICENSE image'da yo'q**
`.dockerignore` `LICENSE` ni exclude qiladi va Dockerfile uni ko'chir maydi.
**Oqibat:** AGPL-3.0 §4 bo'yicha binary tarqatilganda litsenziya matni majburiy.
Docker orqali tarqatish — litsenziyasiz tarqatish.
**Yechim:** `.dockerignore` dan olib tashlandi, 3 ta Dockerfile'ga `COPY LICENSE` qo'shildi,
`.goreleaser.yaml` da `files: [LICENSE]` barcha arxivlarda.

### P1 — yaqin muddatda

**K-06. `replay` uchun keraksiz CGO + libpcap**
`Dockerfile` replay'ni `CGO_ENABLED=1` bilan quradi, runtime'ga `libpcap` o'rnatadi.
**Dalil:** `internal/replay/pcap.go:17` → `github.com/google/gopacket/pcapgo` (pure Go).
`go vet ./...` bu mashinada libpcap'siz **muvaffaqiyatli** o'tdi.
**Oqibat:** image'ga ~2 MB, build-base qatlami, CI'da 3 jobda `apt-get install libpcap-dev`.
**Yechim:** hamma joyda `CGO_ENABLED=0`; libpcap olib tashlandi; CI'dan 3 ta
`apt-get install libpcap-dev` qatori olib tashlandi.

**K-07. `-X main.version` faqat 3 binary'da ishlaydi**
`dashboard`, `scan`, `replay` da `var version` **yo'q** → `-X` jim qoladi.
**Oqibat:** `stress-strike-scan version` noto'g'ri/natija bermaydi.
**Yechim:** `internal/version` paketi yaratildi (6 binary bir manba), `.goreleaser.yaml`
shu paketga yozadi; 3 ta legacy `main.version` ham saqlanadi (migratsiya davrida).

**K-08. master/worker image CI'da build qilinmaydi**
3 ta image'ning 2 tasi (`Dockerfile.master`, `Dockerfile.worker`) — regresssiz.
**Oqibat:** distroless build buzilsa, foydalanuvchi `docker build` da xotirjam bo'ladi.
**Yechim:** `ci.yml` docker job — 3 ta dockerfile × 2 arxitektura.

**K-09. HEALTHCHECK yo'q**
`restart: unless-stopped` bilan crash-loop aniqlanmaydi.
**Oqibat:** master/worker crash bo'lsa, compose uni qayta ishga tushiradi va yana
crash qiladi — cheksiz loop, sababni topib bo'lmaydi.
**Yechim:** gRPC `Ping` RPC allaqachon bor (`scripts/fleet-status.sh` ishlatadi).
Compose'da shu asosda probe. Distroless'da shell yo'q — shuning uchun HTTP probe
o'rniga mavjud gRPC probe ishlatiladi (hali binary'ga `healthcheck` subcommand qo'shish kerak).

**K-10. Xavfsizlik skaneri butunlay yo'q**
govulncheck, gosec, CodeQL, Dependabot, gitleaks, Trivy — **hiqari yo'q**.
**Oqibat:** `golang.org/x/crypto v0.51.0`, `x/net v0.55.0` — reachable CVE bo'lishi mumkin,
CI buni ko'rmaydi. Action'lar `@v4/@v5/@v6` — supply-chain sirti.
**Yechim:** `.github/workflows/security.yml`, `codeql.yml`, `.github/dependabot.yml`.

**K-11. Coverage o'lchanadi, gate yo'q**
`coverage.out` yuklanadi, lekin hech kim solishtirmaydi. `-coverpkg` yo'q → har bir
paket o'zini o'zi qamrab oladi va raqam sun'iy yuqori chiqadi.
**Oqibat:** coverage pasayishi sezilmaydi.
**Yechim:** `-coverpkg=./...`, artifact'ni birlashtirish, 45% floor gate, codecov.

**K-12. `install.sh` `curl | bash` va tekshiruvsiz**
README: `curl -fsSL .../main/scripts/install.sh | bash` — `main` branch'idan
(main'da kiritilsa, barcha foydalanuvchilar shu kodni ishga tushiradi).
**Oqibat:** branch'ga write access olish = barcha installer foydalanuvchisiga kod yetkazish.
**Yechim:** `scripts/install.sh` qayta yozildi — versiyani pin qiladi, checksums.txt
bilan tekshiradi, cosign bo'lsa imzoni tekshiradi.

### P2 — rejalashtirish

**K-13. `systemd` `ProtectSystem=strict` + `ReadWritePaths` yo'q** — worker report yozsa,
xato beradi. `ReadWritePaths=/var/lib/stress-strike` qo'shish kerak. (2/10)

**K-14. compose'da `-token ""` doimiy o'tkaziladi** — master'ga bo'sh token aniq
beriladi; auth o'chgan holat. `-token` faqat `SS_TOKEN` bo'lganda berilishi kerak. (2/10)

**K-15. Resource limitlar yo'q** — compose'da CPU/memory limit yo'q (README:940 `docker run
--cpus=2 --memory=512m` bor, lekin compose'da yo'q). Load generator uchun memory limit
o'lim bo'lishi mumkin — `mem_limit` emas, `mem_reservation` + monitoring. (4/10)

**K-16. `.dockerignore` `*.env`** — `worker.env.example` kabi fayllarni ham yeydi.
Aniq pattern'ga o'tkazildi. (5/10)

**K-17. Concurrency / timeout yo'q** — `concurrency` va `timeout-minutes` qo'shildi. (3/10)

**K-18. shellcheck yo'q** — 10 ta shell script bor, hech biri lint qilinmaydi.
`ci.yml` ga shellcheck qo'shish. (2/10)

**K-19. README `brew install libpcap`** — pure Go loyiha uchun noto'g'ri tavsiya (README:87).
**Yechim:** README tahrirlash (backend/docs bo'limi mas'ulasi bilan).

**K-20. go.mod tidy tekshiruvi yo'q** — CI'da qo'shildi (`ci.yml` lint job).

### Tuzatilgan xato (K-21)

**K-21. "flaky build" — bu shunday emas, boshqa sessiya tahrir qilmoqda bo'lgandi**

Audit paytida `GOOS=linux go build ./cmd/stress-strike` bir marta
`lat.Percentile undefined (type **metrics.Histogram ...)` bilan fail bo'ldi.
Men buni "Go 1.26 build-cache gliçhi" deb yozdim — **bu noto'g'ri**, va
tuzatildi. Sabab: parallel sessiya o'sha paytda `histogram.go` da
`Percentile`/`Avg`/`MinLatency`/`MaxLatency` ni `*Histogram` ga ko'chiryapti
(+74 qator) va `dash_mode.go` ni yangilamoqda bo'lardi (+9/-4). Mening
build'im ikkala tahrir orasidagi oynada tushdi.

**Dalil:** `git status` da o'sha sessiyaning o'zgartirishlari ko'rinadi
(`cmd/stress-strike/dash_mode.go`, `internal/metrics/histogram.go`,
`internal/engine/engine.go`, `internal/report/display.go`,
`internal/dashboard/bridge.go`, `internal/demostore/demostore.go`,
`internal/metrics/benchmark_test.go` + yangi `internal/engine/vars_bench_test.go`).
Hozirgi holatda to'liq build **o'tadi** (7/7 urinish).

**Sabab bo'yicha xulosa:** stress-strike'da flaky build **yo'q** — bu mening
noto'g'ri xulosam edi. Parallel tahrirlar paytida validatsiya qilish
kutilmasligi kerak. (Audit qilingan paytdagi o'zgarishlar mening emas.)

---

## 3. YANGILANGAN ARTIFAKTLAR (fayllar yozildi)

| Fayl | Vazifa |
|---|---|
| `.github/workflows/ci.yml` | 6 job: golangci-lint, 3 OS'da race test, coverage gate (45%), 6 platforma × **6 binary**, benchmark, 3 ta Dockerfile build |
| `.github/workflows/release.yml` | GoReleaser + VERSION/tag/source mosligi tekshiruvi |
| `.github/workflows/codeql.yml` | go + javascript-typescript, `build-mode: none` (autobuild `./cmd/...` bilmaydi) |
| `.github/workflows/security.yml` | govulncheck, gosec (SARIF), gitleaks, Trivy (3 image), dependency-review |
| `.github/workflows/docker.yml` | 3 image, GHCR + Docker Hub, cosign keyless, provenance + SBOM attest |
| `.github/dependabot.yml` | gomod (3 guruh), github-actions (2 guruh), docker |
| `.golangci.yml` | v2 schema: gosec, staticcheck, revive, errcheck, gocritic, misspell |
| `.goreleaser.yaml` | 6 build × {linux,darwin,windows} × {amd64,arm64}, checksums, SPDX+CDX SBOM, cosign, nfpms, brews, scoop |
| `Dockerfile` | multi-stage, `CGO_ENABLED=0` (libpcap olib tashlandi), non-root, `STOPSIGNAL`, `COPY LICENSE`, build'da `--version` verify |
| `Dockerfile.master` / `Dockerfile.worker` | distroless nonroot, CA bundle, `COPY LICENSE`, `STOPSIGNAL` |
| `.dockerignore` | `LICENSE` qaytarildi; `*.env` → aniq pattern; `dist`/`packaging`/`patches` qo'shildi |
| `scripts/install.sh` | versiya pin, checksums.txt, cosign verify, `--go` rejimi |
| `VERSION` | `0.14.3` — bitta manba |
| `internal/version/version.go` | 6 binary uchun umumiy versiya + `debug.ReadBuildInfo()` fallback |
| `packaging/homebrew/stress-strike.rb` | Homebrew formula (GoReleaser avtomatik yangilaydi) |
| `packaging/scoop/stress-strike.json` | Scoop manifest + `autoupdate` |
| `packaging/winget/stress-strike.yaml` + `.installer.yaml` | winget manifest (x64 + arm64) |
| `patches/0001-audit-fixes.patch` | K-01, K-04, Makefile tozalash, `main.go` izohi |

**Eski fayllar:** `.audit-backup/` da saqlandi.

---

## 4. PRIORITET VA VAQT

### P0 — bugun (≈3 soat)

| # | Vazifa | Vaqt |
|---|---|---|
| K-01 | `release.sh` `rm -rf dist` tuzatish + compose fayl `.generated/` ga | 15 daq |
| K-05 | `LICENSE` `.dockerignore` dan chiqarish + 3 Dockerfile'ga `COPY` | 10 daq |
| K-02 | `.goreleaser.yaml` (tayyor) → `goreleaser check` + snapshot build | 45 daq |
| K-03/K-04 | `docker.yml` ni yoqish, GHCR secret sozlamasi | 30 daq |
| K-06 | Dockerfile'dan CGO/libpcap olib tashlash | 20 daq |
| — | `VERSION` faylni kiritish, tag'ni `VERSION` bilan moslashtirish | 15 daq |

### P1 — 1-2 kun (≈8 soat)

| # | Vazifa | Vaqt |
|---|---|---|
| K-08 | 3 ta Dockerfile'ni CI matrixasiga qo'shish | 30 daq |
| K-11 | Coverage gate + codecov | 45 daq |
| K-10 | security.yml + codeql.yml yoqish | 1.5 soat |
| K-12 | `install.sh` yangilash + README'ni tuzatish | 1 soat |
| K-07 | `internal/version` → 3 ta `main.go` ga ulash | 1 soat |
| K-13/K-14 | systemd `ReadWritePaths`, compose token | 45 daq |
| K-17/K-18 | concurrency/timeout/shellcheck | 30 daq |
| — | Homebrew tap va Scoop bucket repo'larini yaratish | 1 soat |

### P2 — 1 hafta (≈6 soat)

| # | Vazifa | Vaqt |
|---|---|---|
| K-09 | `healthcheck` subcommand (master/worker/dashboard) + compose probe | 2 soat |
| K-15 | compose resource limit + monitoring | 1.5 soat |
| — | deb/rpm paketlash (GoReleaser `nfpms` yoqilgan) | 1 soat |
| K-19 | README tahrirlash (libpcap tavsiyasini olib tashlash, v0.14.2 → v0.14.3) | 1 soat |
| — | Reproducible build tekshiruvi (2× build, `sha256sum` solishtirish) | 30 daq |

> **Eslatma (K-21):** audit paytida parallel sessiya `histogram.go` / `dash_mode.go` /
> `engine.go` / `report/display.go` / `dashboard/bridge.go` / `demostore/demostore.go` /
> `benchmark_test.go` ni tahrir qilib turgan. Bu o'zgarishlar **meniki emas**.
> Ularni commit qilishdan oldin `git stash`/branch ajratish tavsiya etiladi.

---

## 5. TEKSHIRUV NATIJALARI (buyruqlar asosida)

```
go vet ./...                  → OK (libpcap'siz)
go mod verify                 → all modules verified
go.sum                        → 66 qator
gofmt -l internal/version/    → (toza)
YAML parse (ci/release/codeql/security/docker/
  dependabot/golangci/goreleaser) → 8/8 OK
Darwin build --version        → stress-strike v0.14.3
6 binary (linux/amd64, -s -w -trimpath) → 70.2 MB jami
git ls-files dist/            → 0 (dist to'g'ri ignore qilingan)
docker daemon                 → O'LMAYDI (image hajmi o'lchov qilinmagan)
```

### O'lchov qilinmagan narsa (aniq aytildi)

Docker daemon ishlamaydi (`dial unix /var/run/docker.sock: no such file`),
shuning uchun **image hajmi real build bilan o'lchanmadi**. Taxmin ~78-80 MB
(70.2 MB binary + alpine 3.21 ~8 MB + CA/tzdata ~2 MB; libpcap olib tashlangandan keyin).
Qo'lda build qilingandan keyin `docker images` bilan tekshirish kerak.
