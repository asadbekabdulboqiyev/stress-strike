# ROADMAP — halol cheklovlar va tomona qo'ng'i

Bu ro'yxat **o'zbekilgan tekshirish natijalariga** asoslanadi. Harigaigaiga bosqich
birida aniq, o'lchovlangan cheklovi bo'lgan holda qo'yiladi.

## Kategoriya 1 — Halol cheklovlar (hali bor)

### 1.1 Scanner — checklist emas, oracle emas

- **Holat:** `docs/OWASP-SCANNER.md` da shaffofliklar ochiq yozilgan: JS-render
  SPA / business-logic / chuqur authz ko'rinmaydi; confidence heuristic.
- **Onbitta:** headless browser (Chromium/CDP) kirish; SPA render kutubxonalari;
  authenticated depth (login -> crawl -> scan); business-logic rule paketi.
- **Muddat:** ~3 hafta, 1 senior + 1 part-time.

### 1.2 Bus factor 1

- **Holat:** 88 commit; bitta asosiy muallif.
- **Onbitta:** maintainer kengaytish (i18n, docs), open-source contributor kanal,
  `MAINTAINERS.md`. Qo'shimcha: `CONTRIBUTING.md` ni kuchaytirish.
- **Muddat:** ~2 oy.

### 1.3 Benchmark — faqat loopback

- **Holat:** jamoaviy loopback; mustaqil tizimlar (k6 / wrk2) bilan solishtirish yo'q;
  coverage foizi e'lon qilinmagan edi.
- **Onbitta:** `scripts/bench-compare.sh` (k6/wrk2 integratsiyasi), macOS/Linux/Windows
  matrix, mustaqil 3-tomon ovoz berish.
- **Muddat:** ~4 hafta.

### 1.4 Distributed — worker ishonchini tekshirish qilinmadi

- **Holat:** master telemetry'ni ishonadi; worker attestation yo'q.
- **Onbitta:** worker ed25519 kalit bilan snapshotni imzolash + master'da allowlist
  tekshirishi; key rotation.
- **Muddat:** ~3 hafta, 1 senior.

### 1.5 Dual-use / huquqiy

- **Holat:** authz qatlami bor, lekin auditor huquqiy javobgarlik o'zi qiladi.
- **Onbitta:** compliance paketi (SOC 2 / ISO 27001 mapping), auditor approval workflow
  (mavjud `internal/authz`), DPA/metadata blok.
- **Muddat:** chet tilida, ~1 oy.

## Kategoriya 2 — Mahalliy bo'l (kod qismi)

### 2.1 Internal/scanner 14,244 LOC ni qaytadan yozish

- **Holat:** eng katta paket; test coverage 71.7%.
- **Onbitta:** `scanner` → `scanner/passive`, `scanner/intrusive`, `scanner/cve`,
  `scanner/owasp`, `scanner/auth`, `scanner/jwt`, `scanner/fuzz`, `scanner/dirbust`,
  `scanner/graph`, `scanner/websocket`, `scanner/crawl`, `scanner/portscan`,
  `scanner/sslscan`, `scanner/subdomain`, `scanner/guard`, `scanner/verify`, `scanner/nvd`
  bo'lib turishi; CLI parity modullari `cmd/stress-strike-scan` ga o'tkazilishi.
- **Muddat:** ~6-8 hafta, 2 senior. Muhim: bu refaktoring **ortiqcha qo'ng'ilish** emas —
  g'oyalik qism, lekin commit tartibi bilan bog'liq.

### 2.2 Dashboard'dagi OIDC/RBAC yetishligi

- **Holat:** bearer token default; mTLS + APIKey bor; `internal/oidc` + `internal/rbac`
  mavjud.
- **Onbitta:** dashboard AuthConfig'ga OIDC broker hook qo'shish; RBAC policy integratsiyasi.
- **Muddat:** ~2 hafta, 1 senior + 1 part-time.

### 2.3 HTTP/3 (QUIC)

- **Holat:** HTTP/2 + utls (JA3) kerakli; HTTP/3 yo'q.
- **Onbitta:** `quic-go` qo'shimchasi; UDP transport; load gen HTTP/3 qo'llab-quvvati.
- **Muddat:** ~4 hafta, 2 senior.

### 2.4 Browser-based load testing

- **Holat:** k6 `k6-browser` va JMeter WebDriver ga nisbatan yetishmaslik.
- **Onbitta:** CDP/Chromedp orqali real brauzer; JS SPA yuk testi.
- **Muddat:** ~6 hafta, 2 senior.

## Kategoriya 3 — Mahalliy bo'l bo'lmagan, lekin ochiq

- **VPMP v1 standartlashtirish:** RFC emas; ijtimoiy qabul qilinishi kerak.
- **Release cadence:** oylik minor + patch; `release.yml` ni qoldirmaslik.
- **Security review:** mustaqil uchinchi tomon audit (Red Team) + pen-test skriptlari.
- **Enterprise tier:** `internal/...` da hali yo'q; open-core modelini saqlash kerak.

## Rejalashtirish jadvali (so'rovnoma bo'yicha)

| Hafta | Ishlar |
|---:|---|
| 45-46 | Flaky test tuzatildi + coverage 58.7% + docs/COVERAGE.md; **commit** |
| 47-49 | Worker attestation + distributed trust |
| 50-52 | Dashboard OIDC/RBAC wiring |
| 53-55 | Scanner headless browser + authenticated depth |
| 56-57 | HTTP/3 |
| 58-60 | Independent benchmark harness (k6/wrk2) + VPMP RFC draft + bus factor hiring |

Muhim: **har bosqich oldiga o'lchovlanadi**. Hech bir o'z-o'ziga yaratma.
