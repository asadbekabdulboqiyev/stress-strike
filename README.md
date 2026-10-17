# stress-strike

Zamonaviy, xavfsiz va brauzerdan boshqariladigan xavfsizlik skanerni dashboard. OWASP Top 10, offensiv pentest, sayt crawleri (katana tarzida), HTTP fuzzer, subdomain enumeratsiya, port skaneri, directory brute-force, SSL/TLS tahlili, JWT tahlili, GraphQL introspektsiya va WebSocket xavfsizligi — bittada loyihada.

## 🚀 Xususiyatlar

| Modul | Endpoint | Nima qiladi |
|---|---|---|
| **OWASP Top 10 Scanner** | `POST /api/owasp/scan` | A01–A10 kategorialari, passive + intrusive tekshiruvlar |
| **Pentest (offensiv)** | `POST /api/pentest/scan` | OWASP + CRLF, SQLi, traversal, SSRF, write-methods |
| **Site Crawler** | `POST /api/crawl/scan` | Katana tarzida sayt crawleri, endpoint kashf etish |
| **HTTP Fuzzer** | `POST /api/fuzz/scan` | Coverage-guided fuzzing, javob farqlari bo‘yicha kuzatish |
| **Subdomain Enum** | `POST /api/subdomain/scan` | crt.sh sertifikat shaffofliygi + DNS |
| **Port Scanner** | `POST /api/portscan` | TCP port skaneri, banner grabbing |
| **Dir Bust** | `POST /api/dirbust` | `/admin`, `/.env`, `/.git/`, `/api` … yo‘lni kashf etish |
| **SSL/TLS Analyzer** | `POST /api/sslscan` | Sertifikat muddati, shifrlash, protokol |
| **JWT Analyzer** | `POST /api/jwt/scan` | `alg=none`, kam claimlar, header injection |
| **GraphQL Scanner** | `POST /api/graphql/scan` | Introspektsiya ochikmi, schema kuzatish |
| **WebSocket Tester** | `POST /api/websocket/scan` | Origin tekshiruvi, subprotocol, xavfsizlik |

## 🔐 Xavfsizlik principlari

- **Authorization gate**: har skan `authz` qatlamidan o'tadi. Passive skanlar `OpScan`, har qanday intrusive/`enable` so'rovi `OpPentest` (avtorizatsiya chiptasi talab qiladi).
- **Scope gate**: default faqat kiritilgan host skanlanadi. Boshqa internet manzillar aloqaga chiqmaydi, redirect-yo‘l ham tekshiriladi.
- **Fail-closed audit**: har bir qaror append-only audit log'ga yoziladi. Agar skan ruxsat berilsa lekin yozib bo'lmasa — 500 xato qaytariladi.
- **NOT TESTED, never PASS**: serverga yetmagan kategoria **PASS** deb hisoblanmaydi. Faqat aniq `PASS` verdict faqat PASS bo'ladi.
- **XSS himoya**: barcha serverdan kelgan satrlar `textContent` orqali DOM'ga yuboriladi, `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write` ishlatilmaydi.
- **Input validation**: `DisallowUnknownFields`, 32 KiB body limit, POST-only, same-origin tekshiruvi, raqamli knopkalar kesilmaydi balki rad etiladi.

## 🛠️ O'rnatish

```bash
# Repo'ni klonlash
git clone https://github.com/asadbekabdulboqiyev/stress-strike.git
cd stress-strike

# Build qilish (Go 1.26+)
export GOTOOLCHAIN=go1.26.9
go build ./...

# Binary'larni o'rnatish
go build -o ~/go/bin/stress-strike ./cmd/stress-strike/
go build -o ~/go/bin/stress-strike-dashboard ./cmd/stress-strike-dashboard/
go build -o ~/go/bin/stress-strike-scan ./cmd/stress-strike-scan/

# Tekshirish
stress-strike --version
# stress-strike v0.14.3
```

## 🖥️ Web Dashboardni ishga tushirish

```bash
# Dashboardni ishga tushirish (loopback, authsiz)
stress-strike dashboard --listen 127.0.0.1:8888

# Brauzerda ochish:
# http://127.0.0.1:8888
```

Dashboard’da quyidagi panellar mavjud:
- **OWASP Top 10** — skan, natija jadvali, topilishlar
- **Pentest** — offensiv skan, xavfsizlik topilishlari
- **Crawler** — sayt crawleri, topilgan URL'lar
- **Fuzzer** — HTTP fuzzer natijalari
- **Subdomain** — subdomenlar ro'yxati
- **Port Scan** — ochiq portlar, servislar, bannerlar
- **Dir Bust** — topilgan yo‘llar, status kodlar
- **SSL/TLS** — sertifikat tahlili
- **JWT** — token xavfsizligi
- **GraphQL** — introspektsiya tekshiruvi
- **WebSocket** — WS/WSS xavfsizligi

## 🧪 API ishlatish (curl misollari)

```bash
# OWASP skan (passive, default)
curl -X POST http://127.0.0.1:8888/api/owasp/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","passive":true}'

# Pentest (intrusive, ticket kerak)
curl -X POST http://127.0.0.1:8888/api/pentest/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","intrusive":true,"authorized":"TICKET-ID"}'

# Crawler
curl -X POST http://127.0.0.1:8888/api/crawl/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","depth":3,"pages":100}'

# Fuzzer
curl -X POST http://127.0.0.1:8888/api/fuzz/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com/api","paths":["/item/{id}"],"mutations":100}'

# SSL/TLS
curl -X POST http://127.0.0.1:8888/api/sslscan \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com:443"}'
```

## 🧪 Testlarni ishga tushirish

```bash
# Barcha paketlarni race detektorda tekshirish
export GOTOOLCHAIN=go1.26.9
go test -race -count=1 ./...

# Faqat dashboard va scanner paketlarini tekshirish
go test -race -count=1 ./internal/dashboard/... ./internal/scanner/...

# Linter (golangci-lint v2.14.0)
golangci-lint run --new ./...

# Gosec ratchet (xavfsizlik skaneri)
bash scripts/gosec-ratchet.sh
```

## 📁 Loyiha tuzilishi

```
stress-strike/
├── cmd/
│   ├── stress-strike/          # Asosiy CLI (dashboard, pentest, authorize, audit)
│   ├── stress-strike-dashboard/# Web dashboard binary
│   ├── stress-strike-scan/     # CLI skaner binary
│   └── ...
├── internal/
│   ├── dashboard/              # Web dashboard (handlers, server, app.js, index.html, style.css)
│   ├── scanner/                # Skaner yadrosi (OWASP, pentest, fuzz, crawl, subdomain, portscan, dirbust, sslscan, jwt, graphql, websocket, guard, probe, intrusive)
│   ├── authz/                  # Avtorizatsiya va scope gate
│   └── ...
├── docs/
│   └── OWASP-SCANNER.md        # OWASP skaner hujjati
├── scripts/
│   └── gosec-ratchet.sh        # Gosec xavfsizlik skaneri ratchet
├── .golangci.yml               # Linter konfiguratsiyasi
├── .gitignore
├── LICENSE
└── go.mod
```

## 📄 Litsenziya

Bu loyicha **MIT litsenziyasi** asosida tarqatiladi. Batasini `LICENSE` faylda ko‘ring.

## 🏆 “Ixtirochilikka qadam” olimpiadasi uchun

Bu loyicha quyidagini taqdim etadi:
- 11 ta xavfsizlik skanerni bitta dashboard'da birlashtirish
- Har skan uchun ruxsatgat (authz) va audit log
- Xavfsiz frontend (XSS himoyasi, faqat textContent)
- Rostlik prinsipi: **NOT TESTED, never PASS**
- To'liq test qilingan, CI/CD orqali tekshirilgan

---

**Muallif**: Asadbek Abdulboqiyev  
**Versiya**: 0.14.3  
**Repo**: https://github.com/asadbekabdulboqiyev/stress-strike