# stress-strike — Loyiha Xulosa (One-Pager)

## 1. Loyiha nomi

**stress-strike** — zamonaviy, xavfsiz va brauzerdan boshqariladigan xavfsizlik skanerni dashboard.

## 2. Muammo (nima hal qilinmozg?)

Joriy xavfsizlik skanerlar ko'pincha:
- faqat komanda qatorida (CLI) ishlaydi, brauzerdan foydalanish quvvatli emas;
- har bir skaner alohida vosita, birlashtirilgan dashboard yoq;
- "PASS" deb hisoblaydi, lekin haqiqatan skan qilmasdan;
- serverdan kelgan ma'lumotlarni tekshirmasdan UI'ga yuboradi (XSS xavfi);
- avtorizatsiya va audit log'ga rioyamiento kam.

stress-strike bularning barchasini hal qiladi: **bittada web dashboard'dan OWASP Top 10, offensiv pentest, crawler, fuzzer, subdomain, portscan, dirbust, SSL/TLS, JWT, GraphQL, WebSocket — 11 ta skanerni boshqarish**.

## 3. Hal (nima qilingan)

| Qism | Tafsilot |
|---|---|
| **Scanner yadrosi** | `internal/scanner/` — 11 ta skaner moduli, `Requester` yod (gate) orqali barcha so'rovlar tekshiriladi |
| **Avtorizatsiya (authz)** | `OpScan` / `OpPentest` gate, append-only audit log, fail-closed |
| **Web dashboard** | `internal/dashboard/` — 11 ta panel, `textContent`-only DOM (XSS yo'q) |
| **REST API** | 11 ta `POST` endpoint, JSON so'rov/javob, validatsiya |
| **CLI** | `stress-strike`, `stress-strike-dashboard`, `stress-strike-scan` binarylari |
| **Texnika** | Go 1.26, React-ish vanilla JS, Vite/Tailwind shablon uslubida |

## 4. Keyfiyatli xususiyatlar

- **NOT TESTED, never PASS** — serverga yetmagan kategoria rostlikka e'tibor beriladi, avtomatik PASS qo'yilmaydi.
- **Scope gate** — default faqat kiritilgan host, redirect ham tekshiriladi.
- **Single-flight scan** — bir vaqtda bitta skan, ikkinchi `409` qaytaradi.
- **Input validation** — `DisallowUnknownFields`, 32 KiB limit, knopkalar rad etiladi (klamp qilinmaydi).
- **XSS himoyasi** — barcha serverdan kelgan satrlar `textContent` orqali yuboriladi.

## 5. Texnik metrikalar

| Metrika | Qiymat |
|---|---|
| Kod satrlari (yangi) | ~8 000+ |
| Test qilingan paketlar | 36+ |
| `go test -race` | 0 FAIL / 0 panic |
| `golangci-lint` | 0 issue (yangi kod uchun) |
| gosec ratchet | PASS (frozen 155) |
| CI ishlar | CodeQL, Security, Docker, Test, Lint |

## 6. Qanday foydalaniladi (demo akisi)

1. `stress-strike dashboard --listen 127.0.0.1:8888` — dashboardni ishga tushirish
2. Brauzerda `http://127.0.0.1:8888` ochish
3. OWASP skanni bosish: `target=https://example.com`, `passive=true`
4. Natija: kategoriylar, topilishlar, gate statistikasi, audit log

## 7. Muallif va litsenziya

- **Muallif**: Asadbek Abdulboqiyev
- **Versiya**: 0.14.3
- **Litsenziya**: MIT
- **Repo**: https://github.com/asadbekabdulboqiyev/stress-strike

## 8. Kelajak rejalari

- Windows CI flake hal qilish (`internal/engine/power_test.go`)
- Echt-vaqt bildirishnomalar (WebSocket orqali)
- Foydalanuvchi ro'yxati va rol-based access control (RBAC)
- Skanner natijalarini PDF/JSON eksport qilish

---

**“Ixtirochilikka qadam” olimpiadasi uchun tayyorlangan.** Barcha kod ochiq, test qilingan va xavfsiz.