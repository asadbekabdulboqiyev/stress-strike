# stress-strike — API Hujjati (API Documentation)

Barcha endpointlar faqat `POST` so'rovlarni qabul qiladi, `Content-Type: application/json` talab qiladi va faqat same-origin (brauzer) yoki non-browser (curl, CLI) so'rovlardan qabul qiladi.

## Umumiy qoidalar

| Xususiyat | Qiymat |
|---|---|
| Body limit | 32 KiB |
| Unknown fields | Rad etiladi (`DisallowUnknownFields`) |
| Single-flight | Bir vaqtda bitta skan (ikkinchi → `409 Conflict`) |
| Authz gate | `OpScan` yoki `OpPentest` (intrusive uchun chipta talab qilinadi) |
| Audit log | Har qaror append-only `audit.jsonl` ga yoziladi |
| Numeric knobs | Rad etiladi, klamp qilinmaydi (rate 1–50, budget 1–2000, timeout 1–30 s) |
| Web cap | `budget/rate ≤ 120 s` |

---

## 1. POST /api/owasp/scan — OWASP Top 10 Scanner

So'rov sadasi:

```json
{
  "target": "https://example.com",
  "paths": ["/", "/login"],
  "allow": ["example.com"],
  "allowAll": false,
  "intrusive": false,
  "enable": [],
  "passive": true,
  "dryRun": false,
  "rate": 10,
  "budget": 400,
  "timeoutSec": 10,
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "target": "https://example.com",
  "scope": ["example.com"],
  "dryRun": false,
  "intrusive": false,
  "passive": true,
  "tested": 6,
  "total": 10,
  "score": 83,
  "grade": "B",
  "categories": [
    {"id":"A01","name":"Broken Access Control","status":"NOT TESTED","findings":[],"remediation":[]}
  ],
  "findings": [
    {"id":"PSV-BANNER-006","severity":"informational","title":"Server banner","parameter":"","cwe":"","confidence":"informational","evidence":"GET http://... returned Server: ..."}
  ],
  "gate": {"requests_sent":135,"requests_refused":0,"refused_out_of_scope":0,"refused_intrusive":0,"refused_budget":0,"refused_rate":0,"refused_dry_run":0},
  "notes": []
}
```

`status` qiymatlari: `PASS`, `FAIL`, `WARNING`, `NOT TESTED`. `NOT TESTED` — **bu PASS emas**.

---

## 2. POST /api/pentest/scan — Offensive Pentest

So'rov sadasi (owasp bilan bir xil, lekin `depth` qo'shilgan):

```json
{
  "target": "https://example.com",
  "depth": 2,
  "paths": [],
  "allow": [],
  "allowAll": false,
  "intrusive": true,
  "enable": ["crlf","boolean-sqli","time-sqli","path-traversal","ssrf","write-methods"],
  "passive": false,
  "dryRun": false,
  "rate": 10,
  "budget": 400,
  "timeoutSec": 10,
  "authorized": "TICKET-ID"
}
```

Intrusive so'rovi **majburiy `authorized` chiptasi** va `OpPentest` ruxsatini talab qiladi.

Javob `owasp/scan` bilan bir xil, lekin qo'shimcha `depth` maydoni bor.

---

## 3. POST /api/crawl/scan — Site Crawler (katana-like)

```json
{
  "target": "https://example.com",
  "depth": 3,
  "pages": 100,
  "timeoutSec": 10,
  "rate": 10,
  "budget": 400,
  "concurrency": 5,
  "allow": [],
  "allowAll": false,
  "offsite": false,
  "dryRun": false,
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "target": "https://example.com",
  "scope": ["example.com"],
  "pages": 42,
  "endpoints": 87,
  "duration_sec": 12.4,
  "dryRun": false,
  "offsite": false,
  "gate": {"requests_sent":42,"requests_refused":0,...},
  "discovered": [
    {"url":"https://example.com/about","method":"GET","params":[],"found_at":"https://example.com/","kind":"link"},
    {"url":"https://example.com/login","method":"POST","params":["username","password"],"found_at":"https://example.com/","kind":"form"}
  ],
  "notes": []
}
```

---

## 4. POST /api/fuzz/scan — HTTP Fuzzer

```json
{
  "target": "https://example.com/api",
  "paths": ["/item/{id}","/search?q="],
  "methods": ["GET","POST"],
  "mutations": 100,
  "concurrency": 10,
  "timeoutSec": 10,
  "rate": 10,
  "budget": 400,
  "intrusive": false,
  "allow": [],
  "allowAll": false,
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "target": "https://example.com/api",
  "scope": ["example.com"],
  "sent": 200,
  "refused": 0,
  "interesting": 5,
  "findings": [
    {"method":"GET","url":"https://example.com/api/item/{id}","status_code":500,"body_len":120,"body_hash":"...","headers":[],"mutation":"path-param","reason":"status 500 vs 200; server error","response_time_ms":150}
  ],
  "gate": {...},
  "notes": []
}
```

---

## 5. POST /api/subdomain/scan — Subdomain Enumeration

```json
{
  "target": "example.com",
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "target": "example.com",
  "found": 15,
  "resolved": 10,
  "subdomains": [
    {"name":"www.example.com","ips":["93.184.216.34"],"source":"dns","methods":["A/AAAA"]},
    {"name":"mail.example.com","ips":["1.2.3.4"],"source":"dns","methods":["MX"]}
  ],
  "duration_sec": 3.2,
  "notes": []
}
```

---

## 6. POST /api/portscan — Port Scanner

```json
{
  "target": "example.com",
  "ports": [22,80,443,8080,8443],
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "target": "example.com",
  "opened": 3,
  "closed": 0,
  "ports": [
    {"port":80,"state":"open","service":"http","banner":"HTTP/1.1 200 OK","protocol":"tcp"},
    {"port":443,"state":"open","service":"https","banner":"","protocol":"tcp"}
  ],
  "duration_sec": 1.5,
  "notes": []
}
```

---

## 7. POST /api/dirbust — Directory Brute-forcer

```json
{
  "target": "https://example.com",
  "paths": ["/admin","/.env","/.git/","/api","/swagger"],
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "target": "https://example.com",
  "found": 2,
  "entries": [
    {"url":"https://example.com/admin","method":"GET","status_code":200,"size":1250,"title":"Admin Panel"},
    {"url":"https://example.com/api","method":"GET","status_code":403,"size":45,"title":""}
  ],
  "duration_sec": 0.8,
  "notes": []
}
```

---

## 8. POST /api/sslscan — SSL/TLS Analyzer

```json
{
  "target": "example.com:443",
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "target": "example.com:443",
  "valid": true,
  "issuer":"Let's Encrypt",
  "subject":"example.com",
  "not_before":"2026-01-01",
  "not_after":"2026-07-01",
  "expired": false,
  "sans": ["example.com","www.example.com"],
  "cipher":"TLS_AES_256_GCM_SHA384",
  "version":"TLS 1.3",
  "issues": [],
  "duration_sec": 0.5,
  "notes": []
}
```

---

## 9. POST /api/jwt/scan — JWT Analyzer

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "token": "...",
  "valid": true,
  "algo_confusion": false,
  "header": {"alg":"HS256","typ":"JWT"},
  "payload": {"sub":"1234567890","name":"John Doe","iat":1516239022},
  "issues": ["symmetric algorithm (HS256) — verify secret strength", "missing 'exp' claim", "missing 'iss' claim", "missing 'aud' claim"]
}
```

---

## 10. POST /api/graphql/scan — GraphQL Scanner

```json
{
  "endpoint": "https://example.com/graphql",
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "endpoint": "https://example.com/graphql",
  "reachable": true,
  "introspection": true,
  "schema":"Query",
  "types": ["Query","Mutation","User","Post"],
  "issues": ["GraphQL introspection is enabled — schema exposed"],
  "duration_sec": 0.4
}
```

---

## 11. POST /api/websocket/scan — WebSocket Tester

```json
{
  "url": "wss://example.com/ws",
  "authorized": ""
}
```

Javob:

```json
{
  "ok": true,
  "url": "wss://example.com/ws",
  "connected": true,
  "subprotocol": "",
  "issues": ["no Origin header sent; server accepted connection — verify origin validation"],
  "messages_sent": 1,
  "duration_sec": 0.6
}
```

---

## Xatolik kodlari

| Kod | Ma'nosi |
|---|---|
| `200` | Muvaffaqiyatli skan |
| `400` | Noto'g'ri so'rov (validation xatosi) |
| `401` | Autentifikatsiya talab qilinadi (session lock) |
| `403` | Ruxsat rad etildi (authz gate) |
| `405` | Faqat `POST` so'rov qabul qilinadi |
| `409` | Boshqa skan jarayonda (single-flight) |
| `500` | Audit log yozib bo'lmadi (fail-closed) |

---

## Xavsvizlik eslatmasi

Bu vosita faqat **sizning yoki ruxsat berilgan tizimlarni** skanlash uchun mo'ljallanmagan. Ruxsatsiz skanlash qonuniy javobgarlikga olib ketishi mumkin.