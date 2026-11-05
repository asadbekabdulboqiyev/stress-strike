# Stress-Strike Enterprise

**Status:** Mapping only (no SOC 2 / ISO 27001 certification yet)  
**Version:** 1.0  
**Date:** 2026-11-05  
**Abstract:** Enterprise tier — open-core stress-strike ga qo'shimcha, commerciak
tegishli funksiyalar: SLA, prioritet支持, role-based access control, audit log,
SSO/OIDC, dedicated support, va harajat bilan bog'liq bo'lmagan open-core
xususiyatlar orasidagi chegara.

---

## 1. Open-core chegarasi

| Xususiyat | Open Core (Apache-2.0) | Enterprise (commercial) |
|-----------|------------------------|-------------------------|
| HTTP load testing | ✅ | ✅ |
| Security scanner (TLS/WAF/HTTP/security) | ✅ | ✅ |
| Distributed mode + worker attestation | ✅ | ✅ |
| Dashboard (web UI) | ✅ | ✅ |
| OIDC / RBAC auth | ✅ | ✅ |
| HTTP/3 QUIC probing | ✅ | ✅ |
| Browser-based load testing | ✅ | ✅ |
| SLA garantiyasi | ❌ | ✅ |
| Prioritet 24/7 yordam | ❌ | ✅ |
| SOC 2 Type II / ISO 27001 sertifikat | ❌ | ❌ (reja) |
| Dedicated account manager | ❌ | ✅ |
| Custom SLA / SLIs | ❌ | ✅ |
| On-premise deployment yordam | ❌ | ✅ |
| Advanced audit log export | ❌ | ✅ |
| Priority bug fixes | ❌ | ✅ |

---

## 2. Enterprise funksiyalari

### 2.1 SLA (Service Level Agreement)

| Metrik | Target |
|--------|--------|
| Uptime | 99.9% (monthly) |
| Support javob vaqti (P1) | < 1 hour |
| Support javob vaqti (P2) | < 4 business hours |
| Support javob vaqti (P3) | < 1 business day |
| Bug fix (P1) | < 48 hours |
| Bug fix (P2) | < 7 days |

### 2.2 Qo'llab-quvvatlash (Support)

- **Email:** support@techcorp.example
- **Portal:** enterprise.techcorp.example/support
- **SLA tracking:** har bir ticket uchun SLA timer ko'rsatiladi.

### 2.3 Audit & Compliance

- Barcha state-changing operatsiyalar append-only audit log'ga yoziladi.
- Enterprise muellarlarga audit log export (JSON/CSV/PDF) beriladi.
- SOC 2 Type II va ISO 27001 sertifikati — rejalashtirilgan (hali yo'q).

### 2.4 Deployment

- On-premise: Docker image, Helm chart, binary.
- Cloud: AWS Marketplace, Azure Marketplace (reja).

---

## 3. Narx (Pricing)

| Reja | Narx | Foydalanuvchi | SLA |
|------|------|-------------|-----|
| Startup | $499/oy | 5 admin | 99.5%, < 24h javob |
| Business | $1,499/oy | 25 admin | 99.9%, < 4h javob |
| Enterprise | Custom | Cheksiz | 99.99%, < 1h javob, dedicated AM |

---

## 4. Qaysi holatlarda enterprise kerak?

- **SLA kerak bo'lgan kompaniya** (e-tijorat, bank, gov).
- **24/7 prioritet yordam kerak.**
- **SOC 2 / ISO 27001 talab qiluvchi mijozlar.**
- **Dedicated account manager kerak.**

Open-core foydalanuvchilarga barcha texnik xususiyatlar bepul. Enterprise — faqat
yordam, SLA va sertifikatlar uchun.

---

## 5. Open items

- [ ] SOC 2 Type II audit boshqarish
- [ ] ISO 27001 sertifikat olish
- [ ] Enterprise billing/licensing tizimini qo'shish
- [ ] Dedicated support portalni ishga tushirish
