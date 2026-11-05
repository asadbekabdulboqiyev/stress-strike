# Stress-Strike — Dual-Use & Legal

**Status:** Draft  
**Version:** 1.0  
**Date:** 2026-11-05  
**Abstract:** Stress-strike — bu muallifona tekshirish (authorized assessment) va
yuk sinovi (load testing) uchun mo'ljallangan dastur. U "dual-use": ham foydali
texnik xavfsizlik tekshirishi uchun, ham (agar noto'g'ri ishlatilsa) hujum
sabbab bo'lishi mumkin. Quyidagi hujjat foydalanish chegarasi, soritish (responsible
disclosure), nostrat kuzatish (abuse monitoring) va ma'muriyat shartnomasini
(DPA) belgilaydi.

---

## 1. Foydalanish chegarasi (Acceptable Use Policy)

### 1.1 Ruxsat etilgan foydalanish

- **O'z infrastrukturangizga** yoki **ruxsat berilgan** (yozma ruxsat bilan)
  bazaga stress sinovi va xavfsizlik skanini ishlatish.
- **Qanuni** va **ekspert** nazoratda bo'lgan authorized penetration testing.
- O'quv va ilmiy maqsadlarda foydalanish (laboratoriya, test muhit).

### 1.2 Ta'qilolanadigan foydalanish

Quyidagilar ta'qilolanadi:

- Ruxsatsiz hujum (DDoS, brute-force, injection) uchun foydalanish.
- Boshqa shaxsning yoki tashkilotning serverlariga ruxsatsiz kirishga urinish.
- Filial yoki afosqaruv maqsadlarida xavfsizlik skanini ishlatish.
- Qanun buzişiga yo'l qo'yuvchi niyat bilan foydalanish.

**Vaqtincha ishda:** Barcha skaner va yuk sinov operatsiyalari audit log'ga
yoziladi va coordinator tomonidan kuzatiladi.

---

## 2. Responsible Disclosure (Xavfsizlik xabari)

Stress-strike da xavfsizlik zaiflik aniqlagan bo'lsangiz, quyida amalrang:

1. **Afsoskarish (embargo):** Mavjud xatoni ochiq kokiga chiqarmang.
2. **Yuborish:** `security@techcorp.example` manziliga xabar yuboring.
3. **Hujjat:** Zaiflik turi, qayerda aniqlandi, qaytarish (reproduction) qadamlari,
   ta'sir baholashi.
4. **Javob:** 5 ish kuni ichida tasdiqlanadi, 30 ish kuni ichida hal qilinadi yoki
   reja beriladi.
5. **Aks etadi:** Hal qilindan so'ng, research uchun cradit beriladi (agar istasa).

**Xavfsizlik xabarini ochiq kokiga chiqarishdan oldin 90 kundan kutish kerak.**

---

## 3. Abuse Monitoring (Nostrat kuzatish)

Stress-strike kuzatish vositalari:

| vosita | maqsad | log'lanadi |
|--------|--------|------------|
| Coordinator attestation | worker'imonligini tekshirish | `internal/dist/coordinator/` |
| Audit log | barcha state-changing operatsiyalar | append-only JSONL |
| Rate limiter | dashboard bo'yicha kira-ochirish | `internal/dashboard/auth.go` |
| Scope gate | faqat ruxsat berilgan hostlarni skanlash | `internal/scanner/guard.go` |
| AuthorizedWorkers allowlist | faqat ruxsat berilgan workerlar | `internal/dist/coordinator/master.go` |

Abuse aniqlangan holda:
- Worker `failed` deb marklanadi, telemetry rad etiladi (fail-closed).
- IP foydalanuvchi bloklanadi (dashboard rate limiter).
- Xabar `security@techcorp.example` ga yuboriladi.

---

## 4. DPA (Data Processing Agreement)

Stress-strike quyidagi ma'lumotlarni qayta ishlashi mumkin:

| Ma'lumot turi | Manba | Saqlash muddati |
|--------------|-------|-----------------|
| Target URL / host | Foydalanuvchi kiritadi | 30 kun (log) |
| Worker public key | Worker ro'yxatdan o'tganda | Doimo (allowlist) |
| Telemetry (rps, errors, latency) | Worker'dan keladi | 90 kun |
| Findings (vulnerabilities) | Skaner natijasi | 1 yil |
| Audit log entries | Dashboard / CLI | 1 yil |

### 4.1 Ma'muriyat shartlari

- **Ma'lumotlar uchinchi tarafga yubormaydi** (agar foydalanuvchi ruxsat bermasa).
- **Shifrlangan o'tkazish:** TLS orqali barcha o'tkazmalar.
- **O'chirish:** Foydalanuvchi so'rovida ma'lumotlar 7 kun ichida o'chiriladi.
- **Beruvchi:** TechCorp (asadbek@techcorp.example)

### 4.2 Huquqi chegara

Stress-strike — bu "as-is" (hozirgidek) taqdim etiladi, hech qanday kafolat
siz. Foydalanuvchi o'zi uchun javobgardan holda ishlaydi.

---

## 5. Kontaktlar

| Maqsad | Manzil |
|--------|--------|
| Umumiy savol | maintainers@techcorp.example |
| Xavfsizlik xabari | security@techcorp.example |
| Ma'muriyat / DPA | legal@techcorp.example |
| Enterprise / sotuv | sales@techcorp.example |
