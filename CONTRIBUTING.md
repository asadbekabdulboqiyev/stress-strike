# Contributing to Sift

Salom! Sift ga xisqatingizni qadr qildik. Quyidagi qoidalarga rioya
qiling:

## 1. Ishni boshlashdan oldin

- **Issue oching.** Yangi funksiyalar, xatolar (bug) yoki takliflar uchun
  avval GitHub issue oching. "No limit" usulda ishlaymiz: har bir issue
  alohida commit sifatida ochiladi.
- **Taklif qabul qilinishi kutiladi.** Kod yozishdan oldin maintainer tomonidan
  muhokama qilinishi kerak (agar kattalashtirish bo'lsa).

## 2. Kod stilini

- Go: `gofmt`, `go vet`, `golangci-lint` (agar mavjud bo'lsa).
- Barcha yangi funksiyalar uchun `*_test.go` yozilishi majburiy.
- Har bir commit alohida, qisqa va ma'noli bo'lsin:
  `feat(scope): description` yoki `fix(scope): description`.
- Commit xabarida `fayl:qator` ko'rsatilmasligi mumkin, lekin nima qilinganini
  ochiq ko'rsating.

## 3. Tekshiruvlar (CI)

Har PR uchun quyidagilar muvaffaqiyatli bo'lishi shart:

```bash
go build ./...
go vet ./...
go test -count=1 ./...
```

Coverage target: **80%+**. Yangi kod coverage'ni kamaytirmasligi kerak.

## 4. Xavfsizlik (Security)

- **Hech qachon** API kalitlarini, `.env` fayllarini yoki secretlarni commit
  qilmang.
- Xavfsizlik zaifliklarini topgan bo'lsangiz, difault branch'ga push qilmang.
  `security@techcorp.example` manziliga yuboring (Responsible Disclosure).
- Hamma state-changing endpointlar OIDC + RBAC orqali himoyalangan.

## 5. Hujjatlar (Docs)

- Yangi funksiya qo'shganda `docs/` papkasiga ma'lumot qo'shing.
- API o'zgarsa, `docs/` da yangilanish kerak.
- RFC/standartlar (masalan VPMP) alohida faylda rostlanadi.

## 6. Release jarayoni

- Versiya semver (v0.14.5 → v0.15.0).
- `CHANGELOG.md` yangilanadi.
- `git tag` orqali release belgalanadi.
- Build `./scripts/build-all.sh` orqali amalga oshiriladi.

## 7. Mualliflar (Maintainers)

Joriy maintainerlar ro'yxati `MAINTAINERS.md` da.

Boshqa savollar bo'lsa, issue oching yoki maintainerlarga murojaat qiling.
Rahmat!
