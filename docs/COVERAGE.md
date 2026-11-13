# Coverage — tekshirilgan baza

`Sift` uchun test qonidasi. Maqsad: har commitda **oqitiladigan** ham
**o'rganiladigan** (covered) foizni nazorat qilish.

## Olish holatdagi baseline (2026-11-05)

| Bosqich | Jonli natija | Izoh |
|---|---:|---|
| Umumiy to'plam (`go test ./... -covermode=atomic -coverpkg=./...`) | **58.7%** | `-coverpkg=./...` bilan baholanadi; `-cover` faqat o'z qatlamni hisoblaydi |
| Eng yuqori paketlar | attest 81.9%, otel 80.2%, otel/exporter 98.0%, probe 97.1%, honor 94.0%, rbac 100.0%, demostore 79.1%, metrics/exporter 98.0% | Kriptografik + governance paketlari yuqida |
| Eng yuqori yo'qlangan (real kod, CLI mains bilan) | store/postgres 78.6%, siem 89.0%, report 88.8%, secrets 91.7%, legal 74.6%, metrics 81.5% | |
| O'rganilgan emas (real kod) | store/memstore 0%, tenant 0%, version 0%, auditdb 0%, replay/pcap, engine kernel | Yuqida ko'rib chiqilgan |
| CLI mains (`cmd/*/main.go`) | 0.0% | Tan yagona ish, noto'g'ri hisoblanadi — `main` funksiyasi hech qachon ishga tushmaydi |

## Olish buyrug'li tekshiruvlar

```bash
# Local: to'liq tekshiruv + yuqori o'lchov
go test -race -timeout 20m -covermode=atomic -coverprofile=coverage.out -coverpkg=./... ./...

# Umumiy foizni ko'tarib ko'rish
go tool cover -func=coverage.out | tail -1   # umumiy: X%

# O'rganilgan emas funksiyalarni ko'rsatish
go tool cover -func=coverage.out | grep '0.0%'
```

## CI qoidasi

`.github/workflows/ci.yml` da `coverage` job:

1. `test` jobidan `coverage-*.out` fayllarini oladi (`-coverpkg=./...`);
2. `go tool cover -func` orqali **umumiy foizni** hisoblaydi;
3. foiz **45%** chetidan past bo'lsa CI **red** qaytadi (`floor=45`).

Bu me'yoriy hisoblaydi `test` jobi `go test -race -covermode=atomic -coverpkg=./... ./...`
ishlaydi — ya'ni `test` va `coverage` bir-biriga tegishli hisoblagan natijani qayta ishga tushiradi.

## Mevsulari

- Baseline 58.7% ga yetib, har release da kengaytiriladi (floor 45 ga tushadigan
  kuzatilgan o'lchovlarni `docs/COVERAGE.md` ga yoziladi).
- 0% ro'yxatiga kirgan haqiqiy kod paketlar (memstore, tenant, version, auditdb) uchun
  unit testlar yozilishi kabi ilova yoki internal kodlarni qo'llab-quvvatlash lozim.
- `main()` funksiyalari 0% — tani yagona, chuqar emas.
- Flaky-nazar: `internal/engine` testlari `-race -coverpkg=./...` da ishladi.

## Afzallik

- `-coverpkg=./...` barcha paketlarni o'lchaydi; u o'z qatlamni o'lgan holda esa
  bog'liqlarini ham o'ladi, shuning uchun umumiy foiz yetarli katta bo'lishi mumkin.
- `-covermode=atomic` yadigan reaktivlash uchun; `-covermode=count` natijalari
  bir-biriga ta'sir qilmaydi, balki arxiv ko'pincha farqi qiladi (natijani bir xil
  qasamda tekshirish kerak).
