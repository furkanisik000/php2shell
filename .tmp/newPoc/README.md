# newPoc — php2shell brute-force PoC (X-Powered-By otomatik offset)

## Amaç
20-30 farklı host'u (distro/glibc/SAPI varyasyonu) tek komutla brute-force sweep etmek.
Her host'ta **X-Powered-By → versiyon → otomatik offset** doldurulur, basit bf çalışır.

## Dosyalar
- `common.py` — HTTP primitifleri (raw-socket chunked, cookie parse, **X-Powered-By okuyucu + offset loader**)
- `bf_min.py` — TEK host, en basit bf (OOM → simple session-init → cookie sinyali)
- `bf_multihost.py` — ÇOKLU host sweep (X-Powered-By → offset → bf)
- `bf_simple.py` — TEK host, field-size sweep
- `stage1_leak.py` — eness-style 2-istek leak (OOM + forged zend_string)
- `diag_worker.py` — worker survival probe (OOM sonra session-init)
- `hosts.txt` — host:port listesi şablonu

## Hızlı kullanım

```bash
cd newPoc

# 1) Sadece probe: X-Powered-By + versiyon + offset (bf YOK)
python3 bf_multihost.py --hosts-file hosts.txt --probe-only

# 2) Tam bf sweep (mevcut 14 host, OOM size 8/16/32/64/128)
python3 bf_multihost.py --hosts-file hosts.txt --sizes 8,16,32,64,128

# 3) Tek host, geniş size sweep
python3 bf_min.py --port 18113 --sizes 1,2,4,8,16,32,64,128,256

# 4) Yeni host'lar (farklı IP)
python3 bf_multihost.py --hosts 10.0.0.5:8080,10.0.0.6:8080 --sizes 8,16,32,64
```

## Sinyal
| signal | anlam |
|---|---|
| `clean` | Set-Cookie = 32B session ID (worker clean recover) |
| `big` | Set-Cookie > 100B ama heap pointer yok (belirsiz) |
| `LEAK!` | Set-Cookie'da 2MB-aligned heap pointer cluster → **heap leak** |

## Bulgu (2026-10-23)
- **8.4.26 (18113):** 8/16/32MB'da OOM (500), worker clean recover (32B)
- **8.2.34 (18111):** 8/16/32MB'da OOM ETMİYOR (200) — farklı memory_limit
- → Her host'un memory_limit'ı farklı; bf'de size'ı geniş tut (128-256MB)
- **Kök bloklayıcı:** glibc 2.41 (Debian 13.7) worker'ı clean recover ettiriyor;
  eness lab (Debian 12, glibc 2.36)'da çalışıyor. 20-30 host sweep'inin amacı:
  clean-recover ETMEYEN bir glibc/distro/SAPI bulmak.

## Offset kaynağı
`labs/versions/<ver>/offsets.env` — ZIF_OFFSET (zif_system) + DTOR_OFFSET (zval_ptr_dtor)
- 5.4.45/5.5.38: CLI-relative (DELTA önemli, libphp.so mutlak offset'ı yok)
- 5.6.40 → 8.5.11: libphp.so mutlak offset'leri
