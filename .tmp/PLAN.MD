# PLAN.MD — php2shell 5.4 → 8.5 Tam Surum Kalibrasyonu

**Amac:** CVE-2026-109618 / 109619 (php2shell) icin **5.4 → 8.5** araligindaki her
surumu **ayrintili analiz et → tam kalibre et → test et → uyarla**, her biri icin
**`id` ciktisini** ve **"ne yapildi, nerede"** kaydini tut; sonunda bir **UI** ile
butununu **arastirma olarak** sun.

**Basari olcusu (her surum icin):** `id>/out/p1` calistirildiginda `out/p1`
dosyasinda `uid=33(www-data) gid=33(www-data)` (ya da o SAPI'nin web kullanicisi)
gorulmesi. Bu, o surumun **dogrulandi** sayildigi anlamina gelir.

**Altin referans:** **8.4.26** (lab'de dogrulanmis). Diger her surum bu bazla
karsilastirilir; fark = o surumun kendine ozgu leak vektoru + offset + heap-shape'i.

> ⚠️ **Temel gercek (planin omurgasi):** Leak vektoru **surum-bagimlidir**,
> "ayni PoC + farkli offset" degildir. 8.4.26'da `Set-Cookie: PHPSESSID` uzerinden
> temiz chunk-base leak'i varken, **8.0.30'da ayni kanal manifest olmaz** (worker
> ya segfault'lar ya da normal 32-hex session ID doner). Yani her surum icin
> **o surumun OOM-bailout'unun nerede ve nasil corrupt oldugunu RE ile bulmak**
> gerekir. Bu yuzden plan "offset takasi" degil, **surum-bazli derin re-engineering**.

---

## 0. Kapsam ve varsayimlar

- **Surum secimi:** "5.4 → 8.5 arasi her surum" = **her minor serisinin
  son/etkilenen temsilci surumu** (14 surum). Istege bagli olarak herhangi bir
  patch surumune genisletilebilir (or. 8.0.30 yerine 8.0.28).
- **Yetki:** Tum testler kullanicinin **yetkili** oldugu kendi test
  sitelerinde (`test.example.com` 7.4.33, `lab.example.com/izin.php` 8.2.34) + **Docker
  lab** (kendi makinemizde). Komut **yalnizca zararsiz** (`id>/out/p1`,
  `whoami`). Webshell / reverse-shell / veri okuma **YOK**.
- **SAPI:** **mod_php + Apache prefork**, **tek worker** (PoC'un varsayilan
  profili; Chain D — sifir bagimlilikli pre-auth RCE).
- **Platform:** macOS ARM64; eski (x86) imajlar qemu ile yavas calisir.
  5.4 / 5.5'in **Docker imaji yok** → kaynak build gerekir.

---

## 1. Surum matrisi (14 temsilci surum)

| # | Surum | Branch | Durum | Docker imaji | Lab imaji (ARM64?) | Oncelik | Mevcut durum |
|---|---|---|---|---|---|---|---|
| 1 | **8.4.26** | 8.4 | Active `<8.4.27` | `php:8.4-apache` | ARM64 ✓ | **P0 (baz)** | ✅ **DOGRULANDI** |
| 2 | **8.5.11** | 8.5 | Active `<8.5.12` | `php:8.5-apache` | ARM64 ✓ | **P1** | ⬜ offset+leak gerekli |
| 3 | **8.3.35** | 8.3 | Active `<8.3.36` | `php:8.3-apache` | ARM64 ✓ | **P1** | ⬜ offset+leak gerekli |
| 4 | **8.2.34** | 8.2 | Security-only `<8.2.35` | `php:8.2-apache` | ARM64 ✓ | **P1** | 🟡 `zval_ptr_dtor=0x2fcd30`; zif/htdata yok |
| 5 | **8.1.32** | 8.1 | **EOL** | `php:8.1-apache` | ARM64 ✓ | **P2** | ⬜ |
| 6 | **8.0.30** | 8.0 | **EOL** | `php:8.0-apache` | ARM64 ✓ (qemu) | **P2 (odak)** | 🔴 **BLOCKED** — leak manifest olmuyor |
| 7 | **7.4.33** | 7.4 | **EOL** | `php:7.4-apache` | x86/qemu | **P2** | 🟡 `poc_74.py` var, dogrulanmadi; offset olculmeli |
| 8 | **7.3.33** | 7.3 | **EOL** | `php:7.3-apache` | x86/qemu | **P3** | ⬜ |
| 9 | **7.2.34** | 7.2 | **EOL** | `php:7.2-apache` | x86/qemu | **P3** | ⬜ |
| 10 | **7.1.33** | 7.1 | **EOL** | `php:7.1-apache` | x86/qemu | **P3** | ⬜ |
| 11 | **7.0.33** | 7.0 | **EOL** | `php:7.0-apache` | x86/qemu | **P4** | ⬜ |
| 12 | **5.6.40** | 5.6 | **EOL** | `php:5.6-apache` | x86/qemu | **P4** | ⬜ |
| 13 | **5.5.38** | 5.5 | **EOL** | ❌ imaj yok | **kaynak build** | **P5** | ⬜ |
| 14 | **5.4.45** | 5.4 | **EOL** | ❌ imaj yok | **kaynak build** | **P5** | ⬜ |

> **Not:** "EOL" = resmi yama yok → source backport / izolasyon. Bu surumler en
> kirilgan (yamasiz) ama en zor (non-stripped libphp + heap-shape icin **calisan**
> ornek gerekir). 5.4/5.5 Docker imaji yok → kaynak derlenmeli (ARM64'de yavas).

---

## 2. Her surum icin standart is akisi (7 adim)

Her surum icin **ayni iskelet** uygulanir; surume ozgu olan "Leak vektoru" ve
"heap-shape" adimlaridir. Adimlar siralidir; her adimda cikti bir sonraki
adimin girdisidir.

```
[1] KAYNAK ANALIZI   → o surumun session.c + Zend OOM path'i, 8.2.35 (yamali) ile diff
[2] LAB KURULUMU     → Docker: o surum mod_php prefork, tek worker, zorunlu ini
[3] OFFSET KALIB.    → non-stripped libphp'ten: zif_system / zval_ptr_dtor / htdata
[4] LEAK VEKTORU     → RE: o surumde OOM-bailout NEREDE corrupt, leak hangi kanaldan
[5] PoC UYARLAMASI   → 8.4.26 bazini o surumun leak+offset+heap'e gore degistir
[6] TEST             → id>/out/p1  →  out/p1 = uid=...(www-data)  ✓
[7] KAYIT            → SPEC.md + offsets.env + out/  (PLAN.MD tablosu guncelle)
```

### [1] Kaynak analizi (surum-bazli)
- `ext/session/session.c` → `php_session_rfc1867_callback` / `_update` / `_cleanup`.
- `Zend/zend_execute.c` + `main/main.c` → OOM-bailout / `longjmp` path'i.
- **Diff hedefi:** 8.2.35 (yamasi cikti) `in_rfc1867_update` re-entrancy guard'i +
  `php_session_(un)?serialize_init` → `set_incomplete_classes_only`. Bu guard
  **olmayan** her surum (5.4→8.2.34, 8.3.35, 8.4.26, 8.5.11) acik; guard'in
  **nasil** corrupt ettigini surum surum RE ile bul.
- Cikti: o surumun **vulnerable call-site'i** (dosya:satir) + corrupt olan
  global (`PS(id)`, `PS(mod_data)`, `EG(...)`, `BG(...)`).

### [2] Lab kurulumu (Docker)
- `php:<surum>-apache`, **prefork**, `StartServers=1 / MinSpareServers=1 /
  MaxClients=1` (tek worker), `/out` volume = webroot'a yazilabilir.
- **Zorunlu ini** (PoC profili): `memory_limit=8M`, `max_input_vars=1000`,
  `display_errors=1`, `session.upload_progress.enabled=1`,
  `post_max_size=64M`, `upload_max_filesize=32M`.
- `p.php`: `<?php ini_set('display_errors','1'); echo "ok\n";`
- **macOS ARM64 notu:** host→container port-forward kirik olabilir →
  `docker network p2s` + arm64 `p2s-cli` container'i, hedefe **isimle** eris.
  Eski x86 imajlar qemu ile yavas; 5.4/5.5 kaynak build.

### [3] Offset kalibrasyonu
- Non-stripped libphp (`labs/calib/libphp<xx>.so` ya da kaynak build ciktisi).
- `zif_system` (fake `pDestructor` hedefi), `zval_ptr_dtor` (stage-2 self-check),
  `htdata` (167B canli `zend_string` / `HashTable` layout — **heap'e bagli, calisan
  ornek gerekir**; statik cikmaz).
- Arac: `labs/eness/lab/elf_syms.py` / `labs/calibration-74/scan_dynsym.py`.
- **Self-check:** eness stage-2 `p & 0xFFF == dtor_offset & 0xFFF` → yanlis offset
  stage-2'de duser (hedefle eslesme dogrulanir).

### [4] Leak vektoru (surum-bazli RE) — **planin kritik adimi**
- Soru: bu surumde OOM-bailout **hangi kanaldan** siziriyor?
  - 8.4.26: `Set-Cookie: PHPSESSID` = 2MB-aligned chunk base (temiz leak).
  - 8.0.30: leak YOK → worker segfault ya da normal hex ID. **Farkli kanal bulunmali.**
- RE araclari: `objdump -d` (RFC1867 + OOM path), `scan_dynsym.py`, gerekirse
  `gdb`/core (lab'de) veya source-walk.
- Cikti: o surumun **leak kanali** (header/body/error-message/OOB-read) +
  **heap-shape** (hangi field, hangi boyut, hangi sira).

### [5] PoC uyarlamasi
- 8.4.26 baz PoC'u (`poc_109618.py`) **kopyala**, o surum icin:
  offset'leri `[3]`'ten, leak kanali + heap-shape'i `[4]`'ten degistir.
- 14-byte komut limiti: `id>/out/p1` (10B) uyumlu ✓.
- Her surumun PoC'i kendi klasorunde (`labs/versions/<surum>/poc.py`).

### [6] Test (zararsiz kanit)
- `python3 poc.py -u http://<lab>/p.php -c 'id>/out/p1' --proof-file out/p1`
- Dogrulama: `cat out/p1` → `uid=33(www-data) ...` **ve** site sonrasi 200 OK.
- **Negatif kontrol:** crash/502 + `out/p1` yok = basarisiz (retry gerek).

### [7] Kayit
- `labs/versions/<surum>/SPEC.md` (analiz + offset + leak + test log).
- `labs/versions/<surum>/offsets.env` (kalibre offset'ler).
- `labs/versions/<surum>/out/p1` + `out/test.log`.
- Bu PLAN.MD'nin §5 tablosu + §7 durum tablosu guncelle.

---

## 3. Surum-bazli detay (su anki bilinenler + yapilacaklar)

> Her bolum bir **sablon**dur: bilinenler dolduruldu, bilinmeyenler `TODO`.
> Durum: ✅ DOGRULANDI · 🟡 KISMEN · 🔴 BLOCKED · ⬜ BASLANMADI

### 3.1 — 8.4.26 (ALTIN BAZ) · ✅ DOGRULANDI
- **Kaynak:** eness PoC 4 asama (stage0 rotate → stage1 chunk leak →
  stage2 libphp leak → stage3 fake `pDestructor=zif_system`).
- **Offset:** `zif_system=0x43A870`, `zval_ptr_dtor=0x613C50`,
  `htdata=0x6E0D8` (lab bookworm profile).
- **Leak:** `Set-Cookie: PHPSESSID` = 2MB-aligned chunk base (temiz).
- **Test:** `id>/out/p1` → `uid=33(www-data)` ✓.
- **Nerede:** `labs/eness/poc_109618.py`, `labs/eness/out/offsets.env`.

### 3.2 — 8.5.11 (Active) · ⬜
- **Kaynak:** 8.4.26 ile diff (guard yok mu? struct fark?); `php:8.5-apache`.
- **Offset:** TODO — `zif/dtor/htdata` 8.5.11 libphp'ten.
- **Leak:** TODO — 8.4.26 kanalinin 8.5'te degisip degismedigi RE.
- **PoC:** TODO — 8.4.26 bazini 8.5'e uyarla.
- **Test:** TODO. **Nerede:** `labs/versions/8.5.11/`.

### 3.3 — 8.3.35 (Active) · ⬜
- **Kaynak:** 8.4.26 ile diff; `php:8.3-apache`.
- **Offset:** TODO. **Leak:** TODO. **PoC:** TODO. **Test:** TODO.
- **Nerede:** `labs/versions/8.3.35/`.

### 3.4 — 8.2.34 (Security-only) · 🟡 KISMEN
- **Hedef:** `lab.example.com/izin.php` (8.2.34, vektorler ACIK — multipart 200 OK).
- **Kaynak:** 8.2.35 (yamasi cikti) `in_rfc1867_update` guard'i 8.2.34'te **YOK**
  → acik. `labs/calibration-74/php-8.2.35/ext/session/session.c` (referans).
- **Offset:** `zval_ptr_dtor=0x2fcd30` (8.2.35 sury.org paketi) ✓ ·
  `zif_system` TODO (stripped → calisan 8.2.34/8.2.35 gerekli) · `htdata` TODO.
- **Leak:** TODO — 8.4.26 kanalinin 8.2'de karsiligi.
- **PoC:** TODO. **Test:** TODO. **Nerede:** `labs/versions/8.2.34/`.

### 3.5 — 8.1.32 (EOL) · ⬜
- **Kaynak:** guard yok → acik; `php:8.1-apache` (ARM64).
- **Offset:** TODO. **Leak:** TODO. **PoC:** TODO. **Test:** TODO.
- **Nerede:** `labs/versions/8.1.32/`.

### 3.6 — 8.0.30 (EOL) · 🔴 BLOCKED — **guncel odak**
- **Bulgu:** OOM-bailout **RACY** — worker bazen segfault (`exit signal 11`),
  bazen 200 doner; **ama 200 olanlarda bile `Set-Cookie` = normal 32-hex**
  (heap pointer degil) → 8.4.26 leak kanali 8.0.30'da **manifest olmaz**.
- **Kaynak:** `labs/calibration-74/php-8.0.30-session.c` (3219 satir);
  `php_session_rfc1867_update` (satir ~2966) guard **yok**.
- **Offset:** `zif_system=0x3495d0`, `zval_ptr_dtor=0x4319a0`
  (`labs/calib/libphp80.so`, non-stripped) ✓ · `htdata` TODO.
- **Leak:** 🔴 **8.0.30-ozel kanal bulunmali** (RE: OOM-bailout hangi kanaldan
  siziriyor — header/body/error/OOB-read?).
- **PoC:** TODO — yeni leak kanalina gore yeniden yaz.
- **Test:** TODO. **Nerede:** `labs/versions/8.0.30/`.

### 3.7 — 7.4.33 (EOL) · 🟡 KISMEN
- **Hedef:** `test.example.com` (7.4.33) — **ama** multipart→403, buyuk body→413
  (webserver mitigation) → lab'de dogrulanmali.
- **Kaynak:** `labs/calibration-74/CALIBRATION_74.md` (spec: vulnerable path
  7.4.33'te mevcut `session.c:3169`; type flag + `pDestructor`/`handler` offset
  8.4 ile **ayni**; `execute_data` 7.4=72B, arg1 ex+0x50).
- **Offset:** TODO — `zif/dtor/htdata` 7.4.33 libphp'ten olculmeli.
- **Leak:** TODO — 7.4'te kanal. **PoC:** `poc_74.py` var (dogrulanmadi).
- **Test:** TODO. **Nerede:** `labs/calibration-74/` + `labs/versions/7.4.33/`.

### 3.8 — 7.3.33 (EOL) · ⬜
- **Kaynak:** guard yok; `php:7.3-apache` (x86/qemu).
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/7.3.33/`.

### 3.9 — 7.2.34 (EOL) · ⬜
- **Kaynak:** guard yok; `php:7.2-apache` (x86/qemu).
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/7.2.34/`.

### 3.10 — 7.1.33 (EOL) · ⬜
- **Kaynak:** guard yok; `php:7.1-apache` (x86/qemu).
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/7.1.33/`.

### 3.11 — 7.0.33 (EOL) · ⬜
- **Kaynak:** guard yok; `php:7.0-apache` (x86/qemu).
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/7.0.33/`.

### 3.12 — 5.6.40 (EOL) · ⬜
- **Kaynak:** guard yok; `php:5.6-apache` (x86/qemu). **Not:** 5.x'te Zend
  engine + session API farkli (zval/HashTable layout) → PoC uyarlamasi daha derin.
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/5.6.40/`.

### 3.13 — 5.5.38 (EOL) · ⬜
- **Kaynak:** **Docker imaji yok → kaynak build** (`php-5.5.38.tar`).
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/5.5.38/`.

### 3.14 — 5.4.45 (EOL) · ⬜
- **Kaynak:** **Docker imaji yok → kaynak build** (`php-5.4.45.tar`).
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/5.4.45/`.

---

## 4. UI tasarimi (arastirma olarak yayinlanacak)

**Amac:** Surum + hedef + komut gir → kalibre PoC'i calistir → her surumun
`id` ciktisini ve durumunu goster. Statik, self-contained HTML (Artifact).

**Bilesenler:**
1. **Surum secici** — 14 surum (8.4.26 baz + 13). Her surum: durum rozeti
   (✅/🟡/🔴/⬜) + offset'ler + leak kanali.
2. **Hedef girisi** — URL (`http://.../p.php`) + (opsiyonel) profile
   (bookworm / lab / sury).
3. **Komut girisi** — default `id>/out/p1` (≤14B), `whoami` onerisi; **zararsiz
   komut kilidi** (webshell/reverse-shell reddet).
4. **Calistir** — secilen surumun PoC'ini calistir; canli log akisi.
5. **Sonuc paneli** — `id` ciktisi, `out/p1` icerigi, site sonrasi sagligi,
   kullanilan offset'ler.
6. **Arastirma gorunumu** — surum matrisi tablosu (bu PLAN.MD §5), metodoloji,
   bulgular; "kaynak dosyalar" baglantilari (`labs/versions/<surum>/`).

**Teknik:** Statik HTML + vanilla JS (fetch ile hedefe POST). Self-contained
(inline CSS/JS). Her surumun PoC ciktisi `labs/versions/<surum>/out/`'dan okunur.

**Nerede:** `labs/ui/index.html` (Artifact olarak yayinlanir).

---

## 5. Arastirma yayini (cikti formati)

Her surum icin **tek satir kayit** (UI + rapor ortak):

| Surum | Durum | `id` ciktisi | Offset (zif/dtor/htdata) | Leak kanali | PoC dosyasi | Kanit dosyasi |
|---|---|---|---|---|---|---|
| 8.4.26 | ✅ | `uid=33(www-data) gid=33(www-data)` | `0x43A870 / 0x613C50 / 0x6E0D8` | `Set-Cookie` chunk-base | `labs/eness/poc_109618.py` | `labs/eness/out/p1` |
| 8.5.11 | ⬜ | — | — | — | — | — |
| 8.3.35 | ⬜ | — | — | — | — | — |
| 8.2.34 | 🟡 | — | `? / 0x2fcd30 / ?` | — | — | — |
| 8.1.32 | ⬜ | — | — | — | — | — |
| 8.0.30 | 🔴 | — | `0x3495d0 / 0x4319a0 / ?` | **bulunmali** | — | — |
| 7.4.33 | 🟡 | — | `? / ? / ?` | — | `poc_74.py` | — |
| 7.3.33 | ⬜ | — | — | — | — | — |
| 7.2.34 | ⬜ | — | — | — | — | — |
| 7.1.33 | ⬜ | — | — | — | — | — |
| 7.0.33 | ⬜ | — | — | — | — | — |
| 5.6.40 | ⬜ | — | — | — | — | — |
| 5.5.38 | ⬜ | — | — | — | — | — |
| 5.4.45 | ⬜ | — | — | — | — | — |

**Yayin icerigi:** TL;DR · zaman cizelgesi · mekanizma (session.upload_progress
heap UAF) · ASLR bypass (2 leak) · surum matrisi + `id` kanitlari · metodoloji
(7 adim) · mitigasyon (yama + proxy drop + `upload_progress.enabled=0`) ·
kaynaklar. (ARASTIRMA.md zaten buyuk bolumunu kapsar — bu tablo + UI eklenecek.)

---

## 6. Calisma sirasi ve bagimliliklar

**Faz 0 — Baz dogrulama:** 8.4.26 lab'i hâlâ `id` uretiyor mu? (regresyon kontrolu)

**Faz 1 — Active branch (en degerli, en yakin 8.4'e):**
8.5.11 → 8.3.35 → 8.2.34. 8.4.26'ya yapisal olarak en yakinlar → PoC uyarlamasi
en kisa. 8.2.34 = `lab.example.com` hedefi (vektorler acik) → **en yuksek gercek deger**.

**Faz 2 — Yakin EOL (guncel odak):** 8.1.32 → **8.0.30 (derin re-engineering)**
→ 7.4.33. 8.0.30 leak kanali bulunursa geriye dogru genelleme kolaylasir.

**Faz 3 — Eski EOL:** 7.3.33 → 7.2.34 → 7.1.33 → 7.0.33 (qemu, yavas).

**Faz 4 — Legacy:** 5.6.40 → 5.5.38 → 5.4.45 (son ikisi kaynak build).

**Faz 5 — UI + yayin:** `labs/ui/index.html` (14 surum + `id` tablosu + metodoloji),
Artifact olarak yayinla.

> **Bagimlilik:** Her faz, bir oncekinin "leak kanali + heap-shape" bulgusunu
> kullanir. 8.0.30 (Faz 2) basarili olursa 7.x (Faz 3) uyarlamasi hizlanir;
> basarisizsa Faz 3 bagimsiz RE ile ilerler.

---

## 7. Durum takip tablosu (canli tutulacak)

| Surum | [1] Kaynak | [3] Offset | [4] Leak | [5] PoC | [6] Test | [7] Kayit |
|---|---|---|---|---|---|---|
| 8.4.26 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 8.5.11 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 8.3.35 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 8.2.34 | ✅ | 🟡 | ⬜ | ⬜ | ⬜ | 🟡 |
| 8.1.32 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 8.0.30 | ✅ | 🟡 | 🔴 | ⬜ | 🔴 | 🟡 |
| 7.4.33 | ✅ | ⬜ | ⬜ | 🟡 | ⬜ | 🟡 |
| 7.3.33 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 7.2.34 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 7.1.33 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 7.0.33 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 5.6.40 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 5.5.38 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |
| 5.4.45 | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ |

---

## 8. Dosya yapisi (hedef)

```
php2shell/
├── PLAN.MD                  ← BU DOSYA (plan + canli durum)
├── ARASTIRMA.md             ← ana rapor (CVE, mekanizma, mitigasyon, test siteleri)
├── PUSULA.md               ← proje pusulasi (neyin nerede oldugu)
└── labs/
    ├── eness/              ← 8.4.26 baz PoC (poc_109618.py) + lab/ (elf_syms.py)
    ├── calibration-74/     ← 7.4 spec + poc_74.py + 8.0.30/8.2.35 session.c referans
    ├── calib/              ← 8.0.30 libphp80.so + p.php
    ├── nine-bie/           ← 9bie stock-ini PoC + remote_probe.py
    ├── versions/           ← YENI: surum-bazli kalibrasyon (her surum bir klasor)
    │   ├── 8.2.34/  {SPEC.md, offsets.env, poc.py, out/p1, out/test.log}
    │   ├── 8.0.30/  {SPEC.md, offsets.env, poc.py, out/}
    │   ├── 7.4.33/  {SPEC.md, offsets.env, poc.py, out/}
    │   └── ... (14 surum)
    ├── ui/                 ← YENI: index.html (surum secici + id tablosu + yayin)
    └── research/           ← YENI: yayin dokumani (PLAN.MD §5 tablosu + metodoloji)
```

---

## 9. Ilk somut adimlar (plan onaylandiysa)

1. **Faz 0:** 8.4.26 lab'i `id>/out/p1` ile regresyon kontrolu (hâlâ calisiyor mu?).
2. **Faz 1a:** `8.2.34` — calisan lab kur (ARM64, tek worker, zorunlu ini) →
   `zif_system` + `htdata` olc → 8.4.26 PoC'unu uyarla → `id` test → `lab.example.com`
   canli dogrulama (zararsiz `id>/out/p1`).
3. **Faz 2:** `8.0.30` derin re-engineering — OOM-bailout'un **leak kanali** RE
   (`objdump` + source-walk), yeni kanal bulunur bulunmaz PoC'i yeniden yaz + test.
4. Her adim sonunda §7 tablosu + ilgili `SPEC.md` guncelle; `PUSULA.md`'yi tazele.
```