# PLAN.MD — php2shell 5.4 → 8.5 Tam Sürüm Kalibrasyonu

**Amaç:** CVE-2026-109618 / 109619 (php2shell) için **5.4 → 8.5** aralığındaki her
sürümü **ayrıntılı analiz et → tam kalibre et → test et → uyarla**, her biri için
**`id` çıktısını** ve **"ne yapıldı, nerede"** kaydını tut; sonunda bir **UI** ile
bütününü **araştırma olarak** sun.

**Başarı ölçüsü (her sürüm için):** `id>/out/p1` çalıştırıldığında `out/p1`
dosyasında `uid=33(www-data) gid=33(www-data)` (ya da o SAPI'nin web kullanıcısı)
görülmesi. Bu, o sürümün **doğrulandı** sayıldığı anlamına gelir.

**Altın referans:** **8.4.26** (lab'de doğrulanmış). Diğer her sürüm bu bazla
karşılaştırılır; fark = o sürümün kendine özgü leak vektörü + offset + heap-shape'i.

> ⚠️ **Temel gerçek (planın omurgası):** Leak vektörü **sürüm-bağımlıdır**,
> "aynı PoC + farklı offset" değildir. 8.4.26'da `Set-Cookie: PHPSESSID` üzerinden
> temiz chunk-base leak'i varken, **8.0.30'da aynı kanal manifest olmaz** (worker
> ya segfault'lar ya da normal 32-hex session ID döner). Yani her sürüm için
> **o sürümün OOM-bailout'unun nerede ve nasıl corrupt olduğunu RE ile bulmak**
> gerekir. Bu yüzden plan "offset takası" değil, **sürüm-bazlı derin re-engineering**.

---

## 0. Kapsam ve varsayımlar

- **Sürüm seçimi:** "5.4 → 8.5 arası her sürüm" = **her minor serisinin
  son/etkilenen temsilci sürümü** (14 sürüm). İsteğe bağlı olarak herhangi bir
  patch sürümüne genişletilebilir (ör. 8.0.30 yerine 8.0.28).
- **Yetki:** Tüm testler kullanıcının **yetkili** olduğu kendi test
  sitelerinde (`fra.org.in` 7.4.33, `yilpart.com/izin.php` 8.2.34) + **Docker
  lab** (kendi makinemizde). Komut **yalnızca zararsız** (`id>/out/p1`,
  `whoami`). Webshell / reverse-shell / veri okuma **YOK**.
- **SAPI:** **mod_php + Apache prefork**, **tek worker** (PoC'ün varsayılan
  profili; Chain D — sıfır bağımlılıklı pre-auth RCE).
- **Platform:** macOS ARM64; eski (x86) imajlar qemu ile yavaş çalışır.
  5.4 / 5.5'in **Docker imajı yok** → kaynak build gerekir.

---

## 1. Sürüm matrisi (14 temsilci sürüm)

| # | Sürüm | Branch | Durum | Docker imajı | Lab imajı (ARM64?) | Öncelik | Mevcut durum |
|---|---|---|---|---|---|---|---|
| 1 | **8.4.26** | 8.4 | Active `<8.4.27` | `php:8.4-apache` | ARM64 ✓ | **P0 (baz)** | ✅ **DOĞRULANDI** |
| 2 | **8.5.11** | 8.5 | Active `<8.5.12` | `php:8.5-apache` | ARM64 ✓ | **P1** | ⬜ offset+leak gerekli |
| 3 | **8.3.35** | 8.3 | Active `<8.3.36` | `php:8.3-apache` | ARM64 ✓ | **P1** | ⬜ offset+leak gerekli |
| 4 | **8.2.34** | 8.2 | Security-only `<8.2.35` | `php:8.2-apache` | ARM64 ✓ | **P1** | 🟡 `zval_ptr_dtor=0x2fcd30`; zif/htdata yok |
| 5 | **8.1.32** | 8.1 | **EOL** | `php:8.1-apache` | ARM64 ✓ | **P2** | ⬜ |
| 6 | **8.0.30** | 8.0 | **EOL** | `php:8.0-apache` | ARM64 ✓ (qemu) | **P2 (odak)** | 🔴 **BLOCKED** — leak manifest olmuyor |
| 7 | **7.4.33** | 7.4 | **EOL** | `php:7.4-apache` | x86/qemu | **P2** | 🟡 `poc_74.py` var, doğrulanmadı; offset ölçülmeli |
| 8 | **7.3.33** | 7.3 | **EOL** | `php:7.3-apache` | x86/qemu | **P3** | ⬜ |
| 9 | **7.2.34** | 7.2 | **EOL** | `php:7.2-apache` | x86/qemu | **P3** | ⬜ |
| 10 | **7.1.33** | 7.1 | **EOL** | `php:7.1-apache` | x86/qemu | **P3** | ⬜ |
| 11 | **7.0.33** | 7.0 | **EOL** | `php:7.0-apache` | x86/qemu | **P4** | ⬜ |
| 12 | **5.6.40** | 5.6 | **EOL** | `php:5.6-apache` | x86/qemu | **P4** | ⬜ |
| 13 | **5.5.38** | 5.5 | **EOL** | ❌ imaj yok | **kaynak build** | **P5** | ⬜ |
| 14 | **5.4.45** | 5.4 | **EOL** | ❌ imaj yok | **kaynak build** | **P5** | ⬜ |

> **Not:** "EOL" = resmi yama yok → source backport / izolasyon. Bu sürümler en
> kırılgan (yamasız) ama en zor (non-stripped libphp + heap-shape için **çalışan**
> örnek gerekir). 5.4/5.5 Docker imajı yok → kaynak derlenmeli (ARM64'de yavaş).

---

## 2. Her sürüm için standart iş akışı (7 adım)

Her sürüm için **aynı iskelet** uygulanır; sürüme özgü olan "Leak vektörü" ve
"heap-shape" adımlarıdır. Adımlar sıralıdır; her adımda çıktı bir sonraki
adımın girdisidir.

```
[1] KAYNAK ANALİZİ   → o sürümün session.c + Zend OOM path'i, 8.2.35 (yamalı) ile diff
[2] LAB KURULUMU     → Docker: o sürüm mod_php prefork, tek worker, zorunlu ini
[3] OFFSET KALİB.    → non-stripped libphp'ten: zif_system / zval_ptr_dtor / htdata
[4] LEAK VEKTÖRÜ     → RE: o sürümde OOM-bailout NEREDE corrupt, leak hangi kanaldan
[5] PoC UYARLAMASI   → 8.4.26 bazını o sürümün leak+offset+heap'e göre değiştir
[6] TEST             → id>/out/p1  →  out/p1 = uid=...(www-data)  ✓
[7] KAYIT            → SPEC.md + offsets.env + out/  (PLAN.MD tablosu güncelle)
```

### [1] Kaynak analizi (sürüm-bazlı)
- `ext/session/session.c` → `php_session_rfc1867_callback` / `_update` / `_cleanup`.
- `Zend/zend_execute.c` + `main/main.c` → OOM-bailout / `longjmp` path'i.
- **Diff hedefi:** 8.2.35 (yaması çıktı) `in_rfc1867_update` re-entrancy guard'ı +
  `php_session_(un)?serialize_init` → `set_incomplete_classes_only`. Bu guard
  **olmayan** her sürüm (5.4→8.2.34, 8.3.35, 8.4.26, 8.5.11) açık; guard'ın
  **nasıl** corrupt ettiğini sürüm sürüm RE ile bul.
- Çıktı: o sürümün **vulnerable call-site'ı** (dosya:satır) + corrupt olan
  global (`PS(id)`, `PS(mod_data)`, `EG(...)`, `BG(...)`).

### [2] Lab kurulumu (Docker)
- `php:<sürüm>-apache`, **prefork**, `StartServers=1 / MinSpareServers=1 /
  MaxClients=1` (tek worker), `/out` volume = webroot'a yazılabilir.
- **Zorunlu ini** (PoC profili): `memory_limit=8M`, `max_input_vars=1000`,
  `display_errors=1`, `session.upload_progress.enabled=1`,
  `post_max_size=64M`, `upload_max_filesize=32M`.
- `p.php`: `<?php ini_set('display_errors','1'); echo "ok\n";`
- **macOS ARM64 notu:** host→container port-forward kırık olabilir →
  `docker network p2s` + arm64 `p2s-cli` container'ı, hedefe **isimle** eriş.
  Eski x86 imajlar qemu ile yavaş; 5.4/5.5 kaynak build.

### [3] Offset kalibrasyonu
- Non-stripped libphp (`labs/calib/libphp<xx>.so` ya da kaynak build çıktısı).
- `zif_system` (fake `pDestructor` hedefi), `zval_ptr_dtor` (stage-2 self-check),
  `htdata` (167B canlı `zend_string` / `HashTable` layout — **heap'e bağlı, çalışan
  örnek gerekir**; statik çıkmaz).
- Araç: `labs/eness/lab/elf_syms.py` / `labs/calibration-74/scan_dynsym.py`.
- **Self-check:** eness stage-2 `p & 0xFFF == dtor_offset & 0xFFF` → yanlış offset
  stage-2'de düşer (hedefle eşleşme doğrulanır).

### [4] Leak vektörü (sürüm-bazlı RE) — **planın kritik adımı**
- Soru: bu sürümde OOM-bailout **hangi kanaldan** sızırıyor?
  - 8.4.26: `Set-Cookie: PHPSESSID` = 2MB-aligned chunk base (temiz leak).
  - 8.0.30: leak YOK → worker segfault ya da normal hex ID. **Farklı kanal bulunmalı.**
- RE araçları: `objdump -d` (RFC1867 + OOM path), `scan_dynsym.py`, gerekirse
  `gdb`/core (lab'de) veya source-walk.
- Çıktı: o sürümün **leak kanalı** (header/body/error-message/OOB-read) +
  **heap-shape** (hangi field, hangi boyut, hangi sıra).

### [5] PoC uyarlaması
- 8.4.26 baz PoC'ü (`poc_109618.py`) **kopyala**, o sürüm için:
  offset'leri `[3]`'ten, leak kanalı + heap-shape'i `[4]`'ten değiştir.
- 14-byte komut limiti: `id>/out/p1` (10B) uyumlu ✓.
- Her sürümün PoC'i kendi klasöründe (`labs/versions/<sürüm>/poc.py`).

### [6] Test (zararsız kanıt)
- `python3 poc.py -u http://<lab>/p.php -c 'id>/out/p1' --proof-file out/p1`
- Doğrulama: `cat out/p1` → `uid=33(www-data) ...` **ve** site sonrası 200 OK.
- **Negatif kontrol:** crash/502 + `out/p1` yok = başarısız (retry gerek).

### [7] Kayıt
- `labs/versions/<sürüm>/SPEC.md` (analiz + offset + leak + test log).
- `labs/versions/<sürüm>/offsets.env` (kalibre offset'ler).
- `labs/versions/<sürüm>/out/p1` + `out/test.log`.
- Bu PLAN.MD'nin §5 tablosu + §7 durum tablosu güncelle.

---

## 3. Sürüm-bazlı detay (şu anki bilinenler + yapılacaklar)

> Her bölüm bir **şablon**dur: bilinenler dolduruldu, bilinmeyenler `TODO`.
> Durum: ✅ DOĞRULANDI · 🟡 KISMEN · 🔴 BLOCKED · ⬜ BAŞLANMADI

### 3.1 — 8.4.26 (ALTIN BAZ) · ✅ DOĞRULANDI
- **Kaynak:** eness PoC 4 aşama (stage0 rotate → stage1 chunk leak →
  stage2 libphp leak → stage3 fake `pDestructor=zif_system`).
- **Offset:** `zif_system=0x43A870`, `zval_ptr_dtor=0x613C50`,
  `htdata=0x6E0D8` (lab bookworm profile).
- **Leak:** `Set-Cookie: PHPSESSID` = 2MB-aligned chunk base (temiz).
- **Test:** `id>/out/p1` → `uid=33(www-data)` ✓.
- **Nerede:** `labs/eness/poc_109618.py`, `labs/eness/out/offsets.env`.

### 3.2 — 8.5.11 (Active) · ⬜
- **Kaynak:** 8.4.26 ile diff (guard yok mu? struct fark?); `php:8.5-apache`.
- **Offset:** TODO — `zif/dtor/htdata` 8.5.11 libphp'ten.
- **Leak:** TODO — 8.4.26 kanalının 8.5'te değişip değişmediği RE.
- **PoC:** TODO — 8.4.26 bazını 8.5'e uyarla.
- **Test:** TODO. **Nerede:** `labs/versions/8.5.11/`.

### 3.3 — 8.3.35 (Active) · ⬜
- **Kaynak:** 8.4.26 ile diff; `php:8.3-apache`.
- **Offset:** TODO. **Leak:** TODO. **PoC:** TODO. **Test:** TODO.
- **Nerede:** `labs/versions/8.3.35/`.

### 3.4 — 8.2.34 (Security-only) · 🟡 KISMEN
- **Hedef:** `yilpart.com/izin.php` (8.2.34, vektörler AÇIK — multipart 200 OK).
- **Kaynak:** 8.2.35 (yaması çıktı) `in_rfc1867_update` guard'ı 8.2.34'te **YOK**
  → açık. `labs/calibration-74/php-8.2.35/ext/session/session.c` (referans).
- **Offset:** `zval_ptr_dtor=0x2fcd30` (8.2.35 sury.org paketi) ✓ ·
  `zif_system` TODO (stripped → çalışan 8.2.34/8.2.35 gerekli) · `htdata` TODO.
- **Leak:** TODO — 8.4.26 kanalının 8.2'de karşılığı.
- **PoC:** TODO. **Test:** TODO. **Nerede:** `labs/versions/8.2.34/`.

### 3.5 — 8.1.32 (EOL) · ⬜
- **Kaynak:** guard yok → açık; `php:8.1-apache` (ARM64).
- **Offset:** TODO. **Leak:** TODO. **PoC:** TODO. **Test:** TODO.
- **Nerede:** `labs/versions/8.1.32/`.

### 3.6 — 8.0.30 (EOL) · 🔴 BLOCKED — **güncel odak**
- **Bulgu:** OOM-bailout **RACY** — worker bazen segfault (`exit signal 11`),
  bazen 200 döner; **ama 200 olanlarda bile `Set-Cookie` = normal 32-hex**
  (heap pointer değil) → 8.4.26 leak kanalı 8.0.30'da **manifest olmaz**.
- **Kaynak:** `labs/calibration-74/php-8.0.30-session.c` (3219 satır);
  `php_session_rfc1867_update` (satır ~2966) guard **yok**.
- **Offset:** `zif_system=0x3495d0`, `zval_ptr_dtor=0x4319a0`
  (`labs/calib/libphp80.so`, non-stripped) ✓ · `htdata` TODO.
- **Leak:** 🔴 **8.0.30-özel kanal bulunmalı** (RE: OOM-bailout hangi kanaldan
  sızırıyor — header/body/error/OOB-read?).
- **PoC:** TODO — yeni leak kanalına göre yeniden yaz.
- **Test:** TODO. **Nerede:** `labs/versions/8.0.30/`.

### 3.7 — 7.4.33 (EOL) · 🟡 KISMEN
- **Hedef:** `fra.org.in` (7.4.33) — **ama** multipart→403, büyük body→413
  (webserver mitigation) → lab'de doğrulanmalı.
- **Kaynak:** `labs/calibration-74/CALIBRATION_74.md` (spec: vulnerable path
  7.4.33'te mevcut `session.c:3169`; type flag + `pDestructor`/`handler` offset
  8.4 ile **aynı**; `execute_data` 7.4=72B, arg1 ex+0x50).
- **Offset:** TODO — `zif/dtor/htdata` 7.4.33 libphp'ten ölçülmeli.
- **Leak:** TODO — 7.4'te kanal. **PoC:** `poc_74.py` var (doğrulanmadı).
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
  engine + session API farklı (zval/HashTable layout) → PoC uyarlaması daha derin.
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/5.6.40/`.

### 3.13 — 5.5.38 (EOL) · ⬜
- **Kaynak:** **Docker imajı yok → kaynak build** (`php-5.5.38.tar`).
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/5.5.38/`.

### 3.14 — 5.4.45 (EOL) · ⬜
- **Kaynak:** **Docker imajı yok → kaynak build** (`php-5.4.45.tar`).
- **Offset/Leak/PoC/Test:** TODO. **Nerede:** `labs/versions/5.4.45/`.

---

## 4. UI tasarımı (araştırma olarak yayınlanacak)

**Amaç:** Sürüm + hedef + komut gir → kalibre PoC'i çalıştır → her sürümün
`id` çıktısını ve durumunu göster. Statik, self-contained HTML (Artifact).

**Bileşenler:**
1. **Sürüm seçici** — 14 sürüm (8.4.26 baz + 13). Her sürüm: durum rozeti
   (✅/🟡/🔴/⬜) + offset'ler + leak kanalı.
2. **Hedef girişi** — URL (`http://.../p.php`) + (opsiyonel) profile
   (bookworm / lab / sury).
3. **Komut girişi** — default `id>/out/p1` (≤14B), `whoami` önerisi; **zararsız
   komut kilidi** (webshell/reverse-shell reddet).
4. **Çalıştır** — seçilen sürümün PoC'ini çalıştır; canlı log akışı.
5. **Sonuç paneli** — `id` çıktısı, `out/p1` içeriği, site sonrası sağlığı,
   kullanılan offset'ler.
6. **Araştırma görünümü** — sürüm matrisi tablosu (bu PLAN.MD §5), metodoloji,
   bulgular; "kaynak dosyalar" bağlantıları (`labs/versions/<sürüm>/`).

**Teknik:** Statik HTML + vanilla JS (fetch ile hedefe POST). Self-contained
(inline CSS/JS). Her sürümün PoC çıktısı `labs/versions/<sürüm>/out/`'dan okunur.

**Nerede:** `labs/ui/index.html` (Artifact olarak yayınlanır).

---

## 5. Araştırma yayını (çıktı formatı)

Her sürüm için **tek satır kayıt** (UI + rapor ortak):

| Sürüm | Durum | `id` çıktısı | Offset (zif/dtor/htdata) | Leak kanalı | PoC dosyası | Kanıt dosyası |
|---|---|---|---|---|---|---|
| 8.4.26 | ✅ | `uid=33(www-data) gid=33(www-data)` | `0x43A870 / 0x613C50 / 0x6E0D8` | `Set-Cookie` chunk-base | `labs/eness/poc_109618.py` | `labs/eness/out/p1` |
| 8.5.11 | ⬜ | — | — | — | — | — |
| 8.3.35 | ⬜ | — | — | — | — | — |
| 8.2.34 | 🟡 | — | `? / 0x2fcd30 / ?` | — | — | — |
| 8.1.32 | ⬜ | — | — | — | — | — |
| 8.0.30 | 🔴 | — | `0x3495d0 / 0x4319a0 / ?` | **bulunmalı** | — | — |
| 7.4.33 | 🟡 | — | `? / ? / ?` | — | `poc_74.py` | — |
| 7.3.33 | ⬜ | — | — | — | — | — |
| 7.2.34 | ⬜ | — | — | — | — | — |
| 7.1.33 | ⬜ | — | — | — | — | — |
| 7.0.33 | ⬜ | — | — | — | — | — |
| 5.6.40 | ⬜ | — | — | — | — | — |
| 5.5.38 | ⬜ | — | — | — | — | — |
| 5.4.45 | ⬜ | — | — | — | — | — |

**Yayın içeriği:** TL;DR · zaman çizelgesi · mekanizma (session.upload_progress
heap UAF) · ASLR bypass (2 leak) · sürüm matrisi + `id` kanıtları · metodoloji
(7 adım) · mitigasyon (yama + proxy drop + `upload_progress.enabled=0`) ·
kaynaklar. (ARASTIRMA.md zaten büyük bölümünü kapsar — bu tablo + UI eklenecek.)

---

## 6. Çalışma sırası ve bağımlılıklar

**Faz 0 — Baz doğrulama:** 8.4.26 lab'i hâlâ `id` üretiyor mu? (regresyon kontrolü)

**Faz 1 — Active branch (en değerli, en yakın 8.4'e):**
8.5.11 → 8.3.35 → 8.2.34. 8.4.26'ya yapısal olarak en yakınlar → PoC uyarlaması
en kısa. 8.2.34 = `yilpart.com` hedefi (vektörler açık) → **en yüksek gerçek değer**.

**Faz 2 — Yakın EOL (güncel odak):** 8.1.32 → **8.0.30 (derin re-engineering)**
→ 7.4.33. 8.0.30 leak kanalı bulunursa geriye doğru genelleme kolaylaşır.

**Faz 3 — Eski EOL:** 7.3.33 → 7.2.34 → 7.1.33 → 7.0.33 (qemu, yavaş).

**Faz 4 — Legacy:** 5.6.40 → 5.5.38 → 5.4.45 (son ikisi kaynak build).

**Faz 5 — UI + yayın:** `labs/ui/index.html` (14 sürüm + `id` tablosu + metodoloji),
Artifact olarak yayınla.

> **Bağımlılık:** Her faz, bir öncekinin "leak kanalı + heap-shape" bulgusunu
> kullanır. 8.0.30 (Faz 2) başarılı olursa 7.x (Faz 3) uyarlaması hızlanır;
> başarısızsa Faz 3 bağımsız RE ile ilerler.

---

## 7. Durum takip tablosu (canlı tutulacak)

| Sürüm | [1] Kaynak | [3] Offset | [4] Leak | [5] PoC | [6] Test | [7] Kayıt |
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

## 8. Dosya yapısı (hedef)

```
php2shell/
├── PLAN.MD                  ← BU DOSYA (plan + canlı durum)
├── ARASTIRMA.md             ← ana rapor (CVE, mekanizma, mitigasyon, test siteleri)
├── PUSULA.md               ← proje pusulası (neyin nerede olduğu)
└── labs/
    ├── eness/              ← 8.4.26 baz PoC (poc_109618.py) + lab/ (elf_syms.py)
    ├── calibration-74/     ← 7.4 spec + poc_74.py + 8.0.30/8.2.35 session.c referans
    ├── calib/              ← 8.0.30 libphp80.so + p.php
    ├── nine-bie/           ← 9bie stock-ini PoC + remote_probe.py
    ├── versions/           ← YENİ: sürüm-bazlı kalibrasyon (her sürüm bir klasör)
    │   ├── 8.2.34/  {SPEC.md, offsets.env, poc.py, out/p1, out/test.log}
    │   ├── 8.0.30/  {SPEC.md, offsets.env, poc.py, out/}
    │   ├── 7.4.33/  {SPEC.md, offsets.env, poc.py, out/}
    │   └── ... (14 sürüm)
    ├── ui/                 ← YENİ: index.html (sürüm seçici + id tablosu + yayın)
    └── research/           ← YENİ: yayın dokümanı (PLAN.MD §5 tablosu + metodoloji)
```

---

## 9. İlk somut adımlar (plan onaylandıysa)

1. **Faz 0:** 8.4.26 lab'i `id>/out/p1` ile regresyon kontrolü (hâlâ çalışıyor mu?).
2. **Faz 1a:** `8.2.34` — çalışan lab kur (ARM64, tek worker, zorunlu ini) →
   `zif_system` + `htdata` ölç → 8.4.26 PoC'ünü uyarla → `id` test → `yilpart.com`
   canlı doğrulama (zararsız `id>/out/p1`).
3. **Faz 2:** `8.0.30` derin re-engineering — OOM-bailout'un **leak kanalı** RE
   (`objdump` + source-walk), yeni kanal bulunur bulunmaz PoC'i yeniden yaz + test.
4. Her adım sonunda §7 tablosu + ilgili `SPEC.md` güncelle; `PUSULA.md`'yi tazele.
```