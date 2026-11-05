# P2S — Diğer PoC'ler için Docker Hedefleri (Kurulum Dokümanı)

> **Amaç:** php2shell (18120, kullanıcıda) DIŞINDAKİ native PoC'ler için
> **gerçek kanıt** alınacak Docker hedeflerini tek dokümanda toplama.
> Hedef ortam: **Windows kutusu 192.168.8.123** (Docker Desktop, WSL2, **native amd64**).
> Port aralığı: **18201–18220** (18101–18114 PHP + 18120 OOM ile çakışmaz).
> Sunucudaki agent bu dokümanı takip edip her container'ı ayağa kaldırıp LAN'a açacak.

## Neden Windows kutusu (Colima değil)?

Colima (macOS/aarch64 VM) **AJP ve h2c gibi binary HTTP/2 transportlarında 0-byte/timeout**
veriyor (Ghostcat'te doğrulandı). Windows Docker Desktop = **native amd64 + sağlam port mapping**
→ aynı 18101–18114 PHP hedeflerinin çalıştığı gibi güvenilir.

## Hedef Özeti (PoC → Image → Port → Kanıt)

| # | Hedef | CVE (poc modülü) | Docker image | Port(s) | Gerçek kanıt |
|---|-------|------------------|--------------|---------|--------------|
| 1 | **Ghostcat / Tomcat AJP** | CVE-2020-1938 (java_web) | `tomcat:9.0.30` | HTTP **18201**, AJP **18202** | `/WEB-INF/web.xml` + `/etc/passwd` byte'ları |
| 2 | **nginx h2c (Rapid Reset)** | CVE-2024-7347 (h2c) | `nginx:1.22` | **18203** | RST_STREAM / GOAWAY |
| 3 | **Apache mod_http2** | CVE-2021-44790, CVE-2017-5638, CVE-2024-38477 (h2c) | `httpd:2.4` + mod_http2 | **18205** | RST / GOAWAY / crash |
| 4 | **MySQL 5.7** | CVE-2019-14853, CVE-2015-4824 (mysql_proto) | `mysql:5.7` | **18210** | OK paket (auth bypass) / crash-RST |
| 5 | **MySQL 8.0** | CVE-2023-24714, CVE-2019-14367 (mysql_proto) | `mysql:8.0` | **18211** | OK paket (auth bypass) / crash-RST |
| 6 | **PHP CGI/FPM (RCE)** | CVE-2017-13300, CVE-2014-8142, CVE-2019-8648 (php_http) | `nginx:1.20` + `php:7.4-fpm` | **18215** | `uid=` (id) |
| 7 | *(lokal — Docker gerekmez)* | CVE-2016-1238, CVE-2020-10543, CVE-2021-29923, CVE-2022-36319, CVE-2013-1667 (perl_local) | `perl:5.30` *(ops.)* | — | scanner'ın native mekanizma simülasyonu |

> **Öncelik:** #1 Ghostcat + #6 PHP CGI (gerçek dosya/`uid=` kanıtı, en güvenilir) →
> sonra #4/#5 MySQL, #2/#3 h2c (DoS/UAF = anormal yanıt kanıtı). #7 perl lokal.

---

## 1) Ghostcat — Tomcat 9.0.30 (CVE-2020-1938)  ⭐ ÖNCELİK

Tomcat 9.0.30 = patch **öncesi** son sürüm (9.0.31 secretRequired default yaptı).
AJP connector'ı 8009'da açık + secret yok → `javax.servlet.include.*` ile keyfi dosya okunur.

```powershell
docker pull --platform linux/amd64 tomcat:9.0.30
docker rm -f p2s-ghostcat 2>$null | Out-Null
docker run -d --name p2s-ghostcat --restart unless-stopped `
  -p 18201:8080 -p 18202:8009 `
  tomcat:9.0.30
```

**AJP connector ekle** (secretRequired=false / pre-patch davranış):
```powershell
$ajp = '<Connector port="8009" protocol="AJP/1.3" redirectPort="8443" secretRequired="false"/>'
docker exec p2s-ghostcat sh -c "grep -q 'port=\"8009\"' /usr/local/tomcat/conf/server.xml || sed -i '/<\/Server>/i\\  $ajp' /usr/local/tomcat/conf/server.xml"
docker restart p2s-ghostcat
```

**Doğrula:**
```powershell
curl -s --max-time 5 http://127.0.0.1:18201/ | Select-String "Tomcat"      # HTTP 200
# AJP portu açık mı:
Test-NetConnection 127.0.0.1 -Port 18202 -InformationLevel Quiet            # True
```
**Kanıt (scanner):** `CVE-2020-1938` → host `192.168.8.123:18202`, file `/WEB-INF/web.xml`
ve `../../../../../etc/passwd` → gerçek byte'lar.

---

## 2) nginx h2c — Rapid Reset (CVE-2024-7347)

nginx `http2` (cleartext h2c) açık → HEADERS + RST_STREAM flood → RST/GOAWAY.

```powershell
docker pull --platform linux/amd64 nginx:1.22
docker rm -f p2s-h2c 2>$null | Out-Null
docker run -d --name p2s-h2c --restart unless-stopped -p 18203:80 nginx:1.22
```
**http2 config** (h2c — TLS'siz):
```powershell
$conf = @'
server {
    listen 80 http2;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;
}
'@
Set-Content -Encoding UTF8 "$env:TEMP\p2s_h2c.conf" -Value $conf
docker cp "$env:TEMP\p2s_h2c.conf" p2s-h2c:/etc/nginx/conf.d/default.conf
docker exec p2s-h2c nginx -s reload
```
**Doğrula:**
```powershell
curl -s --http2-prior-knowledge -o /dev/null -w "h2c -> HTTP %{http_code} (http_version=%{http_version})\n" http://127.0.0.1:18203/
```
**Kanıt (scanner):** `CVE-2024-7347` → host `192.168.8.123:18203`, streams 500 → RST/GOAWAY.

---

## 3) Apache mod_http2 (CVE-2021-44790 / 2017-5638 / 2024-38477)

`httpd:2.4` + **mod_http2** (custom modül) + mod_proxy. mod_http2 default image'da yok →
kurulum gerekli. (En çok uğraş isteyen hedef; #1/#2/#4/#5 kanıtı gelene kadar bekletilebilir.)

```powershell
docker pull --platform linux/amd64 httpd:2.4
docker rm -f p2s-apacheh2 2>$null | Out-Null
docker run -d --name p2s-apacheh2 --restart unless-stopped -p 18205:80 httpd:2.4
# mod_http2 + mod_proxy kur (Debian tabanlı image):
docker exec p2s-apacheh2 sh -c "apt-get update && apt-get install -y libapache2-mod-http2 || a2enmod http2"
docker exec p2s-apacheh2 sh -c "a2enmod http2 proxy"
# http2 (h2c) dinle:
docker exec p2s-apacheh2 sh -c "echo 'Protocols h2 http/1.1' >> /etc/apache2/conf-enabled/other-vhosts-incl.conf 2>/dev/null || echo 'Protocols h2 http/1.1' > /etc/apache2/conf-available/h2c.conf && a2enconf h2c"
docker restart p2s-apacheh2
```
**Doğrula:** `curl -s --http2-prior-knowledge -o /dev/null -w "%{http_version}\n" http://127.0.0.1:18205/`
**Kanıt (scanner):** `CVE-2021-44790` / `CVE-2017-5638` / `CVE-2024-38477` → host `192.168.8.123:18205`.

---

## 4) + 5) MySQL 5.7 & 8.0 (mysql_proto)

Native MySQL protokol (scanner socket açar, mysql client yok).
- **5.7** → CVE-2019-14853 (stack overflow), CVE-2015-4824 (auth bypass)
- **8.0** → CVE-2023-24714, CVE-2019-14367 (auth bypass)

```powershell
docker pull --platform linux/amd64 mysql:5.7
docker pull --platform linux/amd64 mysql:8.0

docker rm -f p2s-mysql57 2>$null | Out-Null
docker run -d --name p2s-mysql57 --restart unless-stopped `
  -e MYSQL_ROOT_PASSWORD=p2s_test_123 -e MYSQL_DATABASE=p2s `
  -p 18210:3306 mysql:5.7

docker rm -f p2s-mysql80 2>$null | Out-Null
docker run -d --name p2s-mysql80 --restart unless-stopped `
  -e MYSQL_ROOT_PASSWORD=p2s_test_123 -e MYSQL_DATABASE=p2s `
  -p 18211:3306 mysql:8.0
```
**Doğrula (TCP handshake — scanner'ın gördüğü):**
```powershell
Test-NetConnection 127.0.0.1 -Port 18210 -InformationLevel Quiet   # 5.7
Test-NetConnection 127.0.0.1 -Port 18211 -InformationLevel Quiet   # 8.0
```
**Kanıt (scanner):**
- `CVE-2015-4824` → host `192.168.8.123:18210`, user `` (boş) → OK paket.
- `CVE-2023-24714` → host `192.168.8.123:18211`, user `` (boş) → OK paket.
- `CVE-2019-14853` → host `192.168.8.123:18210`, size_kb 512 → crash/RST sinyali.

---

## 6) PHP CGI / FPM RCE (php_http)  ⭐ ÖNCELİK

nginx + php-fpm, **vulnerable `fastcgi_split_path_info`** config →
CVE-2017-13300 (`/index.php/{cmd}`), CVE-2014-8142 (`? -c ;{cmd}`),
CVE-2019-8648 (`/cgi-bin/php? -c ;{cmd}`). Kanıt = gerçek `uid=`.

```powershell
docker pull --platform linux/amd64 nginx:1.20
docker pull --platform linux/amd64 php:7.4-fpm
docker network create p2s-phpnet 2>$null

# php-fpm (aynı network'te "php" hostnames)
docker rm -f p2s-phpfpm 2>$null | Out-Null
docker run -d --name p2s-phpfpm --restart unless-stopped `
  --network p2s-phpnet --network-alias php php:7.4-fpm

# nginx (vulnerable config)
docker rm -f p2s-phpcgi 2>$null | Out-Null
docker run -d --name p2s-phpcgi --restart unless-stopped `
  --network p2s-phpnet -p 18215:80 nginx:1.20
```
**Vulnerable nginx config** (fastcgi_split_path_info + SCRIPT_FILENAME manipülasyonu):
```powershell
$conf = @'
server {
    listen 80;
    server_name _;
    root /usr/share/nginx/html;
    index index.php;
    location ~ \.php(/|$) {
        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        fastcgi_pass php:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
    }
    location /cgi-bin/ {
        fastcgi_pass php:9000;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /usr/local/bin/php-cgi;
    }
}
'@
Set-Content -Encoding UTF8 "$env:TEMP\p2s_phpcgi.conf" -Value $conf
docker cp "$env:TEMP\p2s_phpcgi.conf" p2s-phpcgi:/etc/nginx/conf.d/default.conf
# index.php hedefi:
$php = '<?php echo "P2S-PHP-OK\n"; ?>'
Set-Content -Encoding ASCII "$env:TEMP\p2s_index.php" -Value $php
docker cp "$env:TEMP\p2s_index.php" p2s-phpcgi:/usr/share/nginx/html/index.php
docker exec p2s-phpcgi nginx -t
docker exec p2s-phpcgi nginx -s reload
```
**Doğrula:**
```powershell
curl -s --max-time 5 http://127.0.0.1:18215/index.php          # "P2S-PHP-OK"
```
**Kanıt (scanner):**
- `CVE-2017-13300` → host `192.168.8.123:18215`, base `/index.php`, cmd `id` → `uid=`.
- `CVE-2014-8142` → host `192.168.8.123:18215`, base `/index.php`, cmd `id` → `uid=`.
- `CVE-2019-8648` → host `192.168.8.123:18215`, base `/cgi-bin/php`, cmd `id` → `uid=`.

---

## 7) Perl (perl_local) — Docker GEREKMEZ

CVE-2016-1238 / CVE-2020-10543 / CVE-2021-29923 / CVE-2022-36319 / CVE-2013-1667 =
**lokal perl-runtime** mekanizmaları (uzak socket vektörü yok). Scanner bunları native olarak
(Python, dış perl binary'si yok) simüle edip raporluyor. İsteğe bağlı gerçek perl:
```powershell
docker run --rm --platform linux/amd64 perl:5.30 perl -v
```

---

## Tek Bat Dosyası — Hepsini Kur (kopyala-yap)

Aşağı `p2s_other_setup.bat` dosyası olarak kaydedip Windows'ta çalıştır:
`p2s_other_setup.bat` (ayrı dosya olarak bu projede hazır).

## Doğrulama Checklist (kurulumdan sonra)

- [ ] `docker ps --filter "name=p2s"` → 7 container (ghostcat, h2c, apacheh2, mysql57, mysql80, phpfpm, phpcgi)
- [ ] `Test-NetConnection 192.168.8.123 -Port 18202` (AJP) → True
- [ ] `curl http://192.168.8.123:18201/` → Tomcat 200
- [ ] `curl --http2-prior-knowledge http://192.168.8.123:18203/` → http_version=2
- [ ] `Test-NetConnection 192.168.8.123 -Port 18210/18211` (MySQL) → True
- [ ] `curl http://192.168.8.123:18215/index.php` → "P2S-PHP-OK"
- [ ] Windows Firewall 18201–18220 LAN'a açık:
      `New-NetFirewallRule -DisplayName "p2s-other" -Direction Inbound -Port 18201-18220 -Protocol TCP -Action Allow`

## Temizlik

```powershell
docker ps -a --filter "name=p2s" --format "{{.Names}}" | Where-Object { $_ -match "ghostcat|h2c|apacheh2|mysql|phpfpm|phpcgi" } | ForEach-Object { docker rm -f $_ 2>$null }
```
