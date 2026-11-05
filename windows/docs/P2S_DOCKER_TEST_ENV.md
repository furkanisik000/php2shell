# php2shell — Docker test ortamı (tüm PHP sürümleri, LAN'a açık)

> **Kapsam:** YALNIZCA PHP kurulumları + Docker erişimi + MCP araçları.
> Amaç: Windows (native amd64) Docker Desktop'ta **5.4 → 8.5 tüm PHP sürümlerini**
> container olarak kurup **LAN ağa açmak**. Başka konu yok (exploit/offset yok).
> Yetkili güvenlik araştırması — hedef: kullanıcıya ait Windows kutusu.

---

## 0) Ön gereksinim

| Gereksinim | Kontrol |
|---|---|
| Windows **x86_64** (ARM/Snapdragon DEĞİL) | `winver` → "64-bit" |
| Virtualization (BIOS) — WSL2 için | `systeminfo \| findstr /i hypervisor` → "Yes" |
| ~25 GB boş disk (14 image) | `df` / Bu Bilgisayar |
| Docker Desktop | `docker version` (WSL backend) |

---

## 1) Docker kurulumu (Windows)

```powershell
# WSL2 kur (restart ister)
wsl --install
wsl --set-default-version 2
wsl -l -v          # VERSION = 2

# Docker Desktop kur: https://www.docker.com/products/docker-desktop/
# (kurulumda "Use WSL 2 instead of Hyper-V" seçili olsun)

# Doğrula (PowerShell)
docker version
docker run --rm --platform linux/amd64 hello-world
```

> WSL2 = native amd64 kernel → amd64 container **qemu emülasyonundan geçmez**.
> Windows CMD'de `docker` PATH'te değilse → `wsl -d Ubuntu docker ...` ya da
> Docker Desktop'ın tam yoluyla çalıştır.

---

## 2) Tüm PHP sürümlerini çek (14, native amd64)

```powershell
# baseline + en kritik
docker pull --platform linux/amd64 php:8.4.26-apache
docker pull --platform linux/amd64 php:8.2.34-apache

# tam 5.4 → 8.5 (14 sürüm)
docker pull --platform linux/amd64 php:5.4.45-apache
docker pull --platform linux/amd64 php:5.5.38-apache
docker pull --platform linux/amd64 php:5.6.40-apache
docker pull --platform linux/amd64 php:7.0.33-apache
docker pull --platform linux/amd64 php:7.1.33-apache
docker pull --platform linux/amd64 php:7.2.34-apache
docker pull --platform linux/amd64 php:7.3.33-apache
docker pull --platform linux/amd64 php:7.4.33-apache
docker pull --platform linux/amd64 php:8.0.30-apache
docker pull --platform linux/amd64 php:8.1.32-apache
docker pull --platform linux/amd64 php:8.2.34-apache
docker pull --platform linux/amd64 php:8.3.35-apache
docker pull --platform linux/amd64 php:8.4.26-apache
docker pull --platform linux/amd64 php:8.5.11-apache
```

> **5.4.45 / 5.5.38:** bazı Docker/containerd v2.1 kurulumlarında manifest-v1
> (`prettyjws`) inemiyor. O durumda `php:5.4`/`php:5.5` (genel tag) ya da
> ayna/mirror kullan; inemiyorsa o iki sürüm kaynak derleme ile (ayrı iş).

---

## 3) Container'ları LAN'a aç — port tablosu

Her sürüm **ayrı port'ta**, LAN'dan erişilebilir (`-p host:80`). Container adı = `p2s<versiyon>`.

| Sürüm | Container adı | Host port | LAN URL |
|---|---|---|---|
| 5.4.45 | `p2s5445` | **18101** | http://192.168.8.123:18101/index.php |
| 5.5.38 | `p2s5538` | **18102** | http://192.168.8.123:18102/index.php |
| 5.6.40 | `p2s5640` | **18103** | http://192.168.8.123:18103/index.php |
| 7.0.33 | `p2s7033` | **18104** | http://192.168.8.123:18104/index.php |
| 7.1.33 | `p2s7133` | **18105** | http://192.168.8.123:18105/index.php |
| 7.2.34 | `p2s7234` | **18106** | http://192.168.8.123:18106/index.php |
| 7.3.33 | `p2s7333` | **18107** | http://192.168.8.123:18107/index.php |
| 7.4.33 | `p2s7433` | **18108** | http://192.168.8.123:18108/index.php |
| 8.0.30 | `p2s8030` | **18109** | http://192.168.8.123:18109/index.php |
| 8.1.32 | `p2s8132` | **18110** | http://192.168.8.123:18110/index.php |
| 8.2.34 | `p2s8234` | **18111** | http://192.168.8.123:18111/index.php |
| 8.3.35 | `p2s8335` | **18112** | http://192.168.8.123:18112/index.php |
| **8.4.26 (baseline)** | `p2s8426` | **18113** | http://192.168.8.123:18113/index.php |
| 8.5.11 | `p2s8511` | **18114** | http://192.168.8.123:18114/index.php |

> Not: IP `192.168.8.123` kullanıcının LAN IP'si — senin kutunda farklıysa
> `ipconfig` ile al, tablodaki URL'leri ona göre değiştir.

### Tek komutla hepsini başlat

```powershell
$map = @{
  "5.4.45"="18101"; "5.5.38"="18102"; "5.6.40"="18103";
  "7.0.33"="18104"; "7.1.33"="18105"; "7.2.34"="18106"; "7.3.33"="18107";
  "7.4.33"="18108"; "8.0.30"="18109"; "8.1.32"="18110"; "8.2.34"="18111";
  "8.3.35"="18112"; "8.4.26"="18113"; "8.5.11"="18114"
}
foreach ($v in ($map.Keys | Sort-Object)) {
  $ctr = "p2s" + ($v -replace "[^0-9]","")
  $port = $map[$v]
  docker rm -f $ctr 2>$null | Out-Null
  docker run -d --name $ctr --restart unless-stopped -p $port:80 "php:$v-apache"
  Write-Host "[$v] -> 18100-range port $port ($ctr)"
}
Start-Sleep -Seconds 3
docker ps --filter "name=p2s" --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}"
```

---

## 4) Her container'a index.php koy (hedef sayfa)

Exploit'in hedeflediği sayfa: `<?php echo "OK\n"; ?>`. Resmî image'da
`/var/www/html/index.php` olmayabilir → her container'a koy:

```powershell
# tek dosya, hepsine cp
$php = '<?php echo "OK"; ?>'
Set-Content -Encoding ASCII "$env:TEMP\p2s_index.php" -Value $php

docker ps -a --filter "name=p2s" --format "{{.Names}}" | ForEach-Object {
  docker cp "$env:TEMP\p2s_index.php" $_":/var/www/html/index.php"
  Write-Host "  index.php -> $_"
}
```

> Ya da container başına:
> `docker exec p2s8426 sh -c "printf '%s' '<?php echo \"OK\"; ?>' > /var/www/html/index.php"`

---

## 5) Doğrula (tüm sürümler LAN'dan)

```powershell
$urls = @(
 "http://127.0.0.1:18101/index.php","http://127.0.0.1:18102/index.php",
 "http://127.0.0.1:18103/index.php","http://127.0.0.1:18104/index.php",
 "http://127.0.0.1:18105/index.php","http://127.0.0.1:18106/index.php",
 "http://127.0.0.1:18107/index.php","http://127.0.0.1:18108/index.php",
 "http://127.0.0.1:18109/index.php","http://127.0.0.1:18110/index.php",
 "http://127.0.0.1:18111/index.php","http://127.0.0.1:18112/index.php",
 "http://127.0.0.1:18113/index.php","http://127.0.0.1:18114/index.php")
foreach ($u in $urls) {
  $r = curl -s --max-time 5 $u
  Write-Host ("{0}  ->  {1}" -f $u, $(if ($r) {"OK"} else {"FAIL"}))
}
```

> LAN'dan (farklı makine): `curl http://192.168.8.123:18113/index.php` → `OK`
> **Windows Firewall:** 18101–18114 aralığını LAN profiline aç:
> `New-NetFirewallRule -DisplayName "p2s-php" -Direction Inbound -Port 18101-18114 -Protocol TCP -Action Allow`

---

## 6) MCP araçları — Docker'a programatik erişim

Docker MCP Gateway (http://192.168.8.123:8811/mcp) ile MCP istemcisi üzerinden
Docker'ı yönetmek. **Profil `paths` config'i ister** (desktop-commander + filesystem):

### 6a) Profil düzeltmesi (validation hatası: "paths missing")
```json
{
  "desktop-commander": { "paths": ["/"] },
  "filesystem":        { "paths": ["/"] }
}
```
Profil dosyası: `%USERPROFILE%\.docker\mcp-gateway\profiles\terminal_control.json`
(veya `docker mcp gateway profile list` ile bul).

### 6b) Gateway'i başlat
```powershell
docker mcp gateway run --host 0.0.0.0 --port 8811 --transport streaming --allow-unauthenticated --profile terminal_control
```

### 6c) MCP handshake (initialize → tools)
```http
POST /mcp
Accept: application/json, text/event-stream
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}
→ 200, header: Mcp-Session-Id: <SID>   (sonraki isteklerde gönder)

POST /mcp   (Mcp-Session-Id: <SID>)
{"jsonrpc":"2.0","method":"notifications/initialized"}

POST /mcp   (Mcp-Session-Id: <SID>)
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

### 6d) Kullanışlı MCP tool'ları (katalogdan)
| Server | Ne işe yarar |
|---|---|
| `desktop-commander` | terminal komutu + dosya işlemleri (Docker socket'i mounted ise `docker ...` çalışır) |
| `node-code-sandbox` | disposable Docker container'da JS çalıştır |
| `mcp-api-gateway` | herhangi bir API'yi (Docker Engine API) MCP'ye bağlar |

> Gateway, server'ları **Docker container'ında** çalıştırır; `docker` komutu
> çalışabilesi için container'a Docker socket (`/var/run/docker.sock`) mount
> edilmelidir.

---

## 7) Tek bat dosyası — her şeyi yap (kurulum + başlat + doğrula)

`p2s_target_setup.bat` (Windows'ta çift tıkla):
- Docker'ı kontrol eder,
- 14 PHP image'ını çeker,
- hepsini 18101–18114 portlarında LAN'a açar,
- her container'a index.php koyar,
- local + LAN doğrulaması yapar.

> Bu dosyayı bu projede `p2s_target_setup.bat` olarak hazırladım.

---

## 8) Temizlik (istersen)

```powershell
# tüm p2s container'larını durdur + sil
docker ps -a --filter "name=p2s" --format "{{.Names}}" | ForEach-Object {
  docker rm -f $_ 2>$null
}
# image'ları da sil
docker images --format "{{.Repository}}:{{.Tag}}" | Select-String "php:.*-apache" | ForEach-Object {
  docker rmi $_ 2>$null
}
```

---

## Doğrulama checklist

- [ ] `docker version` → Server: Docker Desktop, WSL 2
- [ ] 14 image `docker images`'da (5.4.45–8.5.11)
- [ ] 14 container `docker ps`'da (p2s5445–p2s8511)
- [ ] 18101–18114 portları dinliyor
- [ ] `curl http://192.168.8.123:18113/index.php` → `OK` (LAN'dan)
- [ ] Windows Firewall 18101–18114 LAN'a açık
