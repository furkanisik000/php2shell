# P2S — CVE Scanner Projesi Haritası

> **php2shell → P2S**: Profesyonel CVE tarama + native PoC motoru.
> Her PoC, scanner'ın kendisi tarafından socket açılarak, exploit mantığı native olarak (Python) çalıştırılır.
> Dış binary (curl/python/c) YOK.

## Mimari

```
php2shell/
├── server.py          # Python stdlib HTTP API + web/dist/ statik servis (port 8123)
├── core.py            # Tarama + risk skoru + PoC dispatch
├── store.py           # SQLite session store (profiles, scans, poc_runs, logs)
├── mcp_server.py      # MCP tool (qwen mcp add p2s ...)
├── db/
│   ├── session.db     # SQLite: profiles, scans, poc_runs, logs
│   └── vulns.json     # 344 CVE katalogu (JSON)
├── poc/               # NATIVE PoC motoru (33 PoC)
│   ├── __init__.py    # REGISTRY + run_exploit()
│   ├── _net.py        # Düşük seviye HTTP/socket primitifleri
│   ├── php2shell.py   # CVE-2026-109618/19 (session.upload_progress OOM+UAF)
│   ├── php_http.py    # PHP HTTP exploitleri (cgi, fpm, phar, unserialize)
│   ├── python_web.py  # Flask/Jinja2 SSTI RCE (CVE-2024-56201/-5088/-22194, CVE-2023-49107)
│   ├── node_web.py    # Node.js LFI (CVE-2024-29041)
│   ├── java_web.py    # Tomcat Ghostcat (CVE-2020-1938, AJP 1.3)
│   ├── asp_dotnet.py  # ASP.NET ViewState RCE + XXE + LFI
│   ├── mysql_proto.py # MySQL protokol exploitleri
│   ├── h2c.py         # HTTP/2 exploitleri
│   └── perl_local.py  # Perl local exploitler
├── web/               # React 18.3.1 + Vite 5.4 frontend
│   └── dist/          # Build output (server.py tarafından servis edilir)
└── targets/           # Docker lab hedefleri
    ├── Dockerfile.node, node_lfi.js
    ├── Dockerfile.dotnet, dotnet_mock.py
    ├── tomcat/, tomcat90/
    └── ...
```

## Doğrulanmış PoC'ler (REAL PROOF)

| CVE / ID | Tip | Kanıt | Durum |
|----------|-----|-------|-------|
| CVE-2024-56201 | SSTI→RCE | `uid=0(root) gid=0(root)` + `uname -a` | ✅ DOĞRULANDI |
| CVE-2024-29041 | LFI | `/etc/passwd` (root:x:0:0) | ✅ DOĞRULANDI |
| CWE-611 (XXE) | FileRead | `/etc/passwd` (root:x:0:0) | ✅ DOĞRULANDI |
| CWE-22-dotnet (LFI) | FileRead | `/etc/passwd` (root:x:0:0) | ✅ DOĞRULANDI |

## Bloke PoC'ler (çevre/sınırlama)

| CVE | Neden | Not |
|-----|-------|-----|
| CVE-2026-109618/19 | 18120 OOM hedefi düşük (RDP ile başlatılacak) | native amd64 + `session_start` + `memory_limit=8M`/`post_max_size=16M` şart; 18101-18114 default config → PHPSESSID oluşmuyor (diagnostikle kanıtlı) |
| CVE-2020-1938 (Ghostcat) | Colima'da AJP transport 0 byte | PoC doğru (spec-verified), environment limit |

### php2shell gerçek kanıt — native amd64 ortam
- **Windows kutusu 192.168.8.123** (x86_64, Docker Desktop): 14 PHP hedef 18101–18114 (native amd64, AÇIK) + **18120 OOM test hedefi** (düşük).
- **18101–18114** `index.php="OK"` → `session_start()` yok, default memory_limit → exploit koşulu yok (PHPSESSID oluşmuyor).
- **18120** = exploit'in ihtiyacı olan kurulum (`memory_limit=8M`, `post_max_size=16M`, `session_start`); RDP `likat/124578` ile `p2s_probe_deploy.bat` çalıştırınca ayağa kalkacak.
- **Düzeltilen bug:** `_hex("465370")` ondalık (0x719DA) yorumlanıyordu → hex'e (0x465370) zorlandı. Stage2/3 pointer'ları artık doğru.

## Kullanım

```bash
# Server başlat (port 8123)
python3.12 server.py

# API endpointleri
GET  /api/health
GET  /api/pocs              # PoC listesi
GET  /api/vulns             # CVE katalogu
POST /api/scan              # Tarama başlat
GET  /api/scans             # Tarama geçmişi
POST /api/poc/run           # PoC çalıştır
GET  /api/logs              # Loglar
```

## MCP Tool

```bash
qwen mcp add p2s -- /opt/homebrew/bin/python3.12 /Users/emredagdelen/Desktop/php2shell/mcp_server.py
# Qwen restart gerekli
```

## Risk Skoru

```
base = 100 * (1 - e^(-raw / 2.5))
Grades: ≥85 Kritik | 65 Yüksek | 45 Orta | 25 Düşük | <25 Minimal
```

## Docker Lab Hedefleri

| Hedef | Port | Amaç |
|-------|------|------|
| p2s-flask-ssti | 18081 | Flask/Jinja2 SSTI RCE |
| p2s-node-lfi | 18082 | Node.js LFI |
| p2s-dotnet | 18085 | ASP.NET XXE + LFI |
| p2s-ghostcat | 18083 | Tomcat AJP (Ghostcat) |
| p2s-82lab | 18282 | PHP 8.2.34 lab |

## PoC Motoru API

```python
import poc

# Liste
poc.list_exploits()  # {cve_id: spec}

# Tek PoC çalıştır
result = poc.run_exploit("CVE-2024-56201", {
    "url": "http://127.0.0.1:18081/vuln",
    "param": "name",
    "cmd": "id",
})
# result: {ok, success, status, evidence, detail, log}
```
