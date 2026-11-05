# `targets/` — Intentionally-Vulnerable Docker Lab Targets

Disposable sandbox applications used to **validate** the P2S native PoC engine.
Each target is vulnerable on purpose and exposes synthetic data only.

> ⚠️ Run these **only** on your own machine, bound to localhost/private networks.
> Never expose any container in this folder to the internet. Delete them after use.

## Target matrix

| File(s) | Application | Weakness exercised | CVEs validated | Suggested port |
|---------|-------------|--------------------|----------------|----------------|
| `Dockerfile.flask` + `flask_ssti.py` | Flask/Jinja2 demo | Server-Side Template Injection | CVE-2024-56201, CVE-2024-5088, CVE-2023-49107 | 18081 |
| `Dockerfile.node` + `node_lfi.js` | Express demo | Path traversal / LFI | CVE-2024-29041 | 18082 |
| `tomcat/`, `tomcat90/` | Tomcat 9.0.x with AJP connector | AJP file read/include ("Ghostcat") | CVE-2020-1938 | 18083 (HTTP), 18084 (AJP) |
| `Dockerfile.dotnet` + `dotnet_mock.py` | ASP.NET-style mock | ViewState/deserialization & LFI checks | ASP.NET module validation | 18085 |
| `Dockerfile.php82` + `p82.php`, `p_lab.php` | PHP 8.2 Apache sandbox | Session/upload-progress behavior probes | php2shell family (lab-only research) | 18101+ |

## Build & run

```bash
# Example: Flask SSTI target
docker build -t p2s-flask-ssti -f targets/Dockerfile.flask targets/
docker run -d --rm --name p2s-flask-ssti -p 127.0.0.1:18081:8080 p2s-flask-ssti

# Example: Node LFI target
docker build -t p2s-node-lfi -f targets/Dockerfile.node targets/
docker run -d --rm --name p2s-node-lfi -p 127.0.0.1:18082:3000 p2s-node-lfi

# Example: Tomcat Ghostcat target (AJP enabled, pre-patch behavior)
docker build -t p2s-ghostcat -f targets/tomcat90/Dockerfile targets/tomcat90
docker run -d --rm --name p2s-ghostcat \
  -p 127.0.0.1:18083:8080 -p 127.0.0.1:18084:8009 p2s-ghostcat
```

Bind published ports to `127.0.0.1` (as above) so the lab never leaves your host.

## Verify a target is up

```bash
curl -s http://127.0.0.1:18081/ | head    # Flask demo page
curl -s http://127.0.0.1:18082/   | head  # Node demo page
curl -s http://127.0.0.1:18083/   | head  # Tomcat default page
```

Then point the scanner at it:

```bash
python3 -c "import core; print(core.scan_url('http://127.0.0.1:18081/')['detect'])"
```

## Cleanup

```bash
docker rm -f p2s-flask-ssti p2s-node-lfi p2s-ghostcat 2>/dev/null
docker image prune -f
```

See `research/windows-lab/deploy/` for additional batch scripts that build the larger
PHP version-matrix lab (Windows/Docker Desktop host).
