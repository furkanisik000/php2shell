# P2S — CVE Scanner & Native PoC Engine

> **Educational / authorized-research use only.** This project targets isolated,
> owner-controlled lab environments (local Docker containers). Running it against
> systems you do not own or have explicit written permission to test is illegal.

**P2S** is a self-contained vulnerability research toolkit:

- **Scanner** (`core.py`) — fingerprinting (server, language runtime, ports, TLS, headers), CVE matching from a local database, and a 0–100 risk score per finding.
- **Native PoC engine** (`poc/`) — pure-Python exploit *validators* (no external binaries) that run **only against your lab targets** and return verifiable proof-of-concept evidence.
- **HTTP API + Web UI** (`server.py`, `index.html`, `web/`) — single-page dashboard for scans, profiles, the CVE DB and logs (port `8123`).
- **MCP server** (`mcp_server.py`) — exposes scanner tools over Model Context Protocol (stdio, JSON-RPC 2.0) for AI-assisted research workflows.
- **Chrome extension** (`local-checker-ext/`) — offline, no-auth PHP version/risk checker for browser tabs.

## Repository layout

```
.
├── README.md                 # this file
├── SECURITY.md               # responsible disclosure & usage policy
├── CONTRIBUTING.md           # how to contribute safely
├── LICENSE                   # MIT (see note on third-party code below)
├── .gitignore
│
├── core.py                   # scanner brain: fingerprint → CVE match → risk score → PoC dispatch
├── store.py                  # SQLite session store (profiles, scans, poc runs, logs)
├── server.py                 # stdlib HTTP API + static UI serving (localhost only by default)
├── mcp_server.py             # MCP tool server (stdio transport)
├── index.html                # built-in single-file web UI
│
├── db/                       # data files (JSON); runtime state (session.db, logs) is git-ignored
│   ├── vulns.json            # CVE knowledge base
│   ├── exploits.json         # PoC metadata & command templates
│   └── profiles.json         # example scan profiles
│
├── poc/                      # native PoC modules (one file per vulnerability class)
│   ├── _net.py               # shared socket/HTTP helpers
│   ├── php_http.py           # PHP request-layer checks
│   ├── php2shell.py          # php2shell chain validator (lab-only)
│   ├── java_web.py           # Java/AJP checks
│   ├── asp_dotnet.py         # ASP.NET checks
│   ├── node_web.py           # Node.js checks
│   ├── python_web.py         # Python/SSTI checks
│   ├── perl_local.py         # Perl checks
│   ├── mysql_proto.py        # MySQL protocol checks
│   └── h2c.py                # HTTP/2 cleartext checks
│
├── web/                      # React (Vite) frontend source — rebuild locally, dist/ is ignored
│
├── targets/                  # intentionally-vulnerable Docker lab targets (PHP, Tomcat, Flask, Node, .NET)
│
├── scripts/                  # helper scripts
│   ├── p2s_probe.php         # tiny PHP probe used inside lab containers
│   ├── p2s_other_setup.bat   # Windows/Docker Desktop lab bootstrap
│   └── lab-deploy/           # batch scripts that configure the lab PHP instances
│
├── research/                 # notes & raw research artifacts (read-only archive material)
│   ├── notes/                # project compass, lab setup guides, target matrix
│   └── windows-lab/          # deep-dive research tree recovered from the lab machine
│
├── local-checker-ext/        # unpacked Chrome extension (offline PHP version checker)
│
└── upstream-reference/       # third-party reference PoC for CVE-2026-109618/19 (own license, see dir)
```

## Quick start (lab environment)

Requirements: Python 3.10+ (stdlib only), Docker Desktop / Docker Engine for targets.

```bash
# 1. Start one of the vulnerable lab targets, e.g. the PHP 8.2 sandbox
docker build -t p2s-php -f targets/Dockerfile.php82 targets/
docker run -d --rm -p 18101:80 p2s-php

# 2. Run the API server + UI (binds 127.0.0.1:8123)
python3 server.py
# open http://127.0.0.1:8123/

# 3. Or drive the scanner directly
python3 -c "import core; print(core.scan_url('http://127.0.0.1:18101/')['detect'])"

# 4. Optional: attach the MCP server to an MCP-capable client
python3 mcp_server.py
```

The frontend in `web/` is optional; `index.html` at the repo root is served by
default. To rebuild the React app: `npm --prefix web install && npm --prefix web run build`.

## Safety guardrails

- The server is a **localhost tool**: keep it bound to `127.0.0.1` (see note below) and never expose it
  to untrusted networks; static file serving validates paths against traversal.
- PoC modules are *validators*: they prove a class of weakness against a target you point them at; they are not mass-scan or weaponization tooling.
- All bundled targets are disposable Docker containers with synthetic data. Delete them after use.
- No credentials, personal IPs, hostnames or cloud-instance identifiers belong in this repo; runtime state is excluded via `.gitignore`.

## Third-party code

`upstream-reference/` contains an external research PoC kept for reference under its
original license (see `upstream-reference/LICENSE` and `upstream-reference/README.md`).
It is not part of the P2S package and is not imported by any module here.

## Disclaimer

The authors accept no responsibility for misuse. Unauthorized access to computer
systems is illegal in most jurisdictions. Use this project only within environments
you own or are explicitly authorized to test.
