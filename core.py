#!/usr/bin/env python3
"""core.py — P2S CVE Scanner core (shared by the HTTP UI and the MCP server).

Zero third-party dependencies (stdlib only). Everything here runs against
targets the operator is authorized to test (own test sites + authorized
red-team scope).

Public API (used by server.py and mcp_server.py):
  load_vulns()            -> list[CVE]            (exploit panels merged in)
  match_cves(detections)  -> list[dict]           CVEs for detected sw+version
  scan_url(url)           -> dict                 full passive/active fingerprint
  score_risk(scan, cves)  -> dict                 0-100 + grade + transparent factors
  build_profile(url)      -> dict                 scan + cves + risk, persisted
  list_profiles() / get_profile(id) / delete_profile(id) / rename_profile(id, name)
  poc_list()              -> dict                 runnable PoC catalog (merged)
  build_command(cve_id, params) -> str
  run_command(cmd)        -> dict                 bounded local PoC executor
  build_report(profile, fmt) -> (text, filename)
  fingerprint(scan)       -> dict                 one-glance composite
  tls_fingerprint(host, port) / http_headers_audit(p) / probe_paths(host, port)
"""
from __future__ import annotations

import calendar
import concurrent.futures
import hashlib
import json
import math
import os
import re
import shlex
import socket
import ssl
import subprocess
import time
import urllib.parse
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in os.sys.path:
    os.sys.path.insert(0, HERE)
import sys
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# native PoC engine (poc/ package) — the scanner sends the exploit itself
try:
    import poc  # noqa: F401
except Exception as _e:  # pragma: no cover
    poc = None
    _POC_IMPORT_ERROR = str(_e)
else:
    _POC_IMPORT_ERROR = None

# professional session store (SQLite) + logging — profiles / scans / poc_runs / logs
# (static CVE DB + PoC definitions remain in JSON, per project decision)
import store  # noqa: E402
store.init()
log = store.log  # convenience: core.log(level, category, message, data)

DB = os.path.join(HERE, "db")
VULNS = os.path.join(DB, "vulns.json")
EXPLOITS = os.path.join(DB, "exploits.json")
PROFILES = os.path.join(DB, "profiles.json")
REPORTS = os.path.join(DB, "reports")

MAX_RUN = 180          # seconds, per PoC execution
TCP_TIMEOUT = 0.5      # port connect probe
BANNER_TIMEOUT = 1.5   # service banner read
PATH_TIMEOUT = 3.0     # per interesting-path GET

# Bounded local tool allow-list (first real token must be one of these).
# Covers every PoC in db/exploits.json (python3 / curl / mysql / perl) plus a
# few read-only recon helpers. Not a general shell — it is an allow-list gate.
ALLOWED_BIN = {
    "python", "python3", "python3.11", "python3.12", "python3.13",
    "curl", "wget",
    "mysql", "mysqladmin", "mariadb",
    "perl", "ruby",
    "openssl", "nc", "ncat", "socat",
    "id", "whoami", "hostname", "uname", "ping", "dig", "host",
    "php", "git",
}

_SW_NAME = {"apache": "Apache", "nginx": "Nginx", "iis": "IIS",
            "litespeed": "LiteSpeed", "caddy": "Caddy"}


# ---------------------------------------------------------------------------
# time / small helpers
# ---------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clamp(x, lo=0.0, hi=100.0):
    return max(lo, min(hi, x))


def _ver_tuple(v: str):
    try:
        return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
    except Exception:
        return (0, 0, 0)


def grade_for(score: float):
    s = int(round(score))
    if s >= 85:
        return "Kritik", "F"
    if s >= 65:
        return "Yuksek", "D"
    if s >= 45:
        return "Orta", "C"
    if s >= 25:
        return "Dusuk", "B"
    return "Minimal", "A"


# ---------------------------------------------------------------------------
# CVE database (vulns.json with exploit panels merged in from exploits.json)
# ---------------------------------------------------------------------------
_VULNS_CACHE = None
_EXPLOITS_CACHE = None


def load_exploits() -> dict:
    global _EXPLOITS_CACHE
    if _EXPLOITS_CACHE is None:
        try:
            with open(EXPLOITS, "r", encoding="utf-8") as f:
                _EXPLOITS_CACHE = json.load(f)
        except Exception:
            _EXPLOITS_CACHE = {}
    return _EXPLOITS_CACHE


def load_vulns() -> list:
    """Return CVE list; every entry gets an 'exploit' panel merged in by id
    (so a freshly regenerated vulns.json never loses its PoC panels)."""
    global _VULNS_CACHE
    if _VULNS_CACHE is not None:
        return _VULNS_CACHE
    with open(VULNS, "r", encoding="utf-8") as f:
        vulns = json.load(f)
    exp = load_exploits()
    for v in vulns:
        if exp.get(v.get("id")) and not v.get("exploit"):
            v["exploit"] = exp[v["id"]]
    _VULNS_CACHE = vulns
    return vulns


def get_cve(cve_id: str):
    for v in load_vulns():
        if v.get("id") == cve_id:
            return v
    return None


def software_summary() -> dict:
    """software -> {total, with_poc, versions: [...]}"""
    out = {}
    for v in load_vulns():
        sw = v.get("software", "?")
        d = out.setdefault(sw, {"total": 0, "with_poc": 0, "versions": set()})
        d["total"] += 1
        if v.get("exploit"):
            d["with_poc"] += 1
        for a in v.get("affected", []):
            d["versions"].add(a)
    for sw, d in out.items():
        d["versions"] = sorted(d["versions"], key=_ver_tuple)
    return out


# ---------------------------------------------------------------------------
# version parsing / detection
# ---------------------------------------------------------------------------
def _http_probe(url: str, timeout: float = 6.0) -> dict:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        url = "http://" + url
        u = urllib.parse.urlsplit(url)
    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"

    headers, status, err = {}, 0, ""
    ttfb = None
    buf = b""
    try:
        t0 = time.time()
        if u.scheme == "https":
            s = socket.create_connection((host, port), timeout=timeout)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        else:
            s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            f"AppleWebKit/537.36\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        while len(buf) < (1 << 20):
            c = s.recv(65536)
            if not c:
                break
            buf += c
        s.close()
        ttfb = round((time.time() - t0) * 1000, 1)
        head, _, body = buf.partition(b"\r\n\r\n")
        for line in head.split(b"\r\n"):
            if b":" in line:
                k, val = line.split(b":", 1)
                headers[k.decode("latin1").strip().lower()] = val.decode("latin1").strip()
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        status = int(m.group(1)) if m else 0
    except OSError as e:
        err = str(e)

    return {
        "url": f"{u.scheme}://{host}:{port}{path}",
        "host": host, "port": port, "path": path,
        "status": status, "error": err,
        "server": headers.get("server", ""),
        "xpoweredby": headers.get("x-powered-by", ""),
        "date": headers.get("date", ""),
        "ttfb_ms": ttfb,
        "body_bytes": len(buf) - buf.find(b"\r\n\r\n") - 4 if b"\r\n\r\n" in buf else 0,
        "headers": headers,
    }


def detect(p: dict) -> dict:
    xpb = p.get("xpoweredby", "")
    m = re.search(r"(\d+\.\d+\.\d+)", xpb)
    php_ver = m.group(1) if m else ""
    php_major = ".".join(php_ver.split(".")[:2]) if php_ver else ""

    srv = p.get("server", "")
    sr = srv.lower()
    webserver = "unknown"
    if "apache" in sr:
        webserver = "apache"
    elif "nginx" in sr:
        webserver = "nginx"
    elif "iis" in sr:
        webserver = "iis"
    elif "lite speed" in sr or "litespeed" in sr:
        webserver = "litespeed"
    elif "caddy" in sr:
        webserver = "caddy"

    sw_version = ""
    m2 = re.search(r"(\d+\.\d+\.\d+)", srv)
    if m2 and webserver != "unknown":
        sw_version = m2.group(1)
    sw_major = ".".join(sw_version.split(".")[:2]) if sw_version else ""

    os_hint = ""
    if "debian" in sr:
        os_hint = "Debian"
    elif "ubuntu" in sr:
        os_hint = "Ubuntu"
    elif "centos" in sr or "rhel" in sr:
        os_hint = "CentOS/RHEL"
    elif "win" in sr:
        os_hint = "Windows"
    elif "linux" in sr:
        os_hint = "Linux"

    detections = []
    if php_major:
        detections.append({"software": "PHP", "version": php_ver, "major": php_major})
    if webserver in _SW_NAME and sw_major:
        detections.append({"software": _SW_NAME[webserver], "version": sw_version, "major": sw_major})

    sapi = ("mod_php (apache2handler)" if webserver == "apache" and php_ver
            else "php-fpm/litespeed" if webserver in ("nginx", "litespeed")
            else "unknown")

    return {
        **p,
        "php_version": php_ver, "php_major": php_major,
        "webserver": webserver, "webserver_version": sw_version, "webserver_major": sw_major,
        "detections": detections, "os_hint": os_hint, "sapi_guess": sapi,
    }


# ---------------------------------------------------------------------------
# WAF
# ---------------------------------------------------------------------------
def _waf_challenge(host: str, port: int, scheme: str, timeout: float = 3.0):
    path = "/?id=1%27%22%3E%3Csvg%20onload%3Dalert(1)%3E&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    try:
        if scheme == "https":
            s = socket.create_connection((host, port), timeout=timeout)
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        else:
            s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        s.settimeout(timeout)
        while len(buf) < (1 << 16):
            c = s.recv(65536)
            if not c:
                break
            buf += c
        s.close()
    except OSError:
        return 0, []
    head, _, body = buf.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    status = int(m.group(1)) if m else 0
    low = (head + body[:4000]).decode("latin1", "replace").lower()
    words = ["blocked", "access denied", "request rejected", "just a moment",
             "attention required", "firewall", "unusual traffic", "request not allowed"]
    return status, [w for w in words if w in low]


def detect_waf(p: dict) -> dict:
    hdrs = p.get("headers") or {}
    al = " ".join(f"{k}: {v}" for k, v in hdrs.items()).lower()
    srv = hdrs.get("server", "").lower()
    names, evidence = [], []

    def add(name, ev):
        if name not in names:
            names.append(name)
            evidence.append(f"{name} -> {ev}")

    if "cloudflare" in al or "cf-ray" in al or "cf-cache-status" in al:
        add("Cloudflare", "cf-*/cloudflare header")
    if "x-amz-cf-id" in al:
        add("AWS CloudFront/WAF", "x-amz-cf-id")
    if "x-sucuri" in al:
        add("Sucuri", "x-sucuri-*")
    if "incap_s" in al or "visid_incap" in al or "x-imperva" in al:
        add("Imperva/Incapsula", "incap/visid cookie")
    if "mod_security" in al:
        add("ModSecurity", "mod_security (Server)")
    if "bigipserver" in al or "tslb_" in al or "ts_sessionid" in al:
        add("F5 BIG-IP ASM", "bigip/ts* cookie")
    if "x-azure-ref" in al:
        add("Azure Front Door WAF", "x-azure-ref")
    if "x-akamai" in al or "akamai" in srv:
        add("Akamai", "x-akamai/Server")
    if "varnish" in al:
        add("Varnish CDN", "via: varnish")
    if "x-waf" in al:
        add("WAF (generic)", "x-waf header")

    challenge_blocked = False
    challenge_note = ""
    if p.get("status") and p.get("host"):
        u = urllib.parse.urlsplit(p["url"])
        st, hits = _waf_challenge(p["host"], p["port"], u.scheme or "http")
        if st in (403, 406, 503):
            challenge_blocked = True
            challenge_note = f"challenge -> HTTP {st}"
            if hits:
                challenge_note += " (" + ", ".join(hits[:3]) + ")"
            if not names:
                add("WAF (davranis sinyali)", challenge_note)
        elif hits:
            challenge_note = "block keyword: " + ", ".join(hits[:3])

    return {
        "present": bool(names) or challenge_blocked,
        "names": names, "evidence": evidence,
        "challenge_blocked": challenge_blocked, "challenge_note": challenge_note,
    }


# ---------------------------------------------------------------------------
# ports
# ---------------------------------------------------------------------------
PORT_LIST = [
    21, 22, 25, 53, 80, 110, 143, 3306, 3389, 5432, 6379,
    8080, 8443, 9000, 9090, 11434, 27017,
    18101, 18102, 18103, 18104, 18105, 18106, 18107, 18108,
    18109, 18110, 18111, 18112, 18113, 18114, 18120, 18130,
]


def _banner(host: str, port: int):
    try:
        s = socket.create_connection((host, port), timeout=BANNER_TIMEOUT)
    except OSError:
        return None, ""
    try:
        s.settimeout(0.8)
        try:
            greet = s.recv(1024)
        except socket.timeout:
            greet = b""
        if greet:
            if greet.startswith(b"SSH-"):
                return "ssh", greet.decode("latin1", "replace").strip().splitlines()[0]
            if greet[:1] == b"\x0a":
                m = re.search(rb"(\d+\.\d+\.\d+(?:\.\d+)?)", greet)
                if m:
                    return "mysql", m.group(1).decode()
            if greet.startswith(b"220"):
                return "smtp", greet.decode("latin1", "replace").splitlines()[0].strip()
        buf = b""
        try:
            s.sendall(f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            s.settimeout(1.2)
            while b"\r\n\r\n" not in buf and len(buf) < 16384:
                c = s.recv(4096)
                if not c:
                    break
                buf += c
        except OSError:
            pass
        if buf.startswith(b"HTTP/"):
            srv = re.search(rb"(?im)^server:\s*(.+?)\s*$", buf)
            xpb = re.search(rb"(?im)^x-powered-by:\s*(.+?)\s*$", buf)
            parts = []
            if srv:
                parts.append(srv.group(1).decode("latin1", "replace"))
            if xpb:
                parts.append(xpb.group(1).decode("latin1", "replace"))
            return "http", " / ".join(parts)
        if buf.startswith(b"+PONG") or buf.startswith(b"-ERR") or buf.startswith(b"+OK"):
            return "redis", ""
        return "open", ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def scan_ports(host: str, extra_ports=None, skip_port=None) -> list:
    ports = [p for p in PORT_LIST if p != skip_port]
    for p in (extra_ports or []):
        if p not in ports:
            ports.append(p)

    def _alive(port):
        try:
            with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
                return True
        except OSError:
            return False

    open_set = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        for port, ok in zip(ports, ex.map(_alive, ports)):
            if ok:
                open_set.add(port)

    got = {}
    if open_set:
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ex.submit(_banner, host, p): p for p in open_set}
            try:
                for f in concurrent.futures.as_completed(futs, timeout=25):
                    p = futs[f]
                    try:
                        svc, ver = f.result()
                        if svc:
                            got[p] = (svc, ver)
                    except Exception:
                        pass
            except concurrent.futures.TimeoutError:
                pass

    return [{"port": p, "service": got.get(p, ("open", ""))[0],
             "version": got.get(p, ("open", ""))[1]} for p in sorted(open_set)]


# ---------------------------------------------------------------------------
# TLS fingerprint
# ---------------------------------------------------------------------------
def tls_fingerprint(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    """TLS parmak izi: protokol, cipher suite ve sertifika meta verileri.

    Sertifika dogrulamasi BILINCLI olarak kapalidir (CERT_NONE) — taranacak
    hedefler kendi imzaladigi lab sertifikalari da tasiyabilir; amac guvenlik
    denetimi degil servis surum/zafiflik tespiti icin veri toplamaktir.

    Returns:
        {"ok": True, "protocol", "cipher": {...}, "cert": {...}} ya da
        baglanti/sohbet hatasinda {"ok": False, "error": ...}.
    """
    out = {"ok": False}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s, server_hostname=host)
    except Exception as e:
        return {"ok": False, "error": str(e)}

    try:
        cert = ss.getpeercert() or {}
        cipher = ss.cipher()
        proto = ss.version()
        san = []
        for kind, val in cert.get("subjectAltName", []):
            if kind == "DNS":
                san.append(val)
        def _names(tup):
            return [v for _, v in tup] if tup else []
        out = {
            "ok": True,
            "protocol": proto,
            "cipher": {
                "name": cipher[0] if cipher else "",
                "tls": cipher[1] if cipher else "",
                "bits": cipher[2] if cipher and len(cipher) > 2 else 0,
            },
            "cert": {
                "subject": " ".join(_names(cert.get("subject", [])))[:300],
                "issuer": " ".join(_names(cert.get("issuer", [])))[:300],
                "cn": next((v for k, v in cert.get("subject", []) if k == "commonName"), ""),
                "san": san,
                "serial": cert.get("serialNumber", ""),
                "not_before": cert.get("notBefore", ""),
                "not_after": cert.get("notAfter", ""),
            },
        }
        # gun -> saniye cinsinden son kullanma yakinligi (raporlama icin)
        try:
            exp_ts = calendar.timegm(time.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z"))
            out["cert"]["days_to_expire"] = int((exp_ts - time.time()) // 86400)
        except Exception:
            out["cert"]["days_to_expire"] = None
        ss.close()
    except Exception as e:
        out["error"] = str(e)
    return out


# ---------------------------------------------------------------------------
# HTTP security-headers audit
# ---------------------------------------------------------------------------
_HEADER_RULES = [
    ("strict-transport-security", "HSTS", "critical", "HTTPS zorlamasi yok — MITM/protocol-downgrade riski"),
    ("content-security-policy", "CSP", "high", "XSS'i sinirlar; yoksa XSS daha tehlikeli"),
    ("x-frame-options", "X-Frame-Options", "medium", "clickjacking korumasi yok"),
    ("x-content-type-options", "X-Content-Type-Options", "medium", "MIME-sniffing korumasi yok"),
    ("referrer-policy", "Referrer-Policy", "low", "referrer sizdirabilir"),
    ("permissions-policy", "Permissions-Policy", "low", "kamera/mikrofon/clipboard izinleri acik"),
    ("x-xss-protection", "X-XSS-Protection", "low", "eski XSS filtresi (onerilmez ama var)"),
]


def http_headers_audit(p: dict) -> list:
    hdrs = {k.lower(): v for k, v in (p.get("headers") or {}).items()}
    out = []
    for key, label, sev, note in _HEADER_RULES:
        present = key in hdrs
        out.append({
            "header": key, "label": label, "severity": sev,
            "present": present,
            "value": hdrs.get(key, ""),
            "note": ("OK" if present else note),
        })
    # bonus: server / x-powered-by disclosure
    leak = []
    if hdrs.get("server"):
        leak.append({"header": "server", "value": hdrs["server"], "note": "webserver surumu sizdiriyor"})
    if hdrs.get("x-powered-by"):
        leak.append({"header": "x-powered-by", "value": hdrs["x-powered-by"], "note": "PHP surumu sizdiriyor"})
    out.append({"header": "info-disclosure", "label": "Header leak", "severity": "info",
                "present": bool(leak), "value": "; ".join(f"{l['header']}={l['value']}" for l in leak),
                "note": ("surum sizdirma tespit edildi" if leak else "surum sizdirma yok")})
    return out


# ---------------------------------------------------------------------------
# interesting paths (attack-surface discovery)
# ---------------------------------------------------------------------------
INTERESTING_PATHS = [
    "/", "/index.php", "/admin", "/admin/", "/wp-login.php", "/wp-admin/",
    "/phpmyadmin", "/pma", "/.env", "/.git/config", "/server-status",
    "/server-info", "/phpinfo.php", "/info.php", "/test.php", "/izin.php",
    "/cgi-bin/php", "/cgi-bin/.cgi", "/debug", "/actuator", "/api",
]


def probe_paths(host: str, port: int, scheme: str = "http", timeout: float = PATH_TIMEOUT) -> list:
    results = []

    def _one(path):
        try:
            if scheme == "https":
                s = socket.create_connection((host, port), timeout=timeout)
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            else:
                s = socket.create_connection((host, port), timeout=timeout)
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            buf = b""
            s.settimeout(timeout)
            while b"\r\n\r\n" not in buf and len(buf) < 4096:
                c = s.recv(2048)
                if not c:
                    break
                buf += c
            s.close()
            m = re.match(rb"HTTP/1\.[01] (\d{3})", buf)
            st = int(m.group(1)) if m else 0
            cl = re.search(rb"(?im)^content-length:\s*(\d+)", buf)
            return {"path": path, "status": st,
                    "length": int(cl.group(1)) if cl else 0,
                    "interesting": st in (200, 301, 302)}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        for r in ex.map(_one, INTERESTING_PATHS):
            if r:
                results.append(r)
    results.sort(key=lambda x: (not x["interesting"], x["status"], x["path"]))
    return results


# ---------------------------------------------------------------------------
# CVE matching
# ---------------------------------------------------------------------------
def cve_weight(c: dict) -> float:
    """Exploitability weight of one CVE (used for sorting + risk model)."""
    base = _clamp(c.get("score", 9.0) - 9.0, 0.0, 1.0)
    contrib = 0.5 + 0.5 * base
    exp = c.get("exploit") or {}
    m = 1.0
    if exp.get("preauth"):
        m *= 1.4
    if exp.get("type") == "RCE":
        m *= 1.5
    if exp:
        m *= 1.25
    if c.get("edb"):
        m *= 1.1
    return min(1.0, contrib * m)


def match_cves(detections: list) -> list:
    """Return dedup'd CVEs for the detected software+major, exploitability-sorted."""
    vulns = load_vulns()
    by_id = {}
    for d in detections or []:
        sw, major = d.get("software"), d.get("major")
        if not sw or not major:
            continue
        for v in vulns:
            if v.get("software") == sw and major in (v.get("affected") or []):
                v = dict(v)
                v["hit_major"] = major
                v["weight"] = round(cve_weight(v), 4)
                by_id[v["id"]] = v
    out = list(by_id.values())
    out.sort(key=lambda c: (-c.get("weight", 0), -c.get("score", 0)))
    return out


# ---------------------------------------------------------------------------
# risk scoring
# ---------------------------------------------------------------------------
def score_risk(scan: dict, cves: list) -> dict:
    factors = []

    raw = sum(c.get("weight", 0.0) for c in cves)
    base = 100 * (1 - math.exp(-raw / 2.5))
    factors.append({"label": "Eslesen kritik CVE (exploitability)",
                    "delta": round(base, 1),
                    "note": f"{len(cves)} CVE, raw={round(raw, 2)}"})

    n_poc = sum(1 for c in cves if c.get("exploit"))
    n_pre = sum(1 for c in cves if (c.get("exploit") or {}).get("preauth"))
    if n_pre:
        factors.append({"label": "Pre-auth yuzeyi", "delta": 0,
                        "note": f"{n_pre} pre-auth CVE"})
    if n_poc:
        factors.append({"label": "Calisir PoC", "delta": 0,
                        "note": f"{n_poc} CVE'de exploit paneli"})

    mult = 1.0
    waf = scan.get("waf") or {}
    if waf.get("present"):
        mult *= 0.80
        factors.append({"label": "WAF (azaltici)", "delta": round((0.20) * base, 1),
                        "note": ", ".join(waf.get("names") or []) or "sinyal"})
    if waf.get("challenge_blocked"):
        mult *= 0.90
        factors.append({"label": "Challenge/403", "delta": 0, "note": "istek reddedildi"})

    ports = scan.get("ports") or []
    exposure = min(10, len(ports))
    if exposure:
        factors.append({"label": "Acik port yuzeyi", "delta": exposure,
                        "note": f"{len(ports)} acik port"})

    penalty = base * (1 - mult)
    final = _clamp(base - penalty + exposure, 0, 100)
    if penalty:
        factors.append({"label": "Toplam azaltim", "delta": -round(penalty, 1),
                        "note": "WAF/challenge"})

    grade, letter = grade_for(final)
    return {
        "score": round(final, 1),
        "grade": grade,
        "letter": letter,
        "n_cve": len(cves),
        "n_poc": n_poc,
        "n_preauth": n_pre,
        "factors": factors,
        "computed_at": now_iso(),
    }


# ---------------------------------------------------------------------------
# fingerprint composite
# ---------------------------------------------------------------------------
def fingerprint(scan: dict) -> dict:
    return {
        "url": scan.get("url"),
        "host": scan.get("host"),
        "port": scan.get("port"),
        "status": scan.get("status"),
        "ttfb_ms": scan.get("ttfb_ms"),
        "php_version": scan.get("php_version"),
        "php_major": scan.get("php_major"),
        "webserver": scan.get("webserver"),
        "webserver_version": scan.get("webserver_version"),
        "os_hint": scan.get("os_hint"),
        "sapi": scan.get("sapi_guess"),
        "waf": (scan.get("waf") or {}).get("names", []),
        "open_ports": [p["port"] for p in (scan.get("ports") or [])],
        "server_header": scan.get("server"),
        "x_powered_by": scan.get("xpoweredby"),
    }


# ---------------------------------------------------------------------------
# full scan
# ---------------------------------------------------------------------------
def scan_url(url: str, do_paths: bool = True, do_tls: bool = True) -> dict:
    p = _http_probe(url)
    d = detect(p)
    host = p.get("host") or ""
    d["waf"] = detect_waf(p) if host else {"present": False, "names": []}
    d["ports"] = scan_ports(host, skip_port=p.get("port")) if host else []
    if do_tls and host and (p.get("port") in (443, 8443) or "https" in p.get("url", "")):
        try:
            d["tls"] = tls_fingerprint(host, p.get("port") or 443)
        except Exception as e:
            d["tls"] = {"ok": False, "error": str(e)}
    if do_paths and host:
        d["paths"] = probe_paths(host, p.get("port"), (p.get("url", "")[:5]))
    d["headers_audit"] = http_headers_audit(p)
    d["fingerprint"] = fingerprint(d)
    d["cves"] = match_cves(d.get("detections") or [])
    d["risk"] = score_risk(d, d["cves"])
    d["scanned_at"] = now_iso()
    return d


# ---------------------------------------------------------------------------
# profiles (persisted)
# ---------------------------------------------------------------------------
def build_profile(url: str, name: str = None, save: bool = True,
                  do_paths: bool = True, existing_id: str = None) -> dict:
    """Scan a target and (optionally) persist it as a profile in SQLite.

    If `existing_id` is given (re-scan) the new scan is APPENDED to that profile
    (history is kept — professional). Otherwise a new profile is created.
    Every scan is logged to the SQLite logs table + db/logs.log.
    """
    log("INFO", "scan", f"tarama basladi: {url}", {"url": url})
    scan = scan_url(url, do_paths=do_paths)
    host = scan.get("host") or "target"
    port = scan.get("port") or 80
    n_cve = len(scan.get("cves") or [])
    risk = scan.get("risk") or {}
    log("INFO", "scan",
        f"tarama bitti: {host} — {n_cve} CVE, risk={risk.get('score')} ({risk.get('grade') or risk.get('letter') or '-'})",
        {"url": scan.get("url", url), "host": host, "cves": n_cve,
         "risk": risk.get("score"), "grade": risk.get("grade")})

    if not save:
        return {"id": None, "name": name or f"{host}:{port}",
                "url": scan.get("url", url), "created_at": now_iso(), "updated_at": now_iso(),
                "scan": scan, "risk": risk, "poc_results": {}, "scans": [scan]}

    # re-scan an existing profile (append) or create a fresh one
    if existing_id and store.get_profile(existing_id):
        pid = existing_id
    else:
        pid = "p_" + hashlib.sha1(f"{scan.get('url', url)}{time.time()}".encode()).hexdigest()[:10]
        store.save_profile(pid, name or f"{host}:{port}", scan.get("url", url),
                           created=now_iso(), updated=now_iso())
    store.record_scan(pid, scan.get("url", url), scan)
    return store.get_profile(pid)


def list_profiles() -> list:
    return store.list_profiles()


def get_profile(pid: str) -> dict | None:
    return store.get_profile(pid)


def rename_profile(pid: str, name: str) -> bool:
    ok = store.rename_profile(pid, name)
    if ok:
        log("INFO", "profile", f"profil yeniden adlandirildi: {pid} -> {name}")
    return ok


def delete_profile(pid: str) -> bool:
    ok = store.delete_profile(pid)
    log("INFO", "profile", f"profil silindi: {pid}")
    return ok


def record_poc_result(pid: str, cve_id: str, res: dict, params: dict = None) -> bool:
    """Record a PoC run on a profile (SQLite poc_runs table). Kept as a thin
    wrapper — core.run_exploit already logs every run (profile or ad-hoc)."""
    store.record_poc_run(pid, cve_id, params or {}, res)
    return True


def find_profile_by_url(url: str) -> str | None:
    return store.find_profile_by_url(url)


# ---------------------------------------------------------------------------
# PoC command building + bounded execution
# ---------------------------------------------------------------------------
def poc_list() -> dict:
    """Runnable PoC catalog — NATIVE engine specs (poc/ package).

    Each entry is what the scanner will actually do (its working logic), not an
    external command. Enriched with software + CVSS from the CVE database.
    """
    vulns = {v["id"]: v for v in load_vulns()}
    out = {}
    if poc is not None:
        for cid, spec in poc.list_exploits().items():
            v = vulns.get(cid, {})
            out[cid] = {
                "id": cid,
                "software": v.get("software") or spec.get("software"),
                "score": v.get("score", spec.get("score")),
                "name": spec.get("name"),
                "type": spec.get("type"),
                "preauth": spec.get("preauth"),
                "note": spec.get("note"),
                "edb": v.get("edb") or spec.get("edb") or [],
                "inputs": spec.get("inputs") or [],
                "affected": spec.get("affected") or v.get("affected") or [],
                "native": True,
            }
    # fallback: DB panels that still carry a command_template (legacy)
    for v in load_vulns():
        if v["id"] in out:
            continue
        e = v.get("exploit")
        if e and e.get("command_template"):
            out[v["id"]] = {
                "id": v["id"], "software": v.get("software"), "score": v.get("score"),
                "name": e.get("name"), "type": e.get("type"), "preauth": e.get("preauth"),
                "note": e.get("note"), "edb": v.get("edb") or [],
                "inputs": e.get("inputs") or [], "affected": v.get("affected") or [],
                "native": False,
            }
    return out


def run_exploit(cve_id: str, params: dict = None, profile_id: str = None) -> dict:
    """Execute a PoC via the NATIVE engine (scanner sends it itself).

    Every run is logged (SQLite logs table + db/logs.log) and recorded in the
    poc_runs table — with profile_id when run against a saved profile, else as
    an ad-hoc run (profile_id NULL).
    """
    log("INFO", "poc", f"PoC {cve_id} basladi", {"cve": cve_id, "params": params or {}})
    if poc is None:
        res = {"ok": False, "success": False, "cve": cve_id,
               "error": f"native PoC engine yuklenemedi: {_POC_IMPORT_ERROR}"}
    else:
        try:
            res = poc.run_exploit(cve_id, params or {})
        except Exception as e:
            res = {"ok": False, "success": False, "cve": cve_id, "error": str(e)}
    success = bool(res.get("success"))
    if success:
        msg = f"PoC {cve_id} -> BASARILI (kanit alindi)"
    elif res.get("error"):
        msg = f"PoC {cve_id} -> hata: {res.get('error')}"
    else:
        msg = f"PoC {cve_id} -> basarisiz / hedef tetiklenmedi"
    log("SUCCESS" if success else "ERROR", "poc", msg,
        {"cve": cve_id, "success": success, "evidence": (res.get("evidence") or "")[:300]})
    store.record_poc_run(profile_id, cve_id, params or {}, res)
    return res


def build_command(cve_id: str, params: dict) -> str:
    """Legacy komut-sablonu ureticisi (yalnizca db/exploits.json'daki eski paneller icin).

    v2 native motor (poc/ paketi) komut satiri URETMEZ — exploit'i scanner'in
    kendisi socket/HTTP seviyesinde dogrudan calistirir (`run_exploit`). Bu fonksiyon
    yalnizca `command_template` tasiyan legacy CVE panelleri icin geriye donuk
    uyumluluk amaciyla korunmustur ve sablonu `db/exploits.json` uzerinden cozer.

    Duzeltme (2026-11-05): eski surum `poc_list()` ciktisinda bulunmayan
    `command_template` alanina eristigi icin her cagrida KeyError ile patliyordu;
    artik dogru kaynaga (exploit paneli) bakiyor ve PoC'suz CVE icin net hata veriyor.

    Args:
        cve_id: Komut sablonu cozulecek CVE kimligi (orn. "CVE-2024-56201").
        params: Sablondaki `{anahtar}` yer tutucularina doldurulacak kullanici
                parametreleri; eksik anahtarlar input'un `default` degeriyle dolar.

    Returns:
        Yer tutuculari doldurulmus, `run_command()`-uyumlu tek satirlik komut.

    Raises:
        ValueError: CVE icin exploit paneli/sablon tanimli degilse.
    """
    panel = load_exploits().get(cve_id)
    if not panel or not panel.get("command_template"):
        raise ValueError(f"{cve_id} icin command_template iceren bir exploit paneli yok "
                         f"(native PoC varsa dogrudan run_exploit kullanin)")
    cmd = panel["command_template"]
    # Eksik parametreleri panelin varsayilanlariyla doldur — UI formunu bos birakan
    # alanlarin sablonda `{key}` olarak kalmasini engeller.
    filled = dict(params or {})
    for inp in panel.get("inputs") or []:
        k = inp.get("key")
        if k and (k not in filled or filled[k] in (None, "")):
            filled[k] = inp.get("default", "")
    for k, val in filled.items():
        cmd = cmd.replace("{" + k + "}", str(val))
    return cmd


def run_command(cmd: str, timeout: int = MAX_RUN) -> dict:
    """Sinirli (allow-list'li) yerel komut yurutucu — legacy `/run` ucu.

    Guvenlik modeli: ilk gercek token (ENV=val atamalari atlanir) ALLOWED_BIN
    beyaz listesinde olmalidir; calisma suresi `timeout` ile sinirlidir; cikti
    20 KB ile sinirlandirilir. Bu genel bir shell DEGILDIR — salt operatorun
    yetkili oldugu PoC/kesif araclarina kapali bir koprudur.

    Not: v2 native motor bu yolu kullanmaz (`run_exploit` → poc/ paketi); burasi
    yalnizca `command_template` tabanli legacy PoC'lar ve MCP `build_poc_command`
    akisi icin tutulur.

    Args:
        cmd: Yurutulecek komut satiri (beyaz liste kontrolu burada yapilir).
        timeout: Saniye cinsinden ust sinir (varsayilan MAX_RUN=180).

    Returns:
        Basarida {"ok": True, "exit", "stdout", "stderr"}; hatada {"ok": False,
        "error": aciklama}. Asla istisna firlatmaz — HTTP katmani icin guvenli.
    """
    cmd = (cmd or "").strip()
    if not cmd:
        return {"ok": False, "error": "empty command"}
    try:
        toks = shlex.split(cmd)
    except ValueError as e:
        return {"ok": False, "error": f"parse: {e}"}
    # ENV=value bicimindeki onek atamalarini atlayarak ilk gercek binary'i bul
    first = None
    for t in toks:
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):  # leading ENV=val
            continue
        first = t
        break
    if first is None:
        return {"ok": False, "error": "binary bulunamadi"}
    base = os.path.basename(first)
    if base not in ALLOWED_BIN:
        return {"ok": False,
                "error": f"'{base}' izinli listede degil (izinli: {', '.join(sorted(ALLOWED_BIN))})"}
    try:
        r = subprocess.run(cmd, shell=True, cwd=HERE, capture_output=True, timeout=timeout)
        return {
            "ok": True,
            "exit": r.returncode,
            "stdout": r.stdout.decode("utf-8", "replace")[:20000],
            "stderr": r.stderr.decode("utf-8", "replace")[:20000],
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout >{timeout}s"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------------------------------------------------------------------
# report generation
# ---------------------------------------------------------------------------
def build_report(prof: dict, fmt: str = "md") -> tuple:
    scan = prof.get("scan") or {}
    risk = prof.get("risk") or {}
    fp = scan.get("fingerprint") or {}
    slug = re.sub(r"[^a-z0-9]+", "-", (prof.get("name") or "target").lower()).strip("-")
    stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())

    if fmt == "json":
        fname = f"{slug}_risk_{stamp}.json"
        return json.dumps(prof, ensure_ascii=False, indent=2), fname

    L = []
    L.append(f"# Risk Raporu — {prof.get('name')}")
    L.append("")
    L.append(f"- **Hedef:** `{prof.get('url')}`")
    L.append(f"- **Olusturuldu:** {prof.get('created_at')}")
    L.append(f"- **Risk:** **{risk.get('score')}/100** — {risk.get('grade')} ({risk.get('letter')})")
    L.append(f"- **CVE:** {risk.get('n_cve')} eslesme · {risk.get('n_poc')} PoC · {risk.get('n_preauth')} pre-auth")
    L.append("")
    L.append("## Fingerprint")
    L.append("")
    L.append("| Alan | Deger |")
    L.append("|---|---|")
    for k in ("status", "ttfb_ms", "php_version", "webserver", "webserver_version",
              "os_hint", "sapi", "server_header", "x_powered_by"):
        v = fp.get(k)
        L.append(f"| {k} | {v if v not in (None, '', []) else '—'} |")
    L.append(f"| WAF | {', '.join(fp.get('waf') or []) or 'yok'} |")
    L.append(f"| Acik portlar | {', '.join(str(p) for p in fp.get('open_ports') or []) or '—'} |")
    L.append("")

    if scan.get("waf", {}).get("present"):
        waf = scan["waf"]
        L.append("## WAF")
        L.append(f"- {', '.join(waf.get('names') or [])} — {waf.get('challenge_note', '')}")
        L.append("")

    if scan.get("ports"):
        L.append("## Acik Portlar")
        L.append("")
        L.append("| Port | Servis | Surum |")
        L.append("|---|---|---|")
        for p in scan["ports"]:
            L.append(f"| {p['port']} | {p['service']} | {p.get('version') or '—'} |")
        L.append("")

    if scan.get("tls", {}).get("ok"):
        t = scan["tls"]
        L.append("## TLS")
        L.append(f"- Protocol: {t.get('protocol')}")
        L.append(f"- Cipher: {t.get('cipher', {}).get('name')} ({t.get('cipher', {}).get('tls')}, {t.get('cipher', {}).get('bits')}bit)")
        L.append(f"- Issuer: {t.get('cert', {}).get('issuer')}")
        L.append(f"- CN: {t.get('cert', {}).get('cn')}  SAN: {', '.join(t.get('cert', {}).get('san') or [])}")
        L.append(f"- Expiry: {t.get('cert', {}).get('not_after')} ({t.get('cert', {}).get('days_to_expire')} gun)")
        L.append("")

    if scan.get("headers_audit"):
        L.append("## HTTP Guvenlik Header'lari")
        L.append("")
        L.append("| Header | Durum | Not |")
        L.append("|---|---|---|")
        for h in scan["headers_audit"]:
            L.append(f"| {h['label']} | {'✅' if h['present'] else '❌'} | {h['note']} |")
        L.append("")

    cves = scan.get("cves") or []
    if cves:
        L.append(f"## Eslesen Kritik CVE'ler ({len(cves)})")
        L.append("")
        L.append("| CVE | SW | CVSS | Tip | Pre-auth | PoC | EDB |")
        L.append("|---|---|---|---|---|---|---|")
        for c in cves:
            e = c.get("exploit") or {}
            L.append(
                f"| {c['id']} | {c.get('software')} | {c.get('score')} | {e.get('type', '—')} "
                f"| {'evet' if e.get('preauth') else '—'} | {'evet' if e else '—'} "
                f"| {'; '.join(c.get('edb') or e.get('edb') or []) or '—'} |")
        L.append("")
    else:
        L.append("## Eslesen Kritik CVE'ler")
        L.append("")
        L.append("Tespit edilen surumler icin eslesen kritik CVE bulunamadi.")
        L.append("")

    if risk.get("factors"):
        L.append("## Risk Faktorleri")
        L.append("")
        for f in risk["factors"]:
            L.append(f"- {f['label']}: **{f['delta']}** — {f.get('note','')}")
        L.append("")

    pocres = prof.get("poc_results") or {}
    if pocres:
        L.append("## PoC Sonuclari")
        L.append("")
        for cid, r in pocres.items():
            L.append(f"### {cid}")
            L.append(f"- exit={r.get('exit')} @ {r.get('at')}")
            if r.get("stdout"):
                L.append("```")
                L.append(r["stdout"].strip())
                L.append("```")
            if r.get("stderr"):
                L.append("stderr:")
                L.append("```")
                L.append(r["stderr"].strip())
                L.append("```")
            L.append("")

    L.append("")
    L.append("---")
    L.append("_Yetkili guvenlik arastirmasi · P2S CVE Scanner · " + now_iso() + "_")
    return "\n".join(L), f"{slug}_risk_{stamp}.md"


def save_report(prof: dict, fmt: str = "md") -> dict:
    text, fname = build_report(prof, fmt)
    os.makedirs(REPORTS, exist_ok=True)
    path = os.path.join(REPORTS, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return {"path": path, "filename": fname, "bytes": len(text.encode())}
