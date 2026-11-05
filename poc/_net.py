"""poc/_net.py — shared low-level network primitives for the native PoC engine.

No external binaries: the scanner opens sockets and speaks the protocols itself.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.parse


def parse_target(url: str, default_port=None) -> dict:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        url = "http://" + url
        u = urllib.parse.urlsplit(url)
    scheme = u.scheme
    host = u.hostname or "127.0.0.1"
    port = u.port or (default_port or (443 if scheme == "https" else 80))
    return {
        "scheme": scheme, "host": host, "port": port,
        "path": u.path or "/", "tls": scheme == "https",
    }


def _connect(host: str, port: int, tls: bool, timeout: float) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    return s


def http(method: str, host: str, port: int, path: str, headers: dict = None,
         body: bytes = b"", timeout: float = 12.0, tls: bool = False,
         read_cap: int = 1 << 20) -> dict:
    """One raw HTTP/1.1 request (works for http + https). Returns status/headers/body."""
    hdr = f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    for k, v in (headers or {}).items():
        hdr += f"{k}: {v}\r\n"
    if body:
        hdr += f"Content-Length: {len(body)}\r\n"
    hdr += "Connection: close\r\n\r\n"

    s = _connect(host, port, tls, timeout)
    try:
        s.sendall(hdr.encode())
        if body:
            mv = memoryview(body)
            for off in range(0, len(body), 262144):
                s.sendall(mv[off:off + 262144])
        data = bytearray()
        s.settimeout(timeout)
        while len(data) < read_cap:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass

    raw = bytes(data)
    head, _, body_b = raw.partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    status = int(m.group(1)) if m else 0
    hd = {}
    for line in head.split(b"\r\n"):
        if b":" in line:
            k, v = line.split(b":", 1)
            hd[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
    return {"status": status, "headers": hd, "body": body_b, "raw": raw}
