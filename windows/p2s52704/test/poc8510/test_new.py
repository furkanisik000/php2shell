#!/usr/bin/env python3
"""Test the 4 NEW versions (8.5.9, 8.4.24, 8.4.25, 8.3.33) with the default htdata/s_off."""
import subprocess, time, sys

NEW = [
    ("8.5.9",  18121),
    ("8.4.24", 18122),
    ("8.4.25", 18123),
    ("8.3.33", 18124),
]
POC = r"C:\Users\likat\p2s52704\test\poc8335\php2shell.py"

for ver, port in NEW:
    t0 = time.time()
    r = subprocess.run([sys.executable, POC,
                        "-t", "http://127.0.0.1:%d" % port,
                        "-v", ver, "--attempts", "3"],
                       capture_output=True, text=True, timeout=180)
    out = (r.stdout + r.stderr).strip().splitlines()
    ok = any("RCE PROVEN" in l for l in out)
    last = out[-3:] if out else []
    print("=== %s (port %d)  %s  %4.1fs ===" % (ver, port, "RCE OK" if ok else "FAIL", time.time()-t0), flush=True)
    for l in last:
        print("   ", l, flush=True)
    print(flush=True)
print("DONE")
