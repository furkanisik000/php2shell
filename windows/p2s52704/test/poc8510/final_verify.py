#!/usr/bin/env python3
"""Final smoke test: the 4 RCE-verified versions with the current deliverable."""
import os
import subprocess, sys
POC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test", "poc8335", "php2shell.py")
WORKING = [("8.3.33", 18124), ("8.3.35", 18112), ("8.4.26", 18113), ("8.5.11", 18114)]

for ver, port in WORKING:
    r = subprocess.run([sys.executable, POC, "-t", "http://127.0.0.1:%d" % port,
                        "-v", ver, "--attempts", "2"],
                       capture_output=True, text=True, timeout=180)
    out = (r.stdout + r.stderr).strip().splitlines()
    ok = any("RCE PROVEN" in l for l in out)
    line = [l for l in out if "RCE PROVEN" in l or "not reached" in l]
    print("%-7s -> %s   %s" % (ver, "RCE OK" if ok else "FAIL", line[-1].strip() if line else ""), flush=True)
print("DONE")
