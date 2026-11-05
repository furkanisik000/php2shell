import os
import subprocess, sys, time, os, struct

BASE = os.path.dirname(os.path.abspath(__file__))
c = "p2s8335"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# create a 2MB file to slow down the upload
sh(f'docker exec {c} sh -c "head -c 2097152 /dev/zero > /tmp/big.txt"')

r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1]
r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
B = int(r.stdout.strip().split("-")[0], 16)
ps_hsv = B + 0x10432a0 + 0x140
print(f"[*] worker={worker_pid} base={hex(B)} ps_hsv={hex(ps_hsv)}", flush=True)

# Start the upload in the background (large file keeps session active)
up = subprocess.Popen(
    f'docker exec {c} sh -c "curl -s -o /dev/null -F \'PHPSESSID=abc123\' -F \'PHP_SESSION_UPLOAD_PROGRESS=pwn\' -F \'file=@/tmp/big.txt\' http://127.0.0.1/index.php"',
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)

# Read PS(http_session_vars) via /proc/pid/mem while upload is in progress
def read_mem(addr, size):
    skip = addr
    r = subprocess.run(
        f'docker exec {c} sh -c "dd if=/proc/{worker_pid}/mem bs=1 skip={skip} count={size} 2>/dev/null"',
        shell=True, capture_output=True
    )
    return r.stdout

# poll a few times
results = []
for i in range(12):
    time.sleep(0.4)
    try:
        data = read_mem(ps_hsv, 16)
    except Exception as e:
        break
    if len(data) >= 16:
        val = struct.unpack("<Q", data[:8])[0]
        tinfo = struct.unpack("<I", data[8:12])[0]
        results.append((i, hex(val), hex(tinfo)))
        print(f"  poll {i}: R={hex(val)} type_info={hex(tinfo)}", flush=True)

up.kill(); up.wait()

print("\n=== summary ===", flush=True)
for i, v, t in results:
    print(f"  poll {i}: R={v} type_info={t}", flush=True)
