import subprocess, time, struct

c = "p2s8234"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def read_mem(pid, addr, size):
    r = subprocess.run(
        f'docker exec {c} sh -c "dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"',
        shell=True, capture_output=True
    )
    return r.stdout

# Get worker and libphp base
r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
worker_pid = pids[-1]
r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
B = int(r.stdout.strip().split("-")[0], 16)
ps_base = B + 0xf3a120  # ps_globals offset for 8.2.34
print(f"[*] worker={worker_pid} libphp=0x{B:x} ps_base=0x{ps_base:x}", flush=True)

# Start upload
up = subprocess.Popen(
    f'docker exec {c} sh -c "curl -s -o /dev/null -F \'PHPSESSID=abc123\' -F \'PHP_SESSION_UPLOAD_PROGRESS=pwn\' -F \'file=@/tmp/big.txt\' http://127.0.0.1/index.php"',
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
)

# Dump ps_globals (0x100 bytes = 32 qwords)
time.sleep(1.5)
data = read_mem(worker_pid, ps_base, 0x100)
if len(data) < 0x100:
    print(f"[!] Could not read ps_globals (got {len(data)} bytes)", flush=True)
    up.kill(); up.wait()
else:
    words = struct.unpack("<32Q", data)
    print(f"\n=== ps_globals dump (8.2.34, active upload) ===", flush=True)
    for off in range(0, 0x100, 8):
        w = words[off // 8]
        marker = ""
        if w == 0:
            marker = "  <- zero"
        elif 0x700000000000 < w < 0x800000000000:
            if B <= w < B + 0x2000000:
                marker = f"  <- libphp+{w-B:#x}"
            else:
                marker = "  <- heap ptr"
        elif w in (0, 1, 2, 3, 7, 0x1A, 0x10, 1000):
            marker = f"  <- small {w}"
        print(f"  +{off:04x}: 0x{w:016x}{marker}", flush=True)

up.kill(); up.wait()
print(f"\n[*] Done.", flush=True)
