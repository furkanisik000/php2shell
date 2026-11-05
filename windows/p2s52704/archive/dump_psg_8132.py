import subprocess, time, struct

c = "p2s8132"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def read_mem(pid, addr, size):
    r = subprocess.run(
        f'docker exec {c} sh -c "dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"',
        shell=True, capture_output=True
    )
    return r.stdout

# libphp base from master (inherited by worker); ps_globals offset for 8.1.32
B = 0x752c40d0f000
ps_base = B + 0xef1a60
print(f"[*] libphp=0x{B:x} ps_base=0x{ps_base:x} ({ps_base})", flush=True)

worker_pid = 20
data = read_mem(worker_pid, ps_base, 0x200)
if len(data) < 0x200:
    print(f"[!] Could not read ps_globals (got {len(data)} bytes)", flush=True)
else:
    words = struct.unpack("<128Q", data)
    print(f"\n=== ps_globals dump (8.1.32, idle) ===", flush=True)
    for off in range(0, 0x200, 8):
        w = words[off // 8]
        marker = ""
        if w == 0:
            marker = "  <- zero"
        elif 0x700000000000 < w < 0x800000000000:
            if B <= w < B + 0x2000000:
                marker = f"  <- libphp+{w-B:#x}"
            else:
                marker = "  <- heap/other ptr"
        elif w in (1, 2, 3, 7, 0x1A, 0x10, 0x106, 0x307, 100, 1440, 180, 25):
            marker = f"  <- small {w}"
        print(f"  +{off:04x}: 0x{w:016x}{marker}", flush=True)

# Look for a zval pair (heap value, IS_REFERENCE-ish type_info)
print(f"\n=== candidate http_session_vars (value=heap, type has IS_REFERENCE) ===", flush=True)
for off in range(0, 0x200 - 16, 8):
    val = words[off // 8]
    tinfo = words[(off // 8) + 1]
    t = tinfo & 0x1F
    if 0x700000000000 < val < 0x800000000000 and (t == 0x0a or t == 0x10):
        print(f"  +{off:04x}: value=0x{val:x} type_info=0x{tinfo:04x} (type={t})", flush=True)
print(f"\n[*] Done.", flush=True)
