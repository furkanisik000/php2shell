"""Find the exact per-field size limit on 7.4.33's multipart parser."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18108/postdump.php"
t = E.Target(URL, timeout=90.0, verbose=False)

for mb in [1.0, 1.2, 1.5, 1.8, 2.0]:
    size = int(mb * 1024 * 1024)
    parts = [
        {"name": "big", "data": b"B" * size},
        {"name": "a", "data": b"x"},
    ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
        idx = resp.find(b"\r\n\r\n")
        body_only = resp[idx+4:] if idx >= 0 else b""
        stored = b"big=" in body_only
        print(f"{mb}MB ({size}B): stored={stored} body={body_only[:60]!r}", flush=True)
    except Exception as e:
        print(f"{mb}MB: EXC {e}", flush=True)
    time.sleep(0.3)
