"""Test if 7.4.33 stores medium fields in $_POST (4MB, under the 8M limit)."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18108/postdump.php"
t = E.Target(URL, timeout=90.0, verbose=False)

for mb in [1, 2, 4, 6]:
    parts = [
        {"name": "big", "data": b"B" * (mb * 1024 * 1024)},
        {"name": "a", "data": b"x"},
    ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
        # Extract the body (after headers)
        idx = resp.find(b"\r\n\r\n")
        body_only = resp[idx+4:] if idx >= 0 else b""
        print(f"{mb}MB: body={body_only!r}", flush=True)
    except Exception as e:
        print(f"{mb}MB: EXC {e}", flush=True)
    time.sleep(0.3)
