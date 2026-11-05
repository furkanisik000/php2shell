"""Send a multipart POST with a 12MB big field to postdump.php on 7.4.33, see if it's stored."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18108/postdump.php"
t = E.Target(URL, timeout=90.0, verbose=False)

# Big field FIRST (within max_input_vars limit), + 2 small fields
parts = [
    {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    {"name": "a", "data": b"x"},
    {"name": "b", "data": b"y"},
]
body = E.build_multipart(parts, b"S" * 17)
resp = t.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
print(resp.decode(errors="replace"), flush=True)
