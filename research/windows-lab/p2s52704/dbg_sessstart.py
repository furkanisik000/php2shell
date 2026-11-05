#!/usr/bin/env python3
"""Direct diagnostic: does a simple rfc1867 request (PHPSESSID + progress + file, NO OOM)
start a session and send a Set-Cookie on this version? Compares 8.2.34 vs 8.3.35.
Also queries session_status via a PHP page.
"""
import http.client, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18111

def req(body, ct):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
    c.putrequest("POST", "/", skip_host=True)
    c.putheader("Content-Type", ct)
    c.putheader("Content-Length", str(len(body)))
    c.endheaders(); c.send(body)
    r = c.getresponse(); d = r.read(); hdrs = dict((k.lower(), v) for k, v in r.getheaders())
    c.close(); return r.status, d, hdrs

def cookie(hdrs):
    v = hdrs.get("set-cookie", "")
    return v

# Test 1: simple rfc1867 (multipart) with 19-char PHPSESSID + progress + file
bd = "----b"
body = (
    f"--{bd}\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\nattacksessionid0001\r\n"
    f"--{bd}\r\nContent-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\npwn\r\n"
    f"--{bd}\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    "A" * 1000 +
    f"\r\n--{bd}--\r\n"
).encode()
st, d, h = req(body, "multipart/form-data; boundary=" + bd)
print(f"  [T1 multipart rfc1867, 19-char SID] status={st} set-cookie={cookie(h)!r} body={d[:80]!r}", flush=True)

# Test 2: query the session state via a PHP page
c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=30)
c.request("GET", "/sess_chk.php")
r = c.getresponse(); print(f"  [T2 /sess_chk.php] {r.status} {r.read()[:200]!r}", flush=True)
c.close()
