#!/usr/bin/env python3
"""Test whether a basic session (upload_progress, fresh id) starts on a port
and produces a Set-Cookie. Isolates SID issue vs session-not-starting."""
import socket, re, sys

PORT = int(sys.argv[1])
body = (b'--BB\r\nContent-Disposition: form-data; '
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nk0\r\n--BB--\r\n')
req = (b'POST /index.php HTTP/1.1\r\nHost: x\r\n'
       b'Content-Type: multipart/form-data; boundary=BB\r\nContent-Length: '
       + str(len(body)).encode() + b'\r\n\r\n' + body)
s = socket.create_connection(('127.0.0.1', PORT), timeout=15)
s.sendall(req)
resp = b""
while True:
    c = s.recv(65536)
    if not c:
        break
    resp += c
s.close()
cookies = re.findall(rb"Set-Cookie: ([^\r\n]*)", resp)
status = resp.split(b"\r\n", 1)[0]
print(f"port={PORT} status: {status!r}", flush=True)
print(f"  Set-Cookie count: {len(cookies)}", flush=True)
for c in cookies:
    print(f"    {c[:60]!r}", flush=True)
