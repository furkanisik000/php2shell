import sys, urllib.request, urllib.error

URL = sys.argv[1] if len(sys.argv) > 1 else "https://attackit.co.il/files/php/info.php"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

req = urllib.request.Request(URL, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
try:
    r = urllib.request.urlopen(req, timeout=30)
    body = r.read(4096)
    print("STATUS:", r.status)
    for k, v in r.headers.items():
        print(f"  {k}: {v}")
    print("BODY (first 2KB):")
    print(body.decode("utf-8", "replace")[:2048])
except urllib.error.HTTPError as e:
    body = e.read(4096) if hasattr(e, "read") else b""
    print("HTTP ERROR:", e.code, e.reason)
    for k, v in (e.headers or {}).items():
        print(f"  {k}: {v}")
    print("BODY (first 2KB):")
    print(body.decode("utf-8", "replace")[:2048])
except Exception as e:
    print("EXC:", type(e).__name__, e)
