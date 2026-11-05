#!/usr/bin/env python3
"""Diagnose network reachability: is the 192.168.8.1 gateway intercepting everything?"""
import ssl, urllib.request, socket

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def probe(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "p2s"})
        r = urllib.request.urlopen(req, timeout=15, context=ctx)
        final = r.geturl()
        data = r.read(200)
        print(f"  {url}\n    -> {r.status} final={final}\n    first-200B={data[:120]!r}")
    except Exception as e:
        print(f"  {url}\n    -> ERR {e}")

for u in [
    "https://raw.githubusercontent.com/dismasa0305/php2shell/HEAD/README.md",
    "https://api.github.com/rate_limit",
    "https://www.google.com",
    "https://192.168.8.1/html/index.html",
]:
    probe(u)
print("done")
