#!/usr/bin/env python3
"""List available php 8.3.x / 8.4.x / 8.5.x -apache tags on Docker Hub."""
import json, re, urllib.request

url = "https://hub.docker.com/v2/repositories/library/php/tags/?page_size=100"
all_tags = []
page = 1
while page < 12:
    u = url + "&page=%d" % page
    req = urllib.request.Request(u, headers={"User-Agent": "p2s"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception as e:
        print("page %d err: %s" % (page, e)); break
    results = data.get("results", [])
    if not results: break
    all_tags.extend(results)
    if not data.get("next"): break
    page += 1

def series(t):
    m = re.match(r"^(8\.[345]\.\d+)-apache$", t.get("name",""))
    return m.group(1) if m else None

by_series = {"8.3": [], "8.4": [], "8.5": []}
for t in all_tags:
    s = series(t)
    if not s: continue
    key = s[:3]
    by_series.setdefault(key, []).append(s)

for k in sorted(by_series, reverse=True):
    vers = sorted(set(by_series[k]), key=lambda v: [int(x) for x in v.split(".")])
    print("\n=== php %s.x (-apache)  [%d] ===" % (k[2], len(vers)))
    print("  " + ", ".join(vers))
