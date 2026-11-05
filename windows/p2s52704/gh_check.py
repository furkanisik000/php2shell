#!/usr/bin/env python3
"""Check GitHub for php2shell repos (new work, esp. sub-8.3 leak)."""
import json, urllib.request, time

def search(q, n=15):
    url = ("https://api.github.com/search/repositories?q=%s&sort=updated&per_page=%d"
           % (urllib.parse.quote(q), n))
    req = urllib.request.Request(url, headers={"User-Agent": "p2s",
          "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    items = data.get("items", [])
    print(f"\n### query={q!r} count={data.get('total_count')}")
    for it in items:
        print(f"  {it['full_name']:<45} upd={it.get('pushed_at','')[:10]} "
              f"stars={it.get('stargazers_count')}")
        d = (it.get("description") or "")[:90]
        if d:
            print(f"      {d}")
    return items

import urllib.parse
search("php2shell")
search("php2shell 8.2 OR 8.3 OR leak")
search("CVE-2026-109618")
