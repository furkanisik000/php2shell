#!/usr/bin/env python3
"""Research: composable PHP vulns (leak / arbitrary-write / RCE) in 5.6-8.2."""
import json, urllib.request, urllib.parse

def search(q, n=10):
    url = ("https://api.github.com/search/repositories?q=%s&sort=updated&per_page=%d"
           % (urllib.parse.quote(q), n))
    req = urllib.request.Request(url, headers={"User-Agent": "p2s",
          "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception as e:
        print(f"\n### query={q!r} ERROR {e}"); return
    items = data.get("items", [])
    print(f"\n### query={q!r} count={data.get('total_count')}")
    for it in items:
        print(f"  {it['full_name']:<45} upd={(it.get('pushed_at') or '')[:10]} "
              f"s={it.get('stargazers_count')}")
        d = (it.get("description") or "")[:95]
        if d: print(f"      {d}")

for q in [
    "PHP RCE 8.1 OR 8.2 exploit 2025",
    "PHP heap leak arbitrary write",
    "PHP use-after-free RCE 8.0 8.1",
    "PHP type confusion RCE",
    "PHP session deserialization RCE",
    "PHP 7.4 RCE exploit 2024 2025",
    "php-cve-2026",
    "PHP OOM UAF exploit",
]:
    search(q)
