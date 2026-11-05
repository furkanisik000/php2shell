#!/usr/bin/env python3
"""Research the '*2Shell' wave (Node2Shell/HTTP2Shell/Python2Shell/React2Shell) on GitHub."""
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
        print(f"\n### {q!r} ERR {e}"); return
    items = data.get("items", [])
    print(f"\n### {q!r} count={data.get('total_count')}")
    for it in items:
        print(f"  {it['full_name']:<45} upd={(it.get('pushed_at') or '')[:10]} s={it.get('stargazers_count')}")
        d = (it.get("description") or "")[:95]
        if d: print(f"      {d}")

for q in [
    "Node2Shell",
    "HTTP2Shell",
    "Python2Shell",
    "React2Shell",
    "Log4Shell Spring4Shell Text4Shell",
    "Brotli RCE exploit 2026",
    "Node.js RCE 2026",
    "Spring4Shell CVE-2022-22963",
    "Text4Shell CVE-2022-42889",
]:
    search(q)
