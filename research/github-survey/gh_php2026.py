#!/usr/bin/env python3
"""Search GitHub for OTHER PHP RCEs in the Oct 2026 wave (besides php2shell)."""
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
    "PHP RCE CVE-2026 exploit",
    "PHP 8.2 8.3 RCE 2026",
    "PHP heap leak 2026 exploit",
    "PHP OOM use-after-free 2026",
    "PHP arbitrary write 2026",
    "PHP 7.4 8.0 RCE exploit 2025 2026",
    "php-cve-2026-1",
    "PHP 0day 2026 RCE",
]:
    search(q)
