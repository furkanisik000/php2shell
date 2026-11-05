#!/usr/bin/env python3
"""Fetch the 9bie upstream exploit.py (what devploit runs) to read its carrier stage-3 params."""
import json, urllib.request

def gh(url):
    req = urllib.request.Request(url, headers={"User-Agent": "p2s", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")

# 1) repo tree
try:
    tree = json.loads(gh("https://api.github.com/repos/9bie/php2shell-bypass-aslr-exp/git/trees/main?recursive=1"))
    print("=== 9bie repo files ===")
    for t in tree.get("tree", []):
        if t["type"] == "blob":
            print("  ", t["path"])
except Exception as e:
    print("tree err:", e)
