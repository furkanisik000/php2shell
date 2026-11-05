#!/usr/bin/env python3
"""Retry git/trees until it works, print all files (esp .json / profile)."""
import json, urllib.request, time

REPO = "dismasa0305/php2shell"
url = f"https://api.github.com/repos/{REPO}/git/trees/HEAD?recursive=1"
for i in range(8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "p2s",
             "Accept": "application/vnd.github+json"})
        d = json.load(urllib.request.urlopen(req, timeout=40))
        files = [t["path"] for t in d.get("tree", []) if t["type"] == "blob"]
        print(f"OK attempt {i}: {len(files)} files")
        print("ALL FILES:")
        for f in files: print("  " + f)
        print("JSON/PROFILE FILES:")
        for f in files:
            if "json" in f.lower() or "profile" in f.lower() or "registry" in f.lower():
                print("  * " + f)
        break
    except Exception as e:
        print(f"  attempt {i} fail: {e}")
        time.sleep(6)
