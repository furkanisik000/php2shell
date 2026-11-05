#!/usr/bin/env python3
"""Fetch the file tree + key files from a GitHub repo."""
import os
import json, sys, urllib.request, os

OUT = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s")
os.makedirs(OUT, exist_ok=True)

def api(url):
    req = urllib.request.Request(url, headers={"User-Agent": "p2s",
          "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)

def raw(url):
    req = urllib.request.Request(url, headers={"User-Agent": "p2s"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.read()

def fetch(repo, maxfiles=16, maxbytes=200_000):
    print(f"\n===== {repo} =====")
    try:
        d = api(f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1")
        files = [t["path"] for t in d.get("tree", []) if t["type"] == "blob"]
    except Exception as e:
        print(f"  tree failed: {e}"); return
    kw = ["exploit", "leak", "poc", "oom", "ghost", "bucket", "stage", "readme",
          "mk_", "send", "spray", "fake", "8.2", "8.3", "5.6", "5.4", "7.4", "chain", "core",
          "profile", "json", "registry", "layout"]
    picked = [f for f in files if any(k in f.lower() for k in kw)]
    picked = (picked or files)[:maxfiles]
    print(f"  files({len(files)}): {files[:30]}")
    for f in picked:
        try:
            data = raw(f"https://raw.githubusercontent.com/{repo}/HEAD/{f}")
            if len(data) > maxbytes:
                data = data[:maxbytes] + b"\n...[truncated]"
            outp = os.path.join(OUT, "ghn_" + f.replace("/", "_"))
            with open(outp, "wb") as fh:
                fh.write(data)
            print(f"  saved {f} -> {len(data)}B")
        except Exception as e:
            print(f"  skip {f}: {e}")

for repo in sys.argv[1:]:
    fetch(repo)
