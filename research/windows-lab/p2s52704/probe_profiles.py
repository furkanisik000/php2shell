#!/usr/bin/env python3
"""Probe likely paths for dimasa0305 profiles.json via raw.githubusercontent (works)."""
import os
import urllib.request, os

REPO = "dismasa0305/php2shell"
OUT = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s")
cands = ["profiles.json", "registry/profiles.json", "profiles/registry.json",
         "data/profiles.json", "config/profiles.json", "profile.json",
         "registry.json", "profiles/official.json", "profiles/debian.json",
         "registry.json", "profiles.json"]
seen = []
for p in cands:
    if p in seen: continue
    seen.append(p)
    url = f"https://raw.githubusercontent.com/{REPO}/HEAD/{p}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "p2s"})
        data = urllib.request.urlopen(req, timeout=30).read()
        outp = os.path.join(OUT, "ghn_profile_" + p.replace("/", "_"))
        with open(outp, "wb") as fh: fh.write(data)
        print(f"FOUND {p} -> {len(data)}B saved {outp}")
        break
    except Exception as e:
        print(f"  no {p}: {e}")
print("done")
