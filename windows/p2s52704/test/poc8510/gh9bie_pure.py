#!/usr/bin/env python3
"""Fetch 9bie pure/ stage-3 scripts (fake_ref_b, cheap_oom_a, mk_ht)."""
import os
import urllib.request

BASE = "https://raw.githubusercontent.com/9bie/php2shell-bypass-aslr-exp/main/"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test", "poc8510")
for name in ["pure/fake_ref_b.py", "pure/cheap_oom_a.py", "pure/mk_ht.py",
             "pure/pwn_pure.py", "pure/mk_b_min.py"]:
    fn = name.split("/")[-1]
    try:
        req = urllib.request.Request(BASE + name, headers={"User-Agent": "p2s"})
        data = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
        open(OUT + "\\" + fn, "w", encoding="utf-8").write(data)
        print("OK %-18s %5d lines" % (fn, len(data.splitlines())))
    except Exception as e:
        print("ERR %-18s %s" % (fn, e))
