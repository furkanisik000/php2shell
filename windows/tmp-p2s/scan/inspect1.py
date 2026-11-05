import os
import json, io, os
D = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s", "scan")
p = os.path.join(D, "trees_summary.json")
print("exists:", os.path.exists(p), "size:", os.path.getsize(p) if os.path.exists(p) else "-")
s = json.load(io.open(p, encoding="utf-8"))
print("keys:", list(s.keys()))
for k, v in s.items():
    if "dinosn" in k:
        hits = [e[0] for e in v if "php72" in e[0] or "tools/" in e[0]]
        print("DINOSN php72/tools hits:", len(hits))
        for h in hits[:60]:
            print("  ", h)
# also full dinosn docs+tools listing
for k, v in s.items():
    if "dinosn" in k:
        print("--- dinosn docs/ + e2e/ + top files ---")
        for e in v:
            if e[0].startswith("docs/") or e[0].startswith("e2e/") or "/" not in e[0]:
                print("  ", e[2], e[1], e[0])
