import os
import json, io, os

D = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s", "scan")
trees = ["xuehuolll_tree.json", "aarsaputra_tree.json", "ikow_tree.json", "barinov_tree.json",
         "dinosn_php_cve_2026_10961x_lab_poc_tree.json", "eness_php2shell_CVE_2026_109618_CVE_2026_109619_PoC_tree.json",
         "3em0_php2shell_tree.json", "mpyw_php_eol_CVE_2026_109618_109619_tree.json",
         "vperetti_php_cve_2026_109618_109619_backports_tree.json", "devploit_php2shell_tree.json",
         "syrex1013_php2shell_tree.json", "xuehuolll_repos.json", "9bie_commits.json"]
out = {}
for f in trees:
    p = os.path.join(D, f)
    raw = json.load(io.open(p, encoding="utf-8"))
    data = raw.get("data")
    if isinstance(data, (bytes, str)) and data.startswith("b'"):
        # data was saved as repr of bytes
        s = data[2:-1].encode("utf-8").decode("unicode_escape") if isinstance(data, str) else None
        data = json.loads(s)
    elif isinstance(data, bytes):
        data = json.loads(data)
    if isinstance(data, dict) and "tree" in data:
        entries = [(t["path"], t.get("size", ""), t["type"]) for t in data["tree"]]
        out[f] = entries
        print("=== " + f + " === (" + str(len(entries)) + " entries)")
        for e in entries:
            print("  " + e[2] + " " + str(e[1]) + " " + e[0])
    elif isinstance(data, list):
        out[f] = [(r.get("full_name"), r.get("description"), r.get("pushed_at")) for r in data]
        print("=== " + f + " === (" + str(len(data)) + " entries)")
        for e in data:
            print("  " + str(e))
    else:
        print("=== " + f + " === type:", type(data), str(data)[:200])
json.dump(out, io.open(os.path.join(D, "trees_summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print("saved trees_summary.json")
