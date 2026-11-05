import os
import json, time, urllib.request, urllib.parse, os

BASE = "https://api.github.com"
HDRS = {
    "User-Agent": "p2s-research-scan/1.0 (authorized lab research)",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
OUT = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s", "scan")

def fetch(url, tag):
    req = urllib.request.Request(url, headers=HDRS)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
            meta = {"status": r.status, "remaining": r.headers.get("X-RateLimit-Remaining")}
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            data = json.loads(body)
        except Exception:
            data = str(body)[:500]
        meta = {"status": e.code, "body": str(data)[:500]}
    except Exception as e:
        data = str(e)
        meta = {"status": "exc", "err": str(e)}
    obj = {"meta": meta, "data": data}
    with open(f"{OUT}/{tag}.json", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1, default=str)
    print(f"{tag}: {meta.get('status')} rem={meta.get('remaining')}")
    return data

# --- advisories by cve_id ---
for cve in ["CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"]:
    d = fetch(BASE + f"/advisories?cve_id={cve}", "adv_" + cve.lower())
    if isinstance(d, list):
        for a in d:
            print(f"   ADV: {a.get('ghsa_id')} {a.get('cve_id')} | {str(a.get('summary'))[:120]}")
            print(f"        affected: {json.dumps(a.get('vulnerabilities', []))[:300]}")
            print(f"        cwes: {a.get('cwes')}")
    time.sleep(1)

# --- 9bie repo deep-dive ---
fetch(BASE + "/repos/9bie/php2shell-bypass-aslr-exp", "9bie_repo")
fetch(BASE + "/repos/9bie/php2shell-bypass-aslr-exp/commits?per_page=15", "9bie_commits")
fetch(BASE + "/repos/9bie/php2shell-bypass-aslr-exp/git/trees/HEAD?recursive=1", "9bie_tree")
time.sleep(1)

# --- xuehuolll ---
fetch(BASE + "/users/xuehuolll", "xuehuolll_user")
fetch(BASE + "/users/xuehuolll/repos?per_page=100", "xuehuolll_repos")
time.sleep(1)
d = fetch(BASE + "/repos/xuehuolll/php2shell-CVE-2026-109618-109619", "xuehuolll_repo")
if isinstance(d, dict):
    print("xuehuolll repo:", d.get("full_name"), "| pushed:", d.get("pushed_at"), "| desc:", d.get("description"))
fetch(BASE + "/repos/xuehuolll/php2shell-CVE-2026-109618-109619/git/trees/HEAD?recursive=1", "xuehuolll_tree")
time.sleep(1)

# --- aarsaputra (claims 5.4-8.4.26) ---
fetch(BASE + "/repos/aarsaputra/php2shell", "aarsaputra_repo")
fetch(BASE + "/repos/aarsaputra/php2shell/git/trees/HEAD?recursive=1", "aarsaputra_tree")
time.sleep(1)

# --- ikow ---
fetch(BASE + "/repos/ikow/php2shell-poc", "ikow_repo")
fetch(BASE + "/repos/ikow/php2shell-poc/git/trees/HEAD?recursive=1", "ikow_tree")
time.sleep(1)

# --- Anton-Barinov patches (EOL 5.4-8.1) ---
fetch(BASE + "/repos/Anton-Barinov/php2shell-patches", "barinov_repo")
fetch(BASE + "/repos/Anton-Barinov/php2shell-patches/git/trees/HEAD?recursive=1", "barinov_tree")
time.sleep(1)

# --- dinosn / eness / 3em0 / mpyw / vperetti / devploit / syrex1013 ---
for owner, repo in [
    ("dinosn", "php-cve-2026-10961x-lab-poc"),
    ("eness", "php2shell-CVE-2026-109618-CVE-2026-109619-PoC"),
    ("3em0", "php2shell"),
    ("mpyw", "php-eol-CVE-2026-109618-109619"),
    ("vperetti", "php-cve-2026-109618-109619-backports"),
    ("devploit", "php2shell"),
    ("syrex1013", "php2shell"),
]:
    slug = owner + "_" + repo.replace("-", "_")
    fetch(BASE + f"/repos/{owner}/{repo}", slug + "_repo")
    fetch(BASE + f"/repos/{owner}/{repo}/git/trees/HEAD?recursive=1", slug + "_tree")
    time.sleep(1)

print("DONE scan2")
