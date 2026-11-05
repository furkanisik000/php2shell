import json, time, urllib.request, urllib.parse, sys

BASE = "https://api.github.com"
HDRS = {
    "User-Agent": "p2s-research-scan/1.0 (authorized lab research)",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
OUT = "C:/Users/likat/.qwen/tmp/p2s/scan"

def get(url, raw=False):
    req = urllib.request.Request(url, headers=HDRS)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
            remaining = r.headers.get("X-RateLimit-Remaining")
            return (data if raw else json.loads(data)), remaining
    except urllib.error.HTTPError as e:
        body = e.read()
        if e.code in (403, 429):
            try:
                info = json.loads(body)
                if "rate_limit" in str(info) or e.headers.get("X-RateLimit-Remaining") == "0":
                    return {"__rate_limited__": True, "status": e.code, "body": str(body)[:300]}, e.headers.get("X-RateLimit-Remaining")
            except Exception:
                pass
        return {"__error__": True, "status": e.code, "url": url, "body": str(body)[:400]}, None
    except Exception as e:
        return {"__error__": True, "status": str(e), "url": url}, None

results = {}

# 0) rate limit
rl, rem = get(BASE + "/rate_limit")
results["rate_limit"] = rl.get("resources", rl) if isinstance(rl, dict) else rl
print("RATE:", json.dumps(results["rate_limit"])[:400])

def save(name, obj):
    with open(f"{OUT}/{name}.json", "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)

# 1) repo searches
queries = {
    "q_php2shell": "php2shell",
    "q_cve": "CVE-2026-109618",
    "q_cve2": "CVE-2026-109619",
    "q_edb52704": "52704 php",
    "q_zendmm": "zend_mm_heap exploit",
    "q_uploadprogress": "upload_progress OOM session leak",
    "q_bypass_aslr": "php2shell bypass aslr",
    "q_poc": "php2shell-poc",
    "q_patches": "php2shell patches backport",
}
for name, q in queries.items():
    url = BASE + "/search/repositories?" + urllib.parse.urlencode({"q": q, "per_page": 30})
    d, rem = get(url)
    save(name, d)
    if isinstance(d, dict) and "items" in d:
        print(f"{name} [{q}]: total={d.get('total_count')}")
        for it in d["items"]:
            print(f"   - {it['full_name']} | {it.get('stargazers_count')}* | {str(it.get('description'))[:80]} | updated={it.get('updated_at')}")
    else:
        print(f"{name} [{q}]: {str(d)[:200]}")
    time.sleep(8)  # search rate 10/min

# 2) user searches
for name, q in {"u_xuehuolll": "xuehuolll", "u_9bie": "9bie", "u_agrresore": "agrresore", "u_ikow": "ikow"}.items():
    url = BASE + "/search/users?" + urllib.parse.urlencode({"q": q, "per_page": 10})
    d, rem = get(url)
    save(name, d)
    if isinstance(d, dict) and "items" in d:
        print(f"{name} [{q}]: " + ", ".join(i["login"] for i in d["items"]))
    else:
        print(f"{name} [{q}]: {str(d)[:200]}")
    time.sleep(8)

# 3) advisories
for name, q in {
    "adv_cve109618": "CVE-2026-109618",
    "adv_cve109619": "CVE-2026-109619",
    "adv_q_php2shell": "php2shell",
    "adv_q_php_oom": "php zend oom session",
}:
    url = BASE + "/advisories?" + urllib.parse.urlencode({"q": q, "per_page": 20})
    d, rem = get(url)
    save(name, d)
    if isinstance(d, list):
        print(f"{name}: {len(d)} advisories")
        for a in d:
            print(f"   - {a.get('ghsa_id')} {a.get('cve_id')} | {str(a.get('summary'))[:90]}")
    else:
        print(f"{name}: {str(d)[:300]}")
    time.sleep(2)

print("DONE scan1")
