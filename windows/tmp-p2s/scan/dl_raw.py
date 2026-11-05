import os
import urllib.request, os, sys

RAW = "https://raw.githubusercontent.com/"
OUT = os.path.join(os.path.expanduser("~"), ".qwen", "tmp", "p2s", "scan", "raw")
os.makedirs(OUT, exist_ok=True)

FILES = [
    # dinosn — PHP 7.2 chain (the gap)
    ("dinosn", "php-cve-2026-10961x-lab-poc", "HEAD", "tools/php72/chain72.py"),
    ("dinosn", "php-cve-2026-10961x-lab-poc", "HEAD", "tools/php72/drive.py"),
    ("dinosn", "php-cve-2026-10961x-lab-poc", "HEAD", "tools/php72/fullchain.py"),
    ("dinosn", "php-cve-2026-10961x-lab-poc", "HEAD", "docs/STOCK-CHAIN.md"),
    ("dinosn", "php-cve-2026-10961x-lab-poc", "HEAD", "docs/NINEBIE-CLASS-PORT.md"),
    ("dinosn", "php-cve-2026-10961x-lab-poc", "HEAD", "docs/ASLR-STOCK.md"),
    ("dinosn", "php-cve-2026-10961x-lab-poc", "HEAD", "docs/SCREENING.md"),
    ("dinosn", "php-cve-2026-10961x-lab-poc", "HEAD", "README.md"),
    # 9bie — current state (bookworm profile?)
    ("9bie", "php2shell-bypass-aslr-exp", "HEAD", "README.md"),
    ("9bie", "php2shell-bypass-aslr-exp", "HEAD", "pure/RESEARCH_PURE_128M.md"),
    ("9bie", "php2shell-bypass-aslr-exp", "HEAD", "offsets/README.md"),
    ("9bie", "php2shell-bypass-aslr-exp", "HEAD", "offsets/php-8.4.26-apache-trixie-amd64.md"),
    ("9bie", "php2shell-bypass-aslr-exp", "HEAD", "exploit.py"),
    ("9bie", "php2shell-bypass-aslr-exp", "HEAD", "archive/legacy-8m/HTTP_HEAP_LEAK.md"),
    ("9bie", "php2shell-bypass-aslr-exp", "HEAD", "archive/legacy-8m/NOTES.md"),
    # xuehuolll
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "README.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "PROVENANCE.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "analysis/03-versions.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "analysis/05-what-actually-works.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "analysis/11-official-patch.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "analysis/12-public-exploits.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "analysis/16-pure-chain.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "analysis/18-pure-off.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "analysis/21-server-matrix.md"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "exploit/cve/pure_off.py"),
    ("xuehuolll", "php2shell-CVE-2026-109618-109619", "HEAD", "exploit/cve/remote_cve.py"),
    # aarsaputra — claims 5.4-8.4.26
    ("aarsaputra", "php2shell", "HEAD", "README.md"),
    ("aarsaputra", "php2shell", "HEAD", "lib/chain.py"),
    ("aarsaputra", "php2shell", "HEAD", "lib/version.py"),
    ("aarsaputra", "php2shell", "HEAD", "lib/detect.py"),
    ("aarsaputra", "php2shell", "HEAD", "docker/offsets.py"),
    ("aarsaputra", "php2shell", "HEAD", "docs/SYARAT_TARGET.md"),
    # ikow
    ("ikow", "php2shell-poc", "HEAD", "README.md"),
    ("ikow", "php2shell-poc", "HEAD", "docs/ANALYSIS.md"),
    ("ikow", "php2shell-poc", "HEAD", "docs/PATCH_ANALYSIS.md"),
    ("ikow", "php2shell-poc", "HEAD", "poc/verify_oom_trigger.py"),
    # barinov patches
    ("Anton-Barinov", "php2shell-patches", "HEAD", "README.md"),
    ("Anton-Barinov", "php2shell-patches", "HEAD", "patches/php-8.1-minimal.patch"),
    ("Anton-Barinov", "php2shell-patches", "HEAD", "patches/php-7.4-minimal.patch"),
    ("Anton-Barinov", "php2shell-patches", "HEAD", "patches/php-5.6-minimal.patch"),
    # others
    ("eness", "php2shell-CVE-2026-109618-CVE-2026-109619-PoC", "HEAD", "README.md"),
    ("3em0", "php2shell", "HEAD", "README.md"),
    ("devploit", "php2shell", "HEAD", "README.md"),
    ("syrex1013", "php2shell", "HEAD", "README.md"),
    ("mpyw", "php-eol-CVE-2026-109618-109619", "HEAD", "README.md"),
    ("vperetti", "php-cve-2026-109618-109619-backports", "HEAD", "README.md"),
]

ok, fail = 0, []
for owner, repo, ref, path in FILES:
    dest = os.path.join(OUT, owner, repo + "__" + path.replace("/", "__"))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    data = None
    for branch in (ref, "main", "master"):
        if data is not None:
            break
        url = RAW + owner + "/" + repo + "/" + branch + "/" + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "p2s-research-scan/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
        except Exception as e:
            if "404" in str(e):
                continue
            fail.append((owner, repo, path, str(e)[:80]))
            break
    if data is not None:
        with open(dest, "wb") as f:
            f.write(data)
        ok += 1
        print("OK  %6d  %s/%s %s" % (len(data), owner, repo, path))
    else:
        fail.append((owner, repo, path, "404 on all branches"))
        print("FAIL %s/%s %s : 404" % (owner, repo, path))
print("done ok=%d fail=%d" % (ok, len(fail)))
for f in fail:
    print("  FAILED:", f)
