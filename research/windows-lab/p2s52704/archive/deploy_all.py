import os
import subprocess, sys

CONTAINERS = [
    ("p2s5445", "18101"), ("p2s5538", "18102"), ("p2s5640", "18103"),
    ("p2s7033", "18104"), ("p2s7133", "18105"), ("p2s7234", "18106"),
    ("p2s7333", "18107"), ("p2s7433", "18108"), ("p2s8030", "18109"),
    ("p2s8132", "18110"), ("p2s8234", "18111"), ("p2s8335", "18112"),
    ("p2s8426", "18113"), ("p2s8511", "18114"),
]
BASE = os.path.dirname(os.path.abspath(__file__))

def run(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

def deploy(c):
    run(f'docker cp {BASE}\\p2s.ini {c}:/usr/local/etc/php/conf.d/99_p2s_exploit.ini')
    run(f'docker cp {BASE}\\mpm_prefork.conf {c}:/etc/apache2/mods-available/mpm_prefork.conf')
    run(f'docker cp {BASE}\\index_sess.php {c}:/var/www/html/index.php')
    # conf-available (Debian) or conf.d (older) for php_value
    r = run(f'docker cp {BASE}\\php-exploit.conf {c}:/etc/apache2/conf-available/php-exploit.conf')
    r2 = run(f'docker cp {BASE}\\php-exploit.conf {c}:/etc/apache2/conf.d/php-exploit.conf')
    sh = (
        "a2enmod mpm_prefork 2>/dev/null; a2dismod mpm_event 2>/dev/null; "
        "a2dismod mpm_worker 2>/dev/null; a2enconf php-exploit 2>/dev/null; "
        "rm -f /usr/local/etc/php/conf.d/99_p2s_maxinput.ini 2>/dev/null; "
        "ln -sf /var/www/html /www 2>/dev/null; "
        "(apache2ctl restart 2>/dev/null || service apache2 restart 2>/dev/null || apachectl restart 2>/dev/null); "
        "sleep 2"
    )
    run(f'docker exec {c} sh -c "{sh}"')

def verify(c, port):
    r = run(f'docker cp {BASE}\\chk.php {c}:/var/www/html/chk.php')
    r2 = run(f'docker exec {c} curl -s http://127.0.0.1/chk.php')
    run(f'docker exec {c} rm -f /var/www/html/chk.php')
    out = r2.stdout.strip()
    ok = ("max_input_vars=1000" in out) and ("max_input_vars=10000" not in out) and "memory_limit=8M" in out
    return ok, out

def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    for c, port in CONTAINERS:
        if only and c not in only:
            continue
        print(f"=== {c} (port {port}) ===")
        deploy(c)
        ok, out = verify(c, port)
        print(("OK  " if ok else "BAD ") + out.replace("\n", " | ")[:200])

if __name__ == "__main__":
    main()
