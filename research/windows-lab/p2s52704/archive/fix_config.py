import os
import subprocess, sys, time
BASE = os.path.dirname(os.path.abspath(__file__))
CONTAINERS = ["p2s5445","p2s5538","p2s5640","p2s7033","p2s7133","p2s7234","p2s7333","p2s7433",
              "p2s8030","p2s8132","p2s8234","p2s8335","p2s8426","p2s8511"]

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def fix(c):
    # 1) if a rogue main php.ini exists, force it to max_input_vars=1000
    r = sh(f'docker exec {c} sh -c "test -f /usr/local/etc/php/php.ini && echo yes"')
    if "yes" in r.stdout:
        sh(f'docker exec {c} sh -c "echo max_input_vars=1000 > /usr/local/etc/php/php.ini"')
    # 2) ensure conf.d has the full clean config
    sh(f'docker cp {BASE}\\p2s1000.ini {c}:/usr/local/etc/php/conf.d/99_p2s.ini')
    # 3) remove php_value overrides
    sh(f'docker exec {c} sh -c "rm -f /etc/apache2/conf-enabled/php-exploit.conf /etc/apache2/conf.d/php-exploit.conf /etc/apache2/conf-available/php-exploit.conf 2>/dev/null"')
    sh(f'docker exec {c} sh -c "ln -sf /var/www/html /www 2>/dev/null"')
    sh(f'docker restart {c}')
    time.sleep(2.5)
    # 4) verify
    sh(f'docker cp {BASE}\\chk.php {c}:/var/www/html/chk.php')
    out = sh(f'docker exec {c} curl -s http://127.0.0.1/chk.php').stdout.strip()
    sh(f'docker exec {c} rm -f /var/www/html/chk.php')
    ok = ("max_input_vars=1000" in out) and ("max_input_vars=10000" not in out) and ("memory_limit=8M" in out)
    return ok, out

only = sys.argv[1:] if len(sys.argv) > 1 else None
for c in CONTAINERS:
    if only and c not in only:
        continue
    ok, out = fix(c)
    print(f"{c:10s} {'OK ' if ok else 'BAD'}  {out.replace(chr(10), ' | ')[:150]}")
