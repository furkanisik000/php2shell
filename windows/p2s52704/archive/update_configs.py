"""Update all 14 containers to default memory_limit (128M) + 512M post_max_size."""
import subprocess, sys, time

sys.path.insert(0, r"C:\Users\likat\p2s52704")
from versions import VERSIONS

SED = (
    "sed -i 's/memory_limit=.*/memory_limit=128M/' /usr/local/etc/php/conf.d/99_p2s.ini; "
    "sed -i 's/post_max_size=.*/post_max_size=512M/' /usr/local/etc/php/conf.d/99_p2s.ini; "
    "sed -i 's/upload_max_filesize=.*/upload_max_filesize=512M/' /usr/local/etc/php/conf.d/99_p2s.ini; "
    "echo DONE"
)

for ver, port, container, zif, dtor, htdata, s1n, s2t, s2v, carrier in VERSIONS:
    r = subprocess.run(
        "docker exec " + container + " sh -c 'test -f /usr/local/etc/php/conf.d/99_p2s.ini && echo yes || echo no'",
        shell=True, capture_output=True, text=True,
    )
    if "no" in r.stdout:
        print("  %s: NO CONFIG FILE (skipping)" % ver, flush=True)
        continue

    subprocess.run("docker exec " + container + " sh -c '" + SED + "'", shell=True)
    subprocess.run("docker exec " + container + " apachectl restart 2>/dev/null", shell=True)
    time.sleep(1.0)
    r = subprocess.run(
        "docker exec " + container + " php -r 'echo ini_get(\"memory_limit\").\" | \".ini_get(\"post_max_size\");'",
        shell=True, capture_output=True, text=True,
    )
    ml = r.stdout.strip()
    status = "OK" if "128M" in ml else "FAIL"
    print("  %-8s %-10s %s  (%s)" % (ver, container, status, ml), flush=True)

print("\n=== done ===", flush=True)
