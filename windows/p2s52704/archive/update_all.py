"""Update all 14 containers to 128M memory_limit + 512M post_max_size."""
import subprocess, time

CONTAINERS = [
    "p2s5445", "p2s5538", "p2s5640", "p2s7033", "p2s7133", "p2s7234",
    "p2s7333", "p2s7433", "p2s8030", "p2s8132", "p2s8234", "p2s8335",
    "p2s8426", "p2s8511",
]

SED = (
    "sed -i 's/memory_limit=.*/memory_limit=128M/' /usr/local/etc/php/conf.d/99_p2s.ini; "
    "sed -i 's/post_max_size=.*/post_max_size=512M/' /usr/local/etc/php/conf.d/99_p2s.ini; "
    "sed -i 's/upload_max_filesize=.*/upload_max_filesize=512M/' /usr/local/etc/php/conf.d/99_p2s.ini"
)

for c in CONTAINERS:
    try:
        subprocess.run(["docker", "exec", c, "sh", "-c", SED], timeout=30)
        subprocess.run(["docker", "exec", c, "apachectl", "restart"], timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        # Verify
        r = subprocess.run(
            ["docker", "exec", c, "php", "-r", "echo ini_get('memory_limit');"],
            timeout=10, capture_output=True, text=True,
        )
        ml = r.stdout.strip()
        print("  %-10s memory_limit=%s" % (c, ml), flush=True)
    except Exception as e:
        print("  %-10s ERROR: %s" % (c, e), flush=True)

print("=== done ===", flush=True)
