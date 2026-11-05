#!/usr/bin/env python3
"""Pull the NEW affected versions, run containers, extract zif/dtor offsets via nm.
New: 8.5.9 (18121), 8.4.24 (18122), 8.4.25 (18123), 8.3.33 (18124).
Also re-extract the 4 known ones for a complete table."""
import os
import subprocess, time, json

NEW = [
    ("8.5.9",  "p2s8509", 18121),
    ("8.4.24", "p2s8424", 18122),
    ("8.4.25", "p2s8425", 18123),
    ("8.3.33", "p2s8333", 18124),
]
KNOWN = [
    ("8.3.35", "p2s8335", 18112),
    ("8.4.26", "p2s8426", 18113),
    ("8.5.10", "p2s8510", 18116),
    ("8.5.11", "p2s8511", 18114),
]

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

def setup(ver, name, port):
    print("=== %s (%s, port %d) ===" % (ver, name, port), flush=True)
    sh("docker rm -f %s 2>nul" % name)
    r = sh("docker pull php:%s-apache" % ver, timeout=600)
    if r.returncode != 0:
        print("  PULL FAIL: %s" % (r.stderr or r.stdout)[-200:]); return None
    r = sh("docker run -d --name %s -p %d:80 php:%s-apache" % (name, port, ver))
    if r.returncode != 0:
        print("  RUN FAIL: %s" % (r.stderr or r.stdout)[-200:]); return None
    time.sleep(2)
    # single-worker prefork + php.ini (same as the lab)
    ini = ("display_errors=1\nmemory_limit=128M\nmax_input_vars=1000\n"
           "post_max_size=512M\nupload_max_filesize=512M\n"
           "session.use_cookies=1\nsession.use_strict_mode=0\nsession.upload_progress.enabled=1\n")
    sh("docker exec -i %s tee /usr/local/etc/php/conf.d/99_p2s.ini >nul" % name) if False else None
    # write ini via docker cp (avoid heredoc issues)
    import os, tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "99_p2s.ini"), "w").write(ini)
    open(os.path.join(d, "index.php"), "w").write('<?php session_start(); echo "OK";\n')
    sh("docker cp %s/%s %s:/usr/local/etc/php/conf.d/99_p2s.ini" % (d, "99_p2s.ini", name))
    sh("docker cp %s/%s %s:/var/www/html/index.php" % (d, "index.php", name))
    conf = ("<IfModule mpm_prefork_module>\nStartServers 1\nMinSpareServers 1\n"
            "MaxSpareServers 1\nMaxRequestWorkers 1\nServerLimit 1\n</IfModule>\n")
    open(os.path.join(d, "mpm_prefork.conf"), "w").write(conf)
    sh("docker cp %s/%s %s:/etc/apache2/mods-available/mpm_prefork.conf" % (d, "mpm_prefork.conf", name))
    sh("docker exec %s sh -c 'a2enmod mpm_prefork && a2dismod mpm_event && a2dismod mpm_worker'" % name)
    sh("docker exec %s ln -sf /var/www/html /www" % name)
    sh("docker exec %s apache2ctl restart" % name)
    time.sleep(1.5)
    # extract offsets
    nm = sh("docker exec %s sh -c \"nm /usr/lib/apache2/modules/libphp.so 2>/dev/null | grep -wE 'zif_system|zval_ptr_dtor'\"" % name)
    out = {}
    for line in nm.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1] in ("zif_system", "zval_ptr_dtor"):
            out[parts[-1]] = int(parts[0], 16)
    print("  zif_system    = %s" % ("0x%x" % out.get("zif_system", 0) if "zif_system" in out else "MISSING"))
    print("  zval_ptr_dtor = %s" % ("0x%x" % out.get("zval_ptr_dtor", 0) if "zval_ptr_dtor" in out else "MISSING"))
    return out

results = {}
for ver, name, port in NEW + KNOWN:
    if any(n == name for _, n, _ in KNOWN) and name in ["p2s8335","p2s8426","p2s8510","p2s8511"]:
        # already running, just re-extract
        nm = sh("docker exec %s sh -c \"nm /usr/lib/apache2/modules/libphp.so 2>/dev/null | grep -wE 'zif_system|zval_ptr_dtor'\"" % name)
        out = {}
        for line in nm.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[-1] in ("zif_system", "zval_ptr_dtor"):
                out[parts[-1]] = int(parts[0], 16)
        print("=== %s (existing %s) ===" % (ver, name))
        print("  zif_system    = 0x%x" % out.get("zif_system", 0))
        print("  zval_ptr_dtor = 0x%x" % out.get("zval_ptr_dtor", 0))
        results[ver] = out
    else:
        out = setup(ver, name, port)
        results[ver] = out or {}

print("\n=== OFFSET TABLE ===")
for ver in sorted(results, key=lambda v: [int(x) for x in v.split(".")], reverse=True):
    o = results[ver]
    print("  %-8s zif=0x%-8x dtor=0x%-8x" % (ver, o.get("zif_system",0), o.get("zval_ptr_dtor",0)))
json.dump(results, open(r"C:\Users\<USER>\p2s52704\test\poc8510\offsets.json","w"), indent=2)
print("\nsaved -> offsets.json")
