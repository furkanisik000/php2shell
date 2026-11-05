#!/usr/bin/env python3
"""Extract zif_system / zval_ptr_dtor / ps_globals for all sub-8.3 containers,
auto-detecting the libphp.so path (libphp.so vs libphp7.so)."""
import subprocess, re

VERS = [
    ("8.1.32", "p2s8132"), ("8.0.30", "p2s8030"), ("7.4.33", "p2s7433"),
    ("7.3.33", "p2s7333"), ("7.2.34", "p2s7234"), ("7.1.33", "p2s7133"),
    ("7.0.33", "p2s7033"), ("5.6.40", "p2s5640"), ("5.5.38", "p2s5538"),
    ("5.4.45", "p2s5445"),
]

def sh(c, cmd):
    r = subprocess.run(["docker", "exec", c, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=90)
    return r.stdout

def find_so(c):
    for p in ["/usr/lib/apache2/modules/libphp.so",
              "/usr/lib/apache2/modules/libphp7.so",
              "/usr/lib/apache2/modules/libphp5.so"]:
        if sh(c, "test -f %s && echo OK" % p).strip() == "OK":
            return p
    # fallback: find
    out = sh(c, "find / -name 'libphp*.so' 2>/dev/null | head -1")
    return out.strip() or None

def nm(c, so):
    return sh(c, "nm %s 2>/dev/null" % so)

for ver, c in VERS:
    so = find_so(c)
    if not so:
        print("%-7s %-8s  NO .so FOUND" % (ver, c), flush=True)
        continue
    out = nm(c, so)
    zif = dtor = psg = ""
    for ln in out.splitlines():
        if re.search(r"\bzif_system$", ln): zif = ln.split()[0]
        if re.search(r"\bzval_ptr_dtor$", ln): dtor = ln.split()[0]
        if re.search(r"\bps_globals$", ln): psg = ln.split()[0]
    print("%-7s %-8s  so=%-40s zif=%-12s dtor=%-12s psg=%s"
          % (ver, c, so, zif or "-", dtor or "-", psg or "-"), flush=True)
print("DONE")
