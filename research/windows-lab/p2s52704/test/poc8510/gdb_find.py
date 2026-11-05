#!/usr/bin/env python3
"""Attach gdb to each 8.5.10 worker (break on zend_execute), send a request,
dump ps_globals to find PS(http_session_vars)."""
import subprocess, time, re

def sh(cmd, timeout=30):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

# 1) find worker PIDs
r = sh("docker exec p2s8510 pgrep -f 'apache2 -DFOREGROUND'")
pids = [p for p in r.stdout.split() if p not in ("1",)]
print("workers:", pids, flush=True)

# 2) libphp base + ps_globals base (fixed for this run)
LIBPHP = 0x76a4d3a00000
PS_BASE = LIBPHP + 0x1770a40
ZEXEC = LIBPHP + 0x74fe50
print("libphp=0x%x  ps_globals=0x%x  zend_execute=0x%x" % (LIBPHP, PS_BASE, ZEXEC), flush=True)

# 3) for each worker, write a gdb script + start gdb in background
import os
procs = []
for i, pid in enumerate(pids):
    script = "/tmp/gdb_w%d.txt" % i
    with open(r"research/windows-lab/p2s52704\test\poc8510\gdb_w%d.txt" % i, "w") as f:
        f.write("attach %d\nset pagination off\nset confirm off\n"
                "break *0x%x\ncommands 1\nsilent\n"
                "printf 'HIT worker %d\\n' % 0x%x\nx/160gx 0x%x\n"
                "printf 'END\\n'\ndetach\nquit\nend\ncontinue\n"
                % (int(pid), ZEXEC, int(pid), ZEXEC, PS_BASE))
    sh("docker cp C:/Users/<USER>/p2s52704/test/poc8510/gdb_w%d.txt p2s8510:%s" % (i, script))
    # start gdb in background inside the container
    p = subprocess.Popen(["docker", "exec", "-d", "p2s8510",
                          "sh", "-c", "gdb -batch -x %s > /tmp/gdb_out%d.txt 2>&1" % (script, i)])
    procs.append((pid, i))
time.sleep(2.0)

# 4) send several requests to trigger a breakpoint
for k in range(6):
    sh("docker exec p2s8510 curl -s -m5 http://127.0.0.1/index.php -o /dev/null")
    time.sleep(0.3)
time.sleep(3.0)

# 5) read the gdb outputs
hit = False
for pid, i in procs:
    r = sh("docker exec p2s8510 cat /tmp/gdb_out%d.txt" % i)
    out = r.stdout
    if "HIT worker" in out:
        hit = True
        print("\n=== HIT on worker %d ===" % pid)
        print(out)
        break
    else:
        print("worker %d: no hit (%d bytes)" % (pid, len(out)))
if not hit:
    print("\nNO HIT - trying wider attach")
