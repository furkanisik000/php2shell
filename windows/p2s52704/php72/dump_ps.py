#!/usr/bin/env python3
"""7.2.34: read ps_globals via /proc/PID/mem (gdb-free) before/after the NUL arm,
to see whether PS(id) becomes a dangling heap pointer after the soft-bailout OOM."""
import os
import subprocess, time, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "php72"))
import drive as D

# usage: dump_ps.py [port] [ps_off_hex]  (defaults: 7.2.34)
PORT = int(sys.argv[1], 0) if len(sys.argv) > 1 else 18106
PS_OFF = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0xD51F40
CONT = {18106: "p2s7234", 18107: "p2s7333", 18108: "p2s7433",
        18105: "p2s7133", 18104: "p2s7033", 18103: "p2s5640",
        18102: "p2s5538", 18101: "p2s5445"}.get(PORT, "p2s7234")

def sh(cmd):
    return subprocess.run(["docker", "exec", CONT, "sh", "-c", cmd],
                          capture_output=True, text=True).stdout

def worker_pid():
    out = sh("ps aux | grep www-data | grep -v grep | head -1")
    return int(out.split()[1])

def libphp_base(pid):
    maps = sh("cat /proc/%d/maps" % pid)
    for line in maps.splitlines():
        if "libphp" in line and "modules" in line:
            return int(line.split("-")[0], 16)
    return None

def read_mem(pid, addr, n=8):
    out = sh("perl /tmp/read_mem.pl %d %x %d" % (pid, addr, n))
    out = out.strip()
    return bytes.fromhex(out) if out else None

def dump_ps(pid, label):
    base = libphp_base(pid)
    if base is None:
        print("== %s: libphp base NOT FOUND ==" % label); return
    ps = base + PS_OFF
    print("== %s: worker=%d libphp=%s ps_globals=%s ==" % (label, pid, hex(base), hex(ps)))
    for off, name in ((0x0, "gc"), (0x8, "h"), (0x10, "PS(id)"),
                      (0x150, "http_session_vars"), (0x1b0, "ps_files")):
        v = read_mem(pid, ps + off)
        print("   %-18s @0x%-4x = %s" % (name, off, v.hex() if v else "?"), flush=True)

c = D.Conn("127.0.0.1", PORT, False, timeout=60)
c.get("/index.php")
time.sleep(0.3)
pid = worker_pid()
dump_ps(pid, "BASELINE (after GET)")
time.sleep(0.3)
arm = D.arm_body(1299780, b"a:\n", b"\x00")
ra = c.post("/index.php", arm, False, maxread=65536)
print("arm: status=%s hard=%s closed=%s body=%r" % (
    ra["status"], (b"Allowed memory size" in ra["body"]), ra["closed"],
    ra["body"][:80].decode("latin-1", "replace")), flush=True)
time.sleep(0.5)
pid2 = worker_pid()
print("worker after arm: %d (baseline %d)" % (pid2, pid), flush=True)
dump_ps(pid2, "AFTER ARM")
c.close()
print("DONE")
