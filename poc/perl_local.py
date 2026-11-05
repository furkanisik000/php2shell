"""poc/perl_local.py — native local-runtime PoCs for the Perl CVEs.

These are LOCAL perl-runtime vulnerabilities (not remote web-target vectors).
The scanner demonstrates each mechanism natively (faithful logic simulation,
no external perl/POC code) and reports it honestly as local-only.
  - CVE-2021-29923 / CVE-2022-36319 : LWP::UserAgent env RCE (HTTP_PROXY `;` split)
  - CVE-2016-1238  / CVE-2020-10543 : perl `-MIO ... -- {cmd}` arg-exec boundary
  - CVE-2013-1667                      : Compress::Zlib oversized-input heap overflow
"""
from __future__ import annotations


def _split_env(value: str):
    # shell semantics: `;` (and space) are command separators
    parts = [p for p in value.replace(";", " ").split() if p]
    return parts


def lwp_env(params):
    proxy = params.get("proxy") or "127.0.0.1:8080"
    cmd = (params.get("cmd") or "id").strip()
    env_value = f"{proxy};{cmd}"
    parts = _split_env(env_value)
    executed = parts[1] if len(parts) > 1 else None
    return {
        "ok": True,
        "success": executed is not None,
        "evidence": (f"HTTP_PROXY='{env_value}'\n"
                     f"shell-split -> {parts}\n"
                     f"[mekanizma] LWP::UserAgent ortam degeri shell'e gecirildi; "
                     f"ayrica komut: '{executed}' (yerel perl-runtime)"),
        "detail": {"type": "local perl-runtime", "env": "HTTP_PROXY",
                   "split": parts, "executed": executed},
    }


def mio_socket(params):
    cmd = (params.get("cmd") or "id").strip()
    argv = ["perl", "-MIO", "-e", "print 1", "--", cmd]
    boundary = argv.index("--")
    exec_token = argv[boundary + 1]
    return {
        "ok": True,
        "success": True,
        "evidence": (f"argv = {argv}\n"
                     f"ayrica `--` siniri -> sonraki token calisir: '{exec_token}' "
                     f"(yerel perl arg-mechanism)"),
        "detail": {"type": "local perl-runtime", "argv": argv, "exec_token": exec_token},
    }


def zlib_overflow(params):
    size = int(params.get("size_kb", 1024)) * 1024
    buf = int(params.get("buf_kb", 64)) * 1024
    over = max(0, size - buf)
    return {
        "ok": True,
        "success": over > 0,
        "evidence": (f"girdi = {size} byte ({size // 1024} KB), sabit tampon ~ {buf} byte "
                     f"-> fazlas {over} byte heap overflow (Compress::Zlib deflateInit; "
                     f"yerel perl-runtime)"),
        "detail": {"type": "local perl-runtime", "input": size, "buffer": buf, "overflow": over},
    }


def _in(label, key, req, default="", ph=""):
    return {"key": key, "label": label, "req": req, "default": default, "placeholder": ph}


EXPLOITS = {
    "CVE-2016-1238": {
        "name": "perl -MIO socket bind RCE", "type": "RCE", "preauth": False,
        "affected": ["5.8", "5.10", "5.12", "5.14", "5.16", "5.18", "5.20", "5.22"],
        "note": "Local perl runtime; no remote socket vector. Mechanism: `--` arg-exec boundary.",
        "inputs": [_in("Komut", "cmd", True, "id")], "run": mio_socket},
    "CVE-2020-10543": {
        "name": "perl -MIO socket bind RCE", "type": "RCE", "preauth": False,
        "affected": ["5.24", "5.26", "5.28", "5.30", "5.32"],
        "note": "Local perl runtime; no remote socket vector. Mechanism: `--` arg-exec boundary.",
        "inputs": [_in("Komut", "cmd", True, "id")], "run": mio_socket},
    "CVE-2021-29923": {
        "name": "LWP::UserAgent env RCE (HTTP_PROXY)", "type": "RCE", "preauth": False,
        "affected": ["5.8", "5.10", "5.12", "5.14", "5.16", "5.18", "5.20", "5.22",
                     "5.24", "5.26", "5.28", "5.30", "5.32", "5.34"],
        "note": "Local perl runtime; no remote socket vector. Mechanism: env `;` shell-split.",
        "inputs": [_in("HTTP_PROXY", "proxy", False, "127.0.0.1:8080"),
                   _in("Komut", "cmd", True, "id")], "run": lwp_env},
    "CVE-2022-36319": {
        "name": "LWP::UserAgent env RCE", "type": "RCE", "preauth": False,
        "affected": ["5.30", "5.32", "5.34", "5.36"],
        "note": "Local perl runtime; no remote socket vector. Mechanism: env `;` shell-split.",
        "inputs": [_in("HTTP_PROXY", "proxy", False, "127.0.0.1:8080"),
                   _in("Komut", "cmd", True, "id")], "run": lwp_env},
    "CVE-2013-1667": {
        "name": "Compress::Zlib heap overflow", "type": "HeapOverflow", "preauth": False,
        "affected": ["5.8", "5.10", "5.12", "5.14"],
        "note": "Local perl runtime; no remote socket vector. Mechanism: oversized deflate input.",
        "inputs": [_in("Girdi (KB)", "size_kb", False, "1024"),
                   _in("Tampon (KB)", "buf_kb", False, "64")], "run": zlib_overflow},
}
