"""poc — native PoC engine registry.

Aggregates every PoC module (each exposes an EXPLOITS dict of
{cve_id: {..., "run": fn}}) and provides:
  list_exploits()          -> {cve_id: spec}  (without the run callable)
  get_exploit(cve_id)      -> spec or None    (with run)
  run_exploit(cve_id, p)   -> result dict     (native execution)
  has_exploit(cve_id)      -> bool
"""
from __future__ import annotations

from . import h2c, mysql_proto, perl_local, php2shell, php_http, python_web, node_web, java_web, asp_dotnet

_MODULES = (php2shell, php_http, mysql_proto, h2c, perl_local, python_web, node_web, java_web, asp_dotnet)

REGISTRY: dict = {}
for _m in _MODULES:
    REGISTRY.update(_m.EXPLOITS)


def list_exploits() -> dict:
    out = {}
    for cid, spec in REGISTRY.items():
        d = {k: v for k, v in spec.items() if k != "run"}
        out[cid] = d
    return out


def get_exploit(cve_id: str):
    return REGISTRY.get(cve_id)


def has_exploit(cve_id: str) -> bool:
    return cve_id in REGISTRY


def run_exploit(cve_id: str, params: dict = None) -> dict:
    spec = REGISTRY.get(cve_id)
    if not spec:
        raise ValueError(f"no native PoC for {cve_id} (catalog: {', '.join(sorted(REGISTRY))})")
    params = params or {}
    # defaults: fill missing inputs with their defaults
    filled = dict(params)
    for inp in spec.get("inputs", []):
        k = inp.get("key")
        if k not in filled or filled[k] in (None, ""):
            if inp.get("default") not in (None, ""):
                filled[k] = inp["default"]
    result = spec["run"](filled)
    result.setdefault("cve", cve_id)
    return result
