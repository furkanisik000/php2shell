#!/usr/bin/env python3
"""mcp_server.py — P2S CVE Scanner as an MCP server (Model Context Protocol).

Pure stdlib, zero dependencies. Speaks JSON-RPC 2.0 over stdio (newline-delimited).
Wires the scanner core (core.py) up as MCP tools so Qwen Code / any MCP client
can drive the scanner.

Install (stdio):
    qwen mcp add p2s -- /opt/homebrew/bin/python3.12 /Users/<USER>/Desktop/php2shell/mcp_server.py
    # then a FULL Qwen restart is required (qwen mcp add never hot-loads).

Tools exposed:
    scan_target, list_cves, get_cve, poc_list, build_poc_command, run_poc,
    list_profiles, get_profile, delete_profile, export_report, risk_score,
    tls_fingerprint, port_scan
"""
from __future__ import annotations

import json
import sys

import core

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "p2s-cve-scanner"
SERVER_VERSION = "2.0.0"


def _s(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# tool implementations (each returns a JSON-serializable value)
# ---------------------------------------------------------------------------
def t_scan_target(a):
    url = (a.get("url") or "").strip()
    if not url:
        raise ValueError("url is required")
    prof = core.build_profile(
        url, name=a.get("name"), save=bool(a.get("save", True)),
        do_paths=bool(a.get("paths", True)))
    return prof


def t_list_cves(a):
    out = core.load_vulns()
    if a.get("software"):
        out = [c for c in out if c.get("software") == a["software"]]
    if a.get("version"):
        out = [c for c in out if a["version"] in (c.get("affected") or [])]
    return {"count": len(out), "cves": out}


def t_get_cve(a):
    v = core.get_cve((a.get("id") or "").strip())
    if not v:
        raise ValueError(f"no CVE {a.get('id')}")
    return v


def t_poc_list(a):
    return core.poc_list()


def t_poc_describe(a):
    cid = (a.get("cve_id") or "").strip()
    specs = core.poc_list()
    if cid not in specs:
        raise ValueError(f"{cid} icin native PoC yok")
    return specs[cid]


def t_run_poc(a):
    cve = (a.get("cve_id") or "").strip()
    params = a.get("params", {})
    res = core.run_exploit(cve, params)
    return {"cve": cve, "result": res}


def t_list_profiles(a):
    return core.list_profiles()


def t_get_profile(a):
    p = core.get_profile((a.get("id") or "").strip())
    if not p:
        raise ValueError(f"no profile {a.get('id')}")
    return p


def t_delete_profile(a):
    ok = core.delete_profile((a.get("id") or "").strip())
    return {"deleted": bool(ok)}


def t_export_report(a):
    p = core.get_profile((a.get("id") or "").strip())
    if not p:
        raise ValueError(f"no profile {a.get('id')}")
    fmt = a.get("fmt", "md")
    text, fname = core.build_report(p, fmt)
    saved = core.save_report(p, fmt)
    return {"filename": fname, "path": saved.get("path"), "report": text}


def t_risk_score(a):
    pid = (a.get("id") or "").strip()
    if pid:
        p = core.get_profile(pid)
        if not p:
            raise ValueError(f"no profile {pid}")
        return p.get("risk")
    # inline: score against a url
    url = (a.get("url") or "").strip()
    if not url:
        raise ValueError("provide id or url")
    scan = core.scan_url(url)
    return scan.get("risk")


def t_tls_fingerprint(a):
    host = (a.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    return core.tls_fingerprint(host, int(a.get("port", 443)))


def t_port_scan(a):
    host = (a.get("host") or "").strip()
    if not host:
        raise ValueError("host is required")
    extra = a.get("extra_ports") or []
    return core.scan_ports(host, extra_ports=extra)


def t_list_logs(a):
    out = core.store.list_logs(
        level=(a.get("level") or "").upper() or None,
        category=(a.get("category") or None),
        limit=int(a.get("limit", 200)),
        search=a.get("q") or None)
    return {"count": len(out), "logs": out}


TOOL_IMPLS = {
    "scan_target": t_scan_target,
    "list_cves": t_list_cves,
    "get_cve": t_get_cve,
    "poc_list": t_poc_list,
    "poc_describe": t_poc_describe,
    "run_poc": t_run_poc,
    "list_profiles": t_list_profiles,
    "get_profile": t_get_profile,
    "delete_profile": t_delete_profile,
    "export_report": t_export_report,
    "risk_score": t_risk_score,
    "tls_fingerprint": t_tls_fingerprint,
    "port_scan": t_port_scan,
    "list_logs": t_list_logs,
}


def _schema(props, required=None):
    return {"type": "object", "properties": props, "required": required or []}


TOOLS = [
    {"name": "scan_target",
     "description": "Full scan of an authorized target: HTTP fingerprint, WAF, open ports, TLS, "
                    "security headers, interesting paths, matched critical CVEs, and a 0-100 risk score. "
                    "Saves a target profile.",
     "inputSchema": _schema(
         {"url": {"type": "string"}, "name": {"type": "string"},
          "save": {"type": "boolean"}, "paths": {"type": "boolean"}},
         ["url"])},
    {"name": "list_cves",
     "description": "List critical CVEs, optionally filtered by software and/or version (major).",
     "inputSchema": _schema({"software": {"type": "string"}, "version": {"type": "string"}})},
    {"name": "get_cve",
     "description": "Get one CVE entry (with its exploit/PoC panel if present).",
     "inputSchema": _schema({"id": {"type": "string"}}, ["id"])},
    {"name": "poc_list",
     "description": "List the runnable PoC catalog (CVEs with a command template + inputs).",
     "inputSchema": _schema({})},
    {"name": "poc_describe",
     "description": "Describe the NATIVE PoC for a CVE (name, type, preauth, inputs+defaults, note) — "
                    "what the scanner will do, not an external command.",
     "inputSchema": _schema({"cve_id": {"type": "string"}}, ["cve_id"])},
    {"name": "run_poc",
     "description": "Build AND execute a PoC against the target (bounded, allow-listed binaries only). "
                    "Returns exit/stdout/stderr.",
     "inputSchema": _schema({"cve_id": {"type": "string"}, "params": {"type": "object"}}, ["cve_id"])},
    {"name": "list_profiles",
     "description": "List saved target profiles (summary).",
     "inputSchema": _schema({})},
    {"name": "get_profile",
     "description": "Get one full target profile by id.",
     "inputSchema": _schema({"id": {"type": "string"}}, ["id"])},
    {"name": "delete_profile",
     "description": "Delete a saved target profile by id.",
     "inputSchema": _schema({"id": {"type": "string"}}, ["id"])},
    {"name": "export_report",
     "description": "Generate and save a risk report (markdown or JSON) for a profile; returns the text + path.",
     "inputSchema": _schema({"id": {"type": "string"}, "fmt": {"type": "string", "enum": ["md", "json"]}}, ["id"])},
    {"name": "risk_score",
     "description": "Return the risk score + transparent factor breakdown for a profile id (or a live url).",
     "inputSchema": _schema({"id": {"type": "string"}, "url": {"type": "string"}})},
    {"name": "tls_fingerprint",
     "description": "TLS/certificate fingerprint for a host:protocol (protocol, cipher, issuer, CN, SAN, expiry).",
     "inputSchema": _schema({"host": {"type": "string"}, "port": {"type": "integer"}}, ["host"])},
    {"name": "port_scan",
     "description": "TCP port scan + service banner for a host (common ports + the php2shell lab range).",
     "inputSchema": _schema({"host": {"type": "string"}, "extra_ports": {"type": "array", "items": {"type": "integer"}}}, ["host"])},
    {"name": "list_logs",
     "description": "List the operation log (scan / PoC / profile / system events) from the SQLite session store.",
     "inputSchema": _schema({"level": {"type": "string", "enum": ["INFO", "SUCCESS", "WARN", "ERROR", "DEBUG"]},
                            "category": {"type": "string"}, "limit": {"type": "integer"}, "q": {"type": "string"}})},
]


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 over stdio
# ---------------------------------------------------------------------------
def _send(obj) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _result(rid, result):
    _send({"jsonrpc": "2.0", "id": rid, "result": result})


def _error(rid, code, message):
    _send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})


def handle_initialize(params):
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def handle_tools_list(_params):
    return {"tools": TOOLS}


def handle_tools_call(params):
    name = (params or {}).get("name")
    args = (params or {}).get("arguments", {}) or {}
    fn = TOOL_IMPLS.get(name)
    if not fn:
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}
    try:
        value = fn(args)
        return {"content": [{"type": "text", "text": _s(value)}], "isError": False}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}


def dispatch(msg) -> None:
    method = msg.get("method")
    rid = msg.get("id")
    params = msg.get("params") or {}

    if method is None:
        return  # response or bare — nothing to do

    # notifications (no id) → never respond
    is_notification = "id" not in msg

    if method == "initialize":
        if not is_notification:
            _result(rid, handle_initialize(params))
        return
    if method == "ping":
        if not is_notification:
            _result(rid, {})
        return
    if method == "tools/list":
        if not is_notification:
            _result(rid, handle_tools_list(params))
        return
    if method == "tools/call":
        if not is_notification:
            _result(rid, handle_tools_call(params))
        return
    if method == "notifications/initialized" or method.startswith("notifications/"):
        return

    if not is_notification:
        _error(rid, -32601, f"method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            _error(None, -32700, "parse error")
            continue
        try:
            dispatch(msg)
        except Exception as e:  # never crash the server on one bad call
            rid = msg.get("id")
            if rid is not None:
                _error(rid, -32603, f"internal error: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
