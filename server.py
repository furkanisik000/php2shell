#!/usr/bin/env python3
"""server.py — P2S CVE Scanner: thin HTTP layer over core.py.

Run:  /opt/homebrew/bin/python3.12 server.py 8123
UI:   http://127.0.0.1:8123

Endpoints
  GET  /                 index.html (professional UI)
  GET  /health           liveness + version + counts
  GET  /db/<file>        serve db files (vulns.json, exploits.json, ...)
  GET  /cves?software=&version=    CVE list (filtered)
  GET  /pocs             runnable PoC catalog
  POST /probe            {url} -> fingerprint + waf + ports (no save)
  POST /scan             {url, name?, save?} -> full scan + CVEs + risk (+save profile)
  GET  /profiles         list saved target profiles (summary)
  GET  /profiles/<id>    one full profile
  POST /profiles/<id>/rename      {name}
  DELETE /profiles/<id>
  GET  /profiles/<id>/report?fmt=md|json   (downloads report)
  POST /profiles/<id>/poc/<cve>  {params{}} -> build+run PoC, record on profile
  POST /run              {command} -> bounded local PoC executor
  GET  /mcp              MCP server doc + install line
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import core

HERE = core.HERE
DB = core.DB
DIST = os.path.join(HERE, "web", "dist")   # built React frontend (web/ -> dist/)
VERSION = "2.1.0"


class H(BaseHTTPRequestHandler):
    # ---- helpers ----------------------------------------------------------
    def _json(self, code: int, obj) -> None:
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _text(self, code: int, text: str, ctype: str = "text/plain") -> None:
        b = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _file(self, path: str, download_name: str = None) -> None:
        if not os.path.isfile(path):
            self._json(404, {"error": "not found"})
            return
        with open(path, "rb") as f:
            b = f.read()
        if path.endswith(".html"):
            ctype = "text/html"
        elif path.endswith(".json"):
            ctype = "application/json"
        elif path.endswith(".js"):
            ctype = "application/javascript"
        elif path.endswith(".css"):
            ctype = "text/css"
        else:
            ctype = "text/plain"
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return {}

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.command} {self.path} -> {fmt % args}", flush=True)

    # ---- CORS / methods ---------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ---- GET --------------------------------------------------------------
    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        query = {k: v for k, v in urllib.parse.parse_qsl(parts.query)}

        if path in ("/", "/index.html"):
            # React frontend (web/ -> dist/); falls back to legacy index.html if dist missing
            self._file(os.path.join(DIST, "index.html") if os.path.exists(os.path.join(DIST, "index.html"))
                       else os.path.join(HERE, "index.html"))
        elif path.startswith("/assets/"):
            self._file(os.path.join(DIST, path.lstrip("/")))
        elif path == "/health":
            try:
                vulns = core.load_vulns()
            except Exception as e:
                self._json(200, {"ok": False, "error": str(e)})
                return
            self._json(200, {
                "ok": True, "version": VERSION,
                "vulns": len(vulns),
                "with_poc": sum(1 for v in vulns if v.get("exploit")),
                "software": core.software_summary(),
                "profiles": len(core.list_profiles()),
            })
        elif path == "/cves":
            out = core.load_vulns()
            if query.get("software"):
                out = [c for c in out if c.get("software") == query["software"]]
            if query.get("version"):
                out = [c for c in out if query["version"] in (c.get("affected") or [])]
            self._json(200, {"count": len(out), "cves": out})
        elif path == "/pocs":
            self._json(200, {"count": len(core.poc_list()), "pocs": core.poc_list()})
        elif path == "/profiles":
            self._json(200, {"count": len(core.list_profiles()), "profiles": core.list_profiles()})
        elif re.match(r"^/profiles/[^/]+/poc-runs$", path):
            m = re.match(r"^/profiles/([^/]+)/poc-runs$", path)
            pid = urllib.parse.unquote(m.group(1))
            out = core.store.poc_history(pid, limit=200)
            self._json(200, {"count": len(out), "runs": out})
        elif re.match(r"^/profiles/[^/]+/scans$", path):
            m = re.match(r"^/profiles/([^/]+)/scans$", path)
            pid = urllib.parse.unquote(m.group(1))
            out = core.store.scan_history(pid, limit=100)
            self._json(200, {"count": len(out), "scans": out})
        elif path == "/logs":
            out = core.store.list_logs(level=query.get("level"), category=query.get("category"),
                                       limit=int(query.get("limit", 200)), search=query.get("q"))
            self._json(200, {"count": len(out), "logs": out})
        elif path.startswith("/profiles/") and "/report" in path:
            m = re.match(r"^/profiles/([^/]+)/report$", path)
            if m:
                pid = urllib.parse.unquote(m.group(1))
                prof = core.get_profile(pid)
                if not prof:
                    self._json(404, {"error": "no profile"})
                    return
                fmt = query.get("fmt", "md")
                text, fname = core.build_report(prof, fmt)
                b = text.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8" if fmt == "md" else "application/json")
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            else:
                self._json(404, {"error": "not found"})
        elif path.startswith("/profiles/"):
            m = re.match(r"^/profiles/([^/]+)$", path)
            if m:
                prof = core.get_profile(urllib.parse.unquote(m.group(1)))
                self._json(200 if prof else 404, prof or {"error": "no profile"})
            else:
                self._json(404, {"error": "not found"})
        elif path == "/mcp":
            doc = (
                "P2S CVE Scanner — MCP server\n"
                f"version {VERSION}\n\n"
                "Install (stdio):  qwen mcp add p2s -- /opt/homebrew/bin/python3.12 "
                f"{os.path.join(HERE, 'mcp_server.py')}\n"
                "(requires a full Qwen restart after 'qwen mcp add')\n\n"
                "Tools: scan_target, list_cves, get_cve, poc_list, build_poc_command,\n"
                "run_poc, list_profiles, get_profile, delete_profile, export_report,\n"
                "risk_score, tls_fingerprint, port_scan\n"
            )
            self._text(200, doc)
        elif path.startswith("/db/"):
            self._file(os.path.join(HERE, path.lstrip("/")))
        else:
            self._json(404, {"error": "not found"})

    # ---- POST -------------------------------------------------------------
    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        body = self._body()

        if path == "/probe":
            url = (body.get("url") or "").strip()
            if not url:
                self._json(400, {"error": "url required"})
                return
            try:
                self._json(200, core.scan_url(url, do_paths=bool(body.get("paths", True))))
            except Exception as e:
                self._json(500, {"error": str(e)})

        elif path == "/scan":
            url = (body.get("url") or "").strip()
            if not url:
                self._json(400, {"error": "url required"})
                return
            try:
                prof = core.build_profile(url, name=body.get("name"),
                                          save=body.get("save", True),
                                          do_paths=bool(body.get("paths", True)))
            except Exception as e:
                self._json(500, {"error": str(e)})
                return
            self._json(200, prof)

        elif path == "/run":
            cmd = (body.get("command") or "").strip()
            if not cmd:
                self._json(400, {"error": "command required"})
                return
            self._json(200, core.run_command(cmd))

        elif re.match(r"^/profiles/[^/]+/poc/[^/]+$", path):
            m = re.match(r"^/profiles/([^/]+)/poc/(.+)$", path)
            pid = urllib.parse.unquote(m.group(1))
            cve = urllib.parse.unquote(m.group(2))
            if not core.get_profile(pid):
                self._json(404, {"error": "no profile"})
                return
            params = body.get("params", {})
            # run_exploit already logs the run + records it to poc_runs (profile-linked)
            res = core.run_exploit(cve, params, profile_id=pid)
            self._json(200, {"cve": cve, "result": res})

        elif re.match(r"^/poc/[^/]+$", path):
            m = re.match(r"^/poc/(.+)$", path)
            cve = urllib.parse.unquote(m.group(1))
            params = body.get("params", {})
            res = core.run_exploit(cve, params)
            self._json(200, {"cve": cve, "result": res})

        elif re.match(r"^/profiles/[^/]+/rename$", path):
            m = re.match(r"^/profiles/([^/]+)/rename$", path)
            pid = urllib.parse.unquote(m.group(1))
            name = (body.get("name") or "").strip()
            if not name:
                self._json(400, {"error": "name required"})
                return
            ok = core.rename_profile(pid, name)
            self._json(200 if ok else 404, {"ok": ok})

        elif re.match(r"^/profiles/[^/]+/rescan$", path):
            m = re.match(r"^/profiles/([^/]+)/rescan$", path)
            pid = urllib.parse.unquote(m.group(1))
            prof = core.get_profile(pid)
            if not prof:
                self._json(404, {"error": "no profile"})
                return
            url = (body.get("url") or prof.get("url") or "").strip()
            name = (body.get("name") or prof.get("name") or "").strip() or None
            # re-scan appends to the SAME profile (history is kept — professional)
            out = core.build_profile(url, name=name, save=True, existing_id=pid)
            self._json(200, out)

        elif path == "/logs/clear":
            n = core.store.clear_logs()
            core.store.log("INFO", "system", f"logs temizlendi ({n} satır)")
            self._json(200, {"cleared": n})

        else:
            self._json(404, {"error": "not found"})

    # ---- DELETE -----------------------------------------------------------
    def do_DELETE(self):
        path = urllib.parse.urlsplit(self.path).path
        m = re.match(r"^/profiles/([^/]+)$", path)
        if m:
            pid = urllib.parse.unquote(m.group(1))
            ok = core.delete_profile(pid)
            self._json(200 if ok else 404, {"ok": ok})
            return
        self._json(404, {"error": "not found"})


def main():
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8123
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    print(f"[*] P2S CVE Scanner v{VERSION}  http://127.0.0.1:{port}  (core: {os.path.basename(HERE)})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
