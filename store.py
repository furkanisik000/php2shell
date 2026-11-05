"""store.py — P2S professional SQLite session store + logging.

Session / runtime data (profiles, scans, PoC runs, logs) lives in SQLite at
db/session.db. Static data (CVE DB, PoC definitions) stays in JSON
(db/vulns.json, db/exploits.json) — per project decision ("poclar şuanlık json").

Design goals (professional, per user directive):
  * Relational, queryable, timestamped, thread-safe (per-call connections).
  * Full history of scans AND PoC runs (not just latest), with success flags.
  * A real logging system: every scan / PoC run / error is logged to the
    `logs` table AND mirrored to db/logs.log (for humans + tail).
  * One-time migration from the legacy db/profiles.json.

Tables
------
  profiles (id PK, name, url, created_at, updated_at)
  scans    (id PK, profile_id FK->profiles, url, ts, result_json)
  poc_runs (id PK, profile_id FK->profiles NULL, cve_id, ts, params_json,
            result_json, success)
  logs     (id PK, ts, level, category, message, data_json)

This module is stdlib-only and must NOT import core (avoids a cycle); it owns
its own paths.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "db")
DB_PATH = os.path.join(DB, "session.db")
LOG_FILE = os.path.join(DB, "logs.log")

_LOCK = threading.Lock()  # serialize writes to the log file (sqlite is safe per-conn)
_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40, "SUCCESS": 50}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  url         TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id  TEXT NOT NULL,
  url         TEXT,
  ts          TEXT NOT NULL,
  result_json TEXT,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS poc_runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id  TEXT,
  cve_id      TEXT NOT NULL,
  ts          TEXT NOT NULL,
  params_json TEXT,
  result_json TEXT,
  success     INTEGER,
  FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  level       TEXT NOT NULL,
  category    TEXT,
  message     TEXT,
  data_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_profile  ON scans(profile_id, ts);
CREATE INDEX IF NOT EXISTS idx_poc_profile    ON poc_runs(profile_id, ts);
CREATE INDEX IF NOT EXISTS idx_logs_ts        ON logs(ts);
"""


# ---------------------------------------------------------------------------
# connection + schema
# ---------------------------------------------------------------------------
def _conn() -> sqlite3.Connection:
    os.makedirs(DB, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init() -> None:
    with _conn() as c:
        c.executescript(_SCHEMA)
        c.commit()
    # migrate legacy JSON profiles exactly once
    try:
        migrate_from_json()
    except Exception:
        pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


def _dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


# ---------------------------------------------------------------------------
# logging system
# ---------------------------------------------------------------------------
def log(level: str, category: str, message: str, data: dict = None) -> None:
    """Append a structured log line to SQLite + db/logs.log."""
    level = (level or "INFO").upper()
    ts = _now()
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO logs (ts, level, category, message, data_json) VALUES (?,?,?,?,?)",
                (ts, level, category, message, _dump(data) if data is not None else None))
            c.commit()
    except Exception:
        pass
    # mirror to a human-readable file
    line = f"[{ts}] [{level:<7}] [{category or '-':<7}] {message}"
    if data:
        line += " " + _dump(data)
    with _LOCK:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
    # quiet console mirror for server debugging
    print(f"[p2s:{level}] {message}", flush=True)


def list_logs(level: str = None, category: str = None, limit: int = 200,
              search: str = None) -> list[dict]:
    q = "SELECT id, ts, level, category, message, data_json FROM logs WHERE 1=1"
    args = []
    if level:
        q += " AND level=?"; args.append(level.upper())
    if category:
        q += " AND category=?"; args.append(category)
    if search:
        q += " AND (message LIKE ? OR data_json LIKE ?)"; args += [f"%{search}%", f"%{search}%"]
    q += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    with _conn() as c:
        rows = c.execute(q, args).fetchall()
    out = []
    for r in rows:
        d = None
        if r["data_json"]:
            try: d = json.loads(r["data_json"])
            except Exception: d = r["data_json"]
        out.append({"id": r["id"], "ts": r["ts"], "level": r["level"],
                    "category": r["category"], "message": r["message"], "data": d})
    return out


def clear_logs() -> int:
    with _conn() as c:
        n = c.execute("SELECT COUNT(*) n FROM logs").fetchone()["n"]
        c.execute("DELETE FROM logs"); c.commit()
    # truncate file too
    with _LOCK:
        try:
            open(LOG_FILE, "w").close()
        except Exception:
            pass
    return n


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------
def save_profile(pid: str, name: str, url: str, created: str = None,
                 updated: str = None) -> None:
    created = created or _now()
    updated = updated or _now()
    with _conn() as c:
        c.execute(
            """INSERT INTO profiles (id,name,url,created_at,updated_at) VALUES (?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, url=excluded.url,
                 updated_at=excluded.updated_at""",
            (pid, name, url, created, updated))
        c.commit()


def touch_profile(pid: str) -> None:
    with _conn() as c:
        c.execute("UPDATE profiles SET updated_at=? WHERE id=?", (_now(), pid))
        c.commit()


def _latest_scan(profile_id: str) -> dict:
    with _conn() as c:
        r = c.execute(
            "SELECT result_json FROM scans WHERE profile_id=? ORDER BY id DESC LIMIT 1",
            (profile_id,)).fetchone()
    if not r or not r["result_json"]:
        return {}
    try:
        return json.loads(r["result_json"]) or {}
    except Exception:
        return {}


def _port_list(latest: dict) -> list:
    ports = latest.get("ports") or []
    return [x.get("port") for x in ports if isinstance(x, dict) and x.get("port") is not None]


def list_profiles() -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT id,name,url,created_at,updated_at FROM profiles "
                         "ORDER BY updated_at DESC").fetchall()
    out = []
    for r in rows:
        pid = r["id"]
        latest = _latest_scan(pid)
        with _conn() as c2:
            n_scans = c2.execute("SELECT COUNT(*) n FROM scans WHERE profile_id=?", (pid,)).fetchone()["n"]
            n_poc = c2.execute("SELECT COUNT(*) n FROM poc_runs WHERE profile_id=?", (pid,)).fetchone()["n"]
        out.append({
            # UI contract (kept identical so the existing UI keeps working)
            "id": pid, "name": r["name"], "url": r["url"],
            "created_at": r["created_at"], "updated_at": r["updated_at"],
            "risk": latest.get("risk") or {},
            "host": latest.get("host"),
            "open_ports": _port_list(latest),
            "n_cve": len(latest.get("cves") or []),
            # new: professional history counts
            "scans": n_scans, "poc_runs": n_poc,
        })
    return out


def get_profile(pid: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM profiles WHERE id=? OR name=?", (pid, pid)).fetchone()
        if not row:
            return None
        pid = row["id"]
        scans = c.execute("SELECT result_json, ts FROM scans WHERE profile_id=? ORDER BY id ASC",
                          (pid,)).fetchall()
        pocs = c.execute("SELECT cve_id, ts, params_json, result_json, success FROM poc_runs "
                         "WHERE profile_id=? ORDER BY id ASC", (pid,)).fetchall()
    scan_list = []
    for s in scans:
        try: scan_list.append(json.loads(s["result_json"]))
        except Exception: scan_list.append({"raw": s["result_json"], "ts": s["ts"]})
    latest = scan_list[-1] if scan_list else {}
    # poc_results: latest result per cve (UI contract) — poc_history: full list
    latest_by_cve = {}
    for p in pocs:
        try: res = json.loads(p["result_json"])
        except Exception: res = {"raw": p["result_json"]}
        latest_by_cve[p["cve_id"]] = res
    poc_history = []
    for p in pocs:
        try: res = json.loads(p["result_json"])
        except Exception: res = {}
        poc_history.append({"ts": p["ts"], "cve_id": p["cve_id"], "success": bool(p["success"]),
                            "params": json.loads(p["params_json"]) if p["params_json"] else None,
                            "result": res})
    return {
        "id": pid, "name": row["name"], "url": row["url"],
        "created_at": row["created_at"], "updated_at": row["updated_at"],
        "scan": latest,                    # latest full scan (UI contract)
        "scans": scan_list,                # full scan history (new)
        "risk": latest.get("risk"),
        "host": latest.get("host"),
        "open_ports": _port_list(latest),
        "n_cve": len(latest.get("cves") or []),
        "poc_results": latest_by_cve,      # UI contract
        "poc_history": poc_history,        # full PoC-run history (new)
    }


def rename_profile(pid: str, name: str) -> bool:
    with _conn() as c:
        cur = c.execute("UPDATE profiles SET name=?, updated_at=? WHERE id=? OR name=?",
                        (name, _now(), pid, pid))
        c.commit()
        return cur.rowcount > 0


def delete_profile(pid: str) -> bool:
    with _conn() as c:
        cur = c.execute("DELETE FROM profiles WHERE id=? OR name=?", (pid, pid))
        c.commit()
        return cur.rowcount > 0


def find_profile_by_url(url: str) -> str | None:
    with _conn() as c:
        r = c.execute("SELECT id FROM profiles WHERE url=? ORDER BY updated_at DESC LIMIT 1",
                      (url,)).fetchone()
        return r["id"] if r else None


# ---------------------------------------------------------------------------
# scans
# ---------------------------------------------------------------------------
def record_scan(profile_id: str, url: str, result: dict) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (profile_id,url,ts,result_json) VALUES (?,?,?,?)",
            (profile_id, url, _now(), _dump(result)))
        c.execute("UPDATE profiles SET updated_at=? WHERE id=?", (_now(), profile_id))
        c.commit()
        return cur.lastrowid


def scan_history(profile_id: str, limit: int = 50) -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT id, url, ts, result_json FROM scans WHERE profile_id=? "
                         "ORDER BY id DESC LIMIT ?", (profile_id, limit)).fetchall()
    out = []
    for r in rows:
        try: res = json.loads(r["result_json"])
        except Exception: res = {}
        out.append({"id": r["id"], "ts": r["ts"], "url": r["url"],
                    "risk": (res or {}).get("risk"), "cve_count": len((res or {}).get("cves") or [])})
    return out


# ---------------------------------------------------------------------------
# PoC runs
# ---------------------------------------------------------------------------
def record_poc_run(profile_id: str | None, cve_id: str, params: dict, result: dict) -> int:
    success = 1 if (result or {}).get("success") else 0
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO poc_runs (profile_id,cve_id,ts,params_json,result_json,success) "
            "VALUES (?,?,?,?,?,?)",
            (profile_id, cve_id, _now(), _dump(params) if params else None,
             _dump(result), success))
        c.commit()
        if profile_id:
            c.execute("UPDATE profiles SET updated_at=? WHERE id=?", (_now(), profile_id))
            c.commit()
        return cur.lastrowid


def poc_history(profile_id: str = None, limit: int = 100) -> list[dict]:
    q = ("SELECT id, profile_id, cve_id, ts, params_json, result_json, success FROM poc_runs ")
    args = []
    if profile_id:
        q += "WHERE profile_id=? "; args.append(profile_id)
    q += "ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    with _conn() as c:
        rows = c.execute(q, args).fetchall()
    out = []
    for r in rows:
        try: res = json.loads(r["result_json"])
        except Exception: res = {}
        out.append({"id": r["id"], "profile_id": r["profile_id"], "cve_id": r["cve_id"],
                    "ts": r["ts"], "success": bool(r["success"]),
                    "params": json.loads(r["params_json"]) if r["params_json"] else None,
                    "result": res})
    return out


# ---------------------------------------------------------------------------
# migration from legacy db/profiles.json
# ---------------------------------------------------------------------------
def migrate_from_json() -> int:
    pjson = os.path.join(DB, "profiles.json")
    if not os.path.exists(pjson):
        return 0
    with _conn() as c:
        n = c.execute("SELECT COUNT(*) n FROM profiles").fetchone()["n"]
    if n > 0:
        return 0  # already migrated
    try:
        with open(pjson, encoding="utf-8") as f:
            legacy = json.load(f)
    except Exception:
        return 0
    if isinstance(legacy, dict):  # {"profiles": [...]} (legacy core.py shape)
        legacy = legacy.get("profiles", [])
    moved = 0
    for prof in legacy or []:
        if not isinstance(prof, dict):
            continue
        pid = prof.get("id") or prof.get("name")
        if not pid:
            continue
        created = prof.get("created_at") or prof.get("created") or _now()
        updated = prof.get("updated_at") or prof.get("updated") or created
        save_profile(str(pid), prof.get("name", str(pid)), prof.get("url", ""),
                     created=created, updated=updated)
        # legacy stored a single 'scan' (or a 'scans' list) — import both
        scans = prof.get("scans")
        if scans is None and prof.get("scan") is not None:
            scans = [prof["scan"]]
        for s in (scans or []):
            if isinstance(s, dict):
                record_scan(str(pid), prof.get("url", ""), s)
        for cve, res in (prof.get("poc_results") or {}).items():
            if isinstance(res, dict):
                record_poc_run(str(pid), cve, None, res)
        moved += 1
    if moved:
        log("INFO", "store", f"migrated {moved} legacy profile(s) from profiles.json into SQLite")
    return moved


if __name__ == "__main__":
    init()
    print(f"store initialized: {DB_PATH}")
    print("profiles:", [p["id"] for p in list_profiles()])
