# Contributing to P2S

Thanks for your interest! P2S is a security-research toolkit, so contributions are
welcome in the code and database areas — **not** in the archived research data.

## What we accept

- Bug fixes and features for `core.py`, `server.py`, `store.py`, `mcp_server.py`,
  `poc/` (as validators), the `web/` UI and `local-checker-ext/`.
- New CVE entries / corrected metadata in `db/vulns.json` and `db/exploits.json`
  (cite the advisory or EDB entry; keep command templates lab-safe).
- Lab target improvements under `targets/` (Dockerfiles must publish ports on
  `127.0.0.1` only).
- Documentation fixes anywhere except `research/` (see below).

## What we do not accept

- Changes, additions or "extensions" to `research/` — it is a frozen archive of a
  completed study against owner-controlled labs. New vulnerability research belongs
  in your own repository; we happily link to published write-ups from README badges
  or issue discussions.
- PoCs targeting real-world third parties, credential material, or anything that
  lowers the guardrails (localhost binding, path validation, etc.).
- Personal data: hostnames, public IPs, usernames, cloud instance IDs, tokens. Run
  `git grep -iE 'C:\\Users|LAB_IP'` before pushing if unsure.

## Development workflow

```bash
python3 -m py_compile core.py server.py store.py mcp_server.py poc/*.py   # syntax gate
python3 server.py            # API + UI at http://127.0.0.1:8123
npm --prefix web install && npm --prefix web run build   # optional React rebuild
```

- Python: stdlib only — no new runtime dependencies without discussion.
- Style: follow existing conventions; every public function keeps an explanatory
  docstring/comment block (English).
- Tests: add a minimal check when touching scanner/risk-score logic
  (`python3 -c "import core; ..."` smoke commands are fine at this stage).

## Pull requests

1. Branch from `main`: `feat/<short-name>` or `fix/<short-name>`.
2. One logical change per PR; describe *what* and *why* in the body.
3. Ensure `git status` shows no runtime artifacts (`session.db`, logs, `__pycache__`).
4. CI-equivalent local checks must pass (compile + server boot + scan smoke test).

## Reporting issues

- Scanner bugs / feature requests → public issue.
- Anything with security implications in this repo itself → see `SECURITY.md`
  (private advisory). Vulnerabilities in PHP/Tomcat/etc. → report to the vendor.

By contributing you confirm you have the rights to the material you submit and that
your contribution complies with the intended-use policy in `SECURITY.md`.
