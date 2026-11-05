# SECURITY.md — Usage Policy & Responsible Disclosure

## Intended use

P2S is a **defensive security-research toolkit**. It is meant to be run by
professionals against systems they own or have explicit, written authorization to
test — typically the disposable Docker lab targets shipped in this repository.

Using this software against infrastructure without permission is illegal in most
jurisdictions and violates the terms under which this project is published. The
maintainers do not condone or support unauthorized use.

## Scope of what we publish

- Scanner, risk model, web UI, MCP server: detection and assessment only.
- `poc/` modules: **validators** that confirm a weakness class against a target you
  explicitly point them at; they return verifiable evidence for reporting purposes.
- `research/`: archived findings from authorized research on owner-controlled labs,
  including per-version exploitability analysis of the php2shell CVEs. Published so
  defenders understand which builds are affected and why patched releases matter.

## Reporting vulnerabilities

If you find a vulnerability **in PHP, Tomcat, MySQL, or other third-party software**
referenced here, report it to that vendor's security team through their official
channels (e.g. <https://www.php.net/reportbug.php>). Coordinated disclosure protects
users and is the path that actually gets things fixed.

If you believe you found a security issue **in this repository itself** (for example
a flaw in the API server, extension, or scanner logic), please open a private GitHub
security advisory instead of a public issue: **Security → Report a vulnerability**
on the repository page. We aim to acknowledge within 5 business days.

## Hardening guidance for running P2S

1. Keep the API server bound to `127.0.0.1` (default). Never expose port 8123 to an
   untrusted network; there is no authentication built in.
2. Run lab targets with localhost-published ports (`-p 127.0.0.1:PORT:PORT`).
3. Do not store scan results containing real client data in this repo; runtime state
   (`db/session.db`, logs) is git-ignored for exactly this reason.
4. Review `upstream-reference/` licenses before reusing any external code.
5. Delete vulnerable containers after each session — they are intentionally exploitable.

## Patch-first advice (php2shell family)

The researched chain affects pre-patch PHP builds. Upgrade PHP to **≥ 8.4.27 / ≥ 8.5.12**
(or your distribution's patched package); as interim mitigation disable
`session.upload_progress.enabled` and set `session.use_strict_mode=1`. Detection in
P2S is complementary — patching is the fix.
