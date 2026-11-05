---
name: php2shell-unchained
description: >-
  Steuert das PHP2Shell-unchained Docker-Lab nach dem Menüpfad [1] FPM, [2] Zer061
  oder [3] Jackalsyn, [4] Multi, [5] lukechilds, [6] Sliver C2 + External
  (Tunnel + Tor-Verschleierung), [7] Singularity, [8] Patch-Audit (WAF Top-10).
  Nutze bei php2shell-lab-vtbw, vtbw-php2shell-lab, zer061, sliver, cloudflared,
  tor, external, patch-audit, singularity, CVE-2026-109618, oder MCP php2shell-unchained.
---

# PHP2Shell — unchained (Agent Skill)

**By Leviticus-Triage** — nur isoliertes Lab oder ausdrücklich erlaubte Ziele.

## Pfad (Menü = HOWTO)

1. **[1] FPM** — `up` → `test` → `rce` → `shell` (Chain A, www-data). `doctor`/`monitor` = Diagnose.
2. **[2] Zer061** oder **[3] Jackalsyn** — Heap-Kit (`zer061-shell`) bzw. `fetch-jackalsyn` → `selftest` → `lab`.
3. **[4] Multi** — `apache-multi-up`, `scan`, `fingerprint`, `exploit-list`.
4. **[5] Reverse Shell** — lukechilds. Nicht `zer061-shell` aus [2] verwechseln.
5. **[6] Sliver C2 + External** — `fetch-sliver` → `server-up` → `operator` → `listener` → `implant` → `stage`. **External-Modus:** `external up [--tor]` = beide Tunnel (web + sliver-http) + HTTPS-Listener + state.env; mit `--tor` läuft Tunnel-Aufbau UND Audit-Traffic über Tor-Exit (Host-IP verschleiert, Beweis: `tor ip`). Externes C2: `sliver implant-external` (HTTPS → Tunnel-Host). Einzeln: `tunnel up web|sliver-http [--tor]`.
6. **[7] Singularity** — nach Shell: `fetch-singularity` → `runtime` → vm/host/container. Nie im PHP-Container.
7. **[8] Workarounds + Patch-Audit** — Einstieg: `workarounds run` (geführt, nur Terminal 1, Log+Auswertung in `out/workarounds/<UTC>/`), `workarounds auto` = Baseline, `workarounds last`. Einzelchecks: `patch-audit list|run|logs`. Extern: `external patch-audit <id>`. JSONL `out/audit/patch-audit.jsonl` (Feld `proxy`). Terminal 2 nur bei shell/console/listener/logs.
8. **[9] Docs/Tools**, **[d] Docker** (`logs target|apache|singularity|sliver|tunnel|tunnel-sliver|tor`, `down` inkl. sliver/tunnel/tor + external state).

## MCP

- `lab_help`, `lab_status`, `lab_run`, `lab_read_doc`, `lab_exploit_map`
- `lab_run(command, subcommand, extra)`
  - `sliver`: subcommand `server-up|operator|listener|http-listener|implant|implant-external|stage|console|ops|down`
  - `tunnel`: subcommand `up|url|status|down`, extra = `web|sliver-http` (`--tor` möglich)
  - `external`: subcommand `up|status|url|env|patch-audit|down`, extra = `--tor` bzw. Szenario
  - `tor`: subcommand `up|ip|status|log|down`
  - `logs`: subcommand `target|apache|singularity|sliver|tunnel|tunnel-sliver|tor`
  - `patch-audit`: `subcommand=run`, extra = Szenario (`waf-bypass-top10`, `vendor-patch`, `all`). `logs` liest JSONL.
  - `workarounds`: subcommand `run|auto|last|logs|guide`, extra = einzelne Schritt-ID
- Docs: `HOWTO-DE`, `WORKAROUNDS`, `SINGULARITY`, `PATCH-AUDIT`, `EXPLOIT-CHAIN`, `CURSOR`

## Agent-Regeln

- Nur Wrapper oder `lab_run`. Keine Produktions-URLs ohne Freigabe.
- `fetch-*` vor Kit-Befehlen. `third_party/` ist nicht im Git.
- Sliver/Singularity nur nach RCE und nur im Lab. Singularity-Build nur mit `CONFIRM_SINGULARITY_*`.
- Tunnel nur gegen Lab-Ziele; die trycloudflare-URL immer mitloggen (out/tunnel/ops.log).
- External/Tor: Grenzen kennen — ohne `--tor` sieht Cloudflare die Host-IP; mit `--tor` nur Tor-Exits (höhere Latenz). `external down [--tor]` aufräumen.

Volltext: `docs/CURSOR-INTEGRATION.md`, `docs/HOWTO-DE.md`
