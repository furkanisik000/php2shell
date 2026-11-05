# Documentation index

**PHP2Shell Unchained** — technical manuals for the lab. The repository [README](../README.md) is the entry point (English); several deep guides are in German (`DE`) to match operator workflows in the project.

## Start here

| Audience | Document |
|----------|----------|
| Everyone | [../README.md](../README.md) — overview, badges, quick start |
| Operators | [DOCUMENTATION.md](DOCUMENTATION.md) — full command & compose reference |
| Sec / patch validation | [WORKAROUNDS-SCHRITT-FUER-SCHRITT.md](WORKAROUNDS-SCHRITT-FUER-SCHRITT.md) + [PATCH-BYPASS-AUDIT.md](PATCH-BYPASS-AUDIT.md) |
| Exploit routing | [EXPLOIT-CHAIN-COMPARISON.md](EXPLOIT-CHAIN-COMPARISON.md) |
| Phased lab flow | [HOWTO-DE.md](HOWTO-DE.md) |
| Cursor IDE | [CURSOR-INTEGRATION.md](CURSOR-INTEGRATION.md) |
| LKM module | [SINGULARITY-LAB.md](SINGULARITY-LAB.md) |
| Policy | [../SECURITY.md](../SECURITY.md) |

## Validation runbook

```bash
vtbw-php2shell-lab validate    # Full-Stack-Matrix (nicht-interaktiv, ~15–45 min)
```

Ergebnisse: `out/validation/<UTC>/` (`session.log`, `matrix.jsonl`, `AUSWERTUNG.md`). MCP-Parität der Server-Datei: `python3 mcp/mcp_parity_client.py <tool> '<json-args>'` (z. B. `lab_status`, `{}`). Nach Änderungen an `mcp/php2shell_lab_mcp.py` die laufende Cursor-MCP-Instanz neu laden (Settings → MCP → Reload), sonst arbeitet sie mit altem Code.

## External references (PHP2Shell)

- [Calif Research — PHP2Shell](https://calif.io/php2shell/)
- [PHP.net — 2026 security archive](https://www.php.net/archive/2026.php)
- [CERT-EU — 2026-018](https://www.cert.europa.eu/publications/security-advisories/2026-018/)
- [NVD CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
- [NVD CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)
