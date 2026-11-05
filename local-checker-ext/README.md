# PHP2Shell Local Checker (unpacked Chrome extension)

A **local, offline, no-auth** variant of the "PHP Vulnerability Checker" browser
extension. The original cloud version depended on a remote vendor API, Google OAuth
and billing — and refused to check local hosts. This variant needs none of that.

## Flow (v1.2)

1. Opening the popup **auto-captures the active tab URL** (`activeTab` permission).
2. The target is **fetched live** — PHP version extracted in order:
   `X-Powered-By` → `Server` header → body markers.
   **Changing IP/port is fine: the target is re-queried every time** (no static host DB).
3. The detected version is looked up in the **version-based local database**
   (`data/db.json`) → php2shell risk note.
4. **No remote API**, **no auth**, **no analytics**, **no update_url**.

## Installation (Load unpacked)

1. Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select this directory: `local-checker-ext`
4. On any PHP-target tab (e.g. `http://127.0.0.1:18101`) click the toolbar icon →
   automatic check.

## Certificates (TLS)

- **Plain HTTP targets** (lab ports 18101–18114, 18120): work directly, no cert needed.
- **Self-signed HTTPS:** browser fetch cannot bypass TLS validation → the error tells
  you to use an `http://` URL.
- Remote targets with valid certificates work.

## Data: `data/db.json` (single editing point)

```jsonc
{
  "cve": "CVE-2026-109618/19 (php2shell)",
  "rules":  { "eolBefore": [8,2], "fixedBranch": null },   // fallback for branches missing from map
  "versions": {                                            // branch (major.minor) -> status
    "8.4": { "status": "POTENTIAL_RISK", "note": "..." },
    "8.6": { "status": "CONFIRMED_FIXED", "note": "..." }  // add once a fixed branch is verified
  }
}
```

- **Version detection never depends on rules** — the true version is always shown live.
- The risk label comes from `versions[branch]`; unknown branches fall back to `rules`.
- `status` values: `EOL_NO_PATCH`, `POTENTIAL_RISK`, `CONFIRMED_FIXED`, `DISTRO_BUILD`,
  `NO_KNOWN_INDICATORS`.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 — `storage` + `activeTab` + host permissions `http(s)://*/*` |
| `data/db.json` | **version-based risk DB** (the place to edit) |
| `lib/version.js` | version parsing + rule scoring (pure functions) |
| `lib/check.js` | live target probe (timeouts, error messages, probe paths) |
| `lib/lookup.js` | db.json version queries |
| `popup.html/css/js` | UI |

## Verified against live lab targets (Node harness, 2026-10-24)

```
127.0.0.1:18101 → PHP/5.4.45  (X-Powered-By) → EOL_NO_PATCH
127.0.0.1:18113 → PHP/8.4.26  (X-Powered-By) → POTENTIAL_RISK (baseline)
127.0.0.1:18120 → PHP/8.4.26  (Server header) → POTENTIAL_RISK
```
