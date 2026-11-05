# Patchwatch · PHP2Shell Observatory

A static HTML/CSS/JavaScript dashboard and repeatable Node.js collection scripts. No AI API, runtime backend, or paid service is required. Includes a real Awesome Selfhosted snapshot with **1,358 projects, 1,131 GitHub-star-ranked repositories, and a growing PHP-component inventory** at initial collection on 22 October 2026. Counts change with the upstream catalogue.

The overview shows **automatic published-image results**, not a manual verification queue. The project inventory includes any evidenced PHP component, dependency, service or tooling, regardless of whether the primary language is Python, JavaScript, Go or something else. PHP examples and development tooling are labelled separately from production runtimes.

## Start locally

Requires Node.js 20 or newer and Git. Docker is optional, for local image inspection only.

```sh
npm ci
npm run dev
```

Open `http://127.0.0.1:4173`. You can also open `dist/index.html` directly; its bundled JS snapshot works without a server. Snapshot reload works over HTTP. The interface uses Google Fonts with local fallbacks; it remains usable without those fonts.

Run `node scripts/package-toolkit.mjs` to regenerate the dashboard's downloadable ZIP after extracting this toolkit or updating its source. The packager uses Node built-ins, excludes Site identity, credentials and local reports, and does not recursively include itself.

## Refresh without AI

```sh
npm run refresh
```

This clones/updates the public Awesome Selfhosted data and NCSC-NL PHP2Shell repositories, checks PHP dependency declarations, polls GitHub releases within a request budget, retrieves Docker Hub tag metadata, and regenerates `dist/data/projects.json`, `projects.js` and a snapshot history. The script never executes code downloaded from those repositories.

Default GitHub budget: 24 requests without a token, 250 with `GITHUB_TOKEN`. Source-file checks and public Docker Hub requests have separate limits and short timeouts. Failed metadata requests retain catalogue or cached values; warnings and dates are retained. API ETags and PHP checks are cached under `.cache/`. Lower budgets prioritize repositories not recently checked, then GitHub stars. A keyword mention of a CVE only creates a review candidate, never a confirmed fix.

For all PHP GitHub repositories in one pass, provide a GitHub token through the environment and increase the budget. No special repository write permissions are needed to read public metadata.

```powershell
# Set GITHUB_TOKEN securely in your shell environment first; never put it in config files.
node scripts/refresh.mjs --budget 600
```

Other modes:

```sh
# Rebuild from existing clones and caches, without network requests
node scripts/refresh.mjs --offline

# Use existing upstream checkouts
node scripts/refresh.mjs --catalog /path/to/awesome-selfhosted-data --ncsc /path/to/php2shell --budget 24

npm run check
npm test
```

At least 1,000 GitHub-ranked records are required before publishing a generated snapshot. Without a full budget, star counts and release data are a mixture of dated catalogue and API records, rather than a claim that every repository was queried live.

## Any PHP component counts

The discovery script searches all GitHub repositories, without a primary-language filter. It reads recursive file trees and inspects nested Composer manifests, PHP source file paths, Dockerfile PHP installs and base images, Compose PHP services, and PHP development tooling. It does not execute repository code.

```sh
# Uses your existing authenticated GitHub CLI token in memory only
node scripts/discover-php.mjs --use-gh --budget 1200
# Or provide GITHUB_TOKEN in the environment
node scripts/discover-php.mjs --budget 1200
npm run refresh
```

Source findings are cached for seven days in `.cache/scope.json`. Bounded API budgets and truncated/error flags are recorded. PHP files may be optional SDKs, plugins, examples or tests; these still enter the inventory, but do not automatically mean a deployed application is vulnerable. Exact source paths and roles are retained. A missing finding is not proof that every plugin, image or dependency is PHP-free.

The initial expanded run inspected 1,133 GitHub file trees. Pi-hole's old catalogue PHP declaration is suppressed for its v6 server, but fresh evidence of a separate PHP component would still be included.

## Automatic published-image verification

The public [automation repository](https://github.com/YoungOnef/php2shell-observatory-data) runs GitHub Actions every six hours. The live dashboard automatically reads its project and verification JSON and polls for updates every five minutes while open. No AI calls, local Docker installation, manual checks or user API keys are needed to view results.

The runner resolves each published image to its immutable **linux/amd64** digest and executes version queries against installed PHP CLI, FPM and CGI binaries in a restricted container. No host mounts or network access are supplied to the probed image. It drops capabilities, uses no-new-privileges, restricts resources and uses a read-only filesystem. Changed digests are rechecked; unchanged digests reuse prior results.

- **Fixed image available:** every queried PHP runtime meets the official upstream fix for both CVEs.
- **Update required:** a queried runtime is below the upstream fixed version, and no vendor backport has been automatically confirmed. This is a conservative update recommendation, not a claim that version numbers disprove vendor backports.
- **Automatic scan failed:** the probe could not establish a verdict. The error is recorded and retried by the scheduler. Failure is never treated as fixed or vulnerable.
- **Host PHP patch available:** PHP is external to any identified image, so the application release cannot establish an image runtime verdict.
- **PHP component present:** source or optional/development PHP exists; this alone does not establish a deployed runtime.

Results describe the exact published digest and queried runtime binaries, not your already-running deployment or all other architectures. Vendor-backported builds and unqueryable web modules remain limitations.

Public machine-readable feeds:

- `https://raw.githubusercontent.com/YoungOnef/php2shell-observatory-data/main/dist/data/projects.json`
- `https://raw.githubusercontent.com/YoungOnef/php2shell-observatory-data/main/dist/data/verified-images.json`

Run your own image verification with `node scripts/verify-images.mjs`. Unlike the optional local audit importer, this publishes no local running-container inventory.

## What “Fix available” means

The PHP advisory identifies **CVE-2026-109618 and CVE-2026-109619**, fixed upstream in:

| PHP branch | Fixed upstream version |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Sources: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5), [first PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [second PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

The dashboard imports exact product-name matches from NCSC-NL's published software tables. Both CVE columns must say `Fix` before a scoped fix is shown. Those tables are generated upstream from its SPDX/VEX inventory. Evidence links pin the source commit and include vendor references and complete scope notes. A pending record means no imported fix confirmation, not confirmed vulnerability. Entries may cover a particular build, runtime, distribution, or container family. Always read the detail.

An application release does not establish that its PHP runtime was updated. PHP version checks cannot establish whether an older version has a vendor backport. The published-image scanner recommends an update for unsupported or prerelease builds, with the reason recorded. Ambiguous builds and branches without a verified fix threshold produce inspection errors. An update recommendation is not proof of exploitability, and vendor backports require separate package evidence. Edit `config/advisory.json` only after checking upstream advisories.

Reviewed evidence can be added to `config/evidence.json`:

```json
{
  "schemaVersion": 1,
  "entries": [{
    "repo": "owner/repository",
    "status": "patched",
    "scope": "The exact release/build/distribution covered",
    "version": "Exact fixed version or immutable build",
    "cves": ["CVE-2026-109618", "CVE-2026-109619"],
    "source": "https://vendor.example/security/advisory",
    "checkedAt": "2026-10-22T00:00:00Z",
    "notes": "What the source confirms and any excluded deployments"
  }]
}
```

The example is a schema illustration, not a real patch claim. The shipped file has no fabricated entries. An invalid evidence record fails generation. Manual evidence never promotes a non-PHP application.

## Docker image inspection

`config/images.json` maps selected PHP projects to documented image publishers. Mappings are curated references, not endorsements or a complete list. Docker Hub's API supplies digests, per-platform manifests and tag timestamps when available. Other registries can be inspected locally. Registry metadata by itself never establishes a fix. The separate automatic hosted runner queries PHP binaries in the exact image digest and supplies the displayed fixed/update/error verdict.

Inspect your running containers (runs a harmless PHP version query with `docker exec`):

```sh
node scripts/audit-docker.mjs --containers
```

Inspect one image. Execution and optional pulling are explicit:

```sh
node scripts/audit-docker.mjs --image nextcloud:latest --run-images --pull
```

An image run uses the immutable inspected ID, no network, a read-only filesystem, a non-root user, dropped capabilities, no-new-privileges, and memory/process limits. Some images will not work under these restrictions or lack PHP CLI; these results remain **unknown**. It never automatically installs updates, changes your containers, mounts the host filesystem or sends exploit requests.

The report records the exact image ID, repository digests, architecture, PHP binary, SAPI, version and timestamp. **It describes CLI only.** PHP-FPM, Apache or other web-serving SAPIs can use a different build; verify them separately. Vendor backports require vendor evidence. The dashboard does not combine a local report with shared patch claims.

Output: `reports/audit.json`. On the Docker images view choose **Import local audit** to view that JSON in the browser. Import stays browser-local and is never uploaded. `--out /path/report.json` changes the output location.

## Schedule / share

The included `.github/workflows/refresh-inventory.yml` and `verify-images.yml` are conventional GitHub Actions workflows with six-hour schedules and manual dispatch. They are already enabled in the public automation repository. The older `refresh.yml` is a manual utility workflow. You can also copy the workflows to your own repository. It uses `GITHUB_TOKEN` supplied by Actions, caches network results, refreshes all PHP metadata, tests the data and commits changed snapshots. If your default branch is protected, adapt the commit step to your pull-request policy. The public inventory and runtime-check workflows are active in YoungOnef/php2shell-observatory-data; local copies are provided for reuse.

For cron on an existing host:

```cron
17 */6 * * * cd /absolute/path/php2shell-observatory && /usr/bin/node scripts/refresh.mjs --budget 600 >> refresh.log 2>&1
```

Provide a token via your scheduler's secret environment if needed. Do not expose an HTTP endpoint that runs Docker or a shell. Serve only `dist/`. The hosted page combines its bundled snapshot with the live public automatic result feed. The public repository workflows are enabled and scheduled; the local workflow copies can also be used for self-hosting. Watchlists are browser-local.

## Self-host the dashboard

Any static web server can serve `dist/`. An optional nginx image is included:

```sh
docker build -t php2shell-observatory .
docker run --rm -p 8080:80 php2shell-observatory
```

This image serves the dashboard only. Refresh the data and rebuild when you want an updated container snapshot, or serve a mounted `dist` directory from your existing web server.

## Files / licenses

- `dist/`: static website, snapshot, source license copies, downloadable toolkit.
- `scripts/refresh.mjs`: catalogue, source verification, release and registry collection.
- `scripts/audit-docker.mjs`: local CLI runtime inspection.
- `scripts/core.mjs`: PHP branch/version assessment and evidence rules.
- `config/`: upstream fixed versions, source exclusions, reviewed evidence and image mappings.
- `tests/`: version boundaries, unknown builds, PHP scope, evidence requirements and real catalogue integrity.
- `THIRD_PARTY_NOTICES.md`: attribution and data license details.

New application code: MIT. Awesome Selfhosted catalogue adaptation: CC BY-SA 3.0. Imported NCSC inventory evidence: EUPL 1.2; consult upstream for reuse terms. License copies remain in `dist/licenses/` and all imported records retain source references.


### Independent validation and image ownership

Published project images and PHP companion or development images carry separate roles. A fixed project image can coexist with an old optional companion; the table shows the companion warning and its exact image separately. Projects without a mapped primary image retain the PHP component verdict. Shlink v5.1.8 is an example: its own image contains PHP 8.5.12, while its development Compose references an older Matomo image.

The hosted verifier now requests a harmless PHP JSON page through installed Apache modules, FPM or CGI in isolated containers, and records web SAPI evidence alongside CLI versions. Generated probe files are the only read-only host mount. It records operating-system and installed PHP package revisions for backport assessment. RoadRunner worker commands are recorded where present. Failed web probes produce scan errors and retry automatically; version results never establish exploitability or the state of an existing deployment.

An additional independent Python spot check lives in the public automation repository, with its fixed random seed, pinned image digests, full outputs and a manual workflow. It does not import the JavaScript classifier. The dashboard and regular collection process remain HTML/CSS/JavaScript and use no AI calls.
