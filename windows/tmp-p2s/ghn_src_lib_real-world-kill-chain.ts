export interface RequestStep {
  method: string;
  path: string;
  contentType: string;
  /** What the body conceptually contains — deliberately redacted, never the real structure/values. */
  bodyNote: string;
  /** What happens server-side once this request lands. */
  resultNote: string;
  /** True if this step is a dangerous/critical moment, for visual emphasis. */
  critical?: boolean;
}

export interface IncidentTechnique {
  id: string;
  name: string;
  detail: string;
  defense: string;
  /** An animated, redacted request sequence showing the shape of the exploit without its working content. */
  requests?: RequestStep[];
  finalResult: string;
}

export interface IncidentStage {
  id: string;
  order: number;
  title: string;
  shortLabel: string;
  detail: string;
  /** Narrated log-style lines — events and conceptual mechanism, never a reproducible trigger/payload. */
  logLines: string[];
  colorFrom: string;
  colorTo: string;
  /** The two CVEs broken out as individually expandable cards, at this stage. */
  techniques?: IncidentTechnique[];
  /** Honest, non-exploit code: what being unpatched vs. patched actually looks like in your infra. */
  example?: {
    vulnerable: string;
    secure: string;
    language?: string;
  };
  /** Headline stats for this stage, shown as a card grid instead of a bullet list. */
  stats?: { value: string; label: string }[];
}

export const REAL_WORLD_STAGES: IncidentStage[] = [
  {
    id: "disclosure",
    order: 1,
    title: "Emergency Disclosure",
    shortLabel: "Disclosure",
    detail:
      "Both bugs were found by security firm Calif, working with OpenAI and Wiz as part of OpenAI's \"Patch the Planet\" initiative — an AI-assisted audit effort the PHP Foundation (via Volker Dusch) opted into. On October 21, 2026, PHP shipped out-of-band patches for both, coordinated with disclosure. Exploitation in the wild began within hours regardless.",
    logLines: [
      "[2026-07-30 UTC] Calif + OpenAI + Wiz begin coordinated PHP audit w/ PHP Foundation",
      "[2026-08-01 UTC] first exploitable OOM-fatal surfaced within days of starting",
      "[2026-10-20 UTC] php.net posts advance notice of an upcoming critical release",
      "[2026-10-21 14:00 UTC] php.net: emergency release — 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35",
      "[2026-10-21 UTC] first public reports of active exploitation attempts",
      "[2026-10-22 UTC] NSA / UK NCSC issue joint advisory",
    ],
    colorFrom: "#a5aed6",
    colorTo: "#8993be",
  },
  {
    id: "the-flaw",
    order: 2,
    title: "Two Unauthenticated RCEs",
    shortLabel: "The Flaw",
    detail:
      "The root cause is one general pattern, exploited two different ways. Deep in PHP's internals, some operations mark a piece of memory as \"ready to use\" before they've actually finished setting it up. If an out-of-memory error interrupts that exact window, PHP's own cleanup code — which runs even during a fatal — ends up trusting and acting on a half-built, not-fully-initialized piece of state. That's the whole bug, expressed two ways against two different PHP deployment modes. Tap each one below.",
    logLines: [
      "[analysis] root cause — a value is marked 'ready' before it's fully initialized",
      "[analysis] an out-of-memory fatal at that exact moment skips the rest of setup",
      "[analysis] PHP's own cleanup code still trusts and acts on the half-built value",
      "[note] exploitation specifics withheld — see cited research for the full technical writeup",
    ],
    colorFrom: "#8993be",
    colorTo: "#6c76a8",
    techniques: [
      {
        id: "modphp-path",
        name: "Apache / mod_php — dangling request-variable entry",
        detail:
          "A specially crafted file-upload request can push PHP's memory usage past its configured limit while the request body itself stays small, by exploiting how PHP expands deeply nested form-field names into many internal lookup-table entries. If that memory limit is hit at exactly the moment PHP is registering one of those entries, the entry is left half-built — but PHP's internal bookkeeping already counted it as valid. When the request ends, PHP's normal teardown logic processes that half-built entry as if it were real, which an attacker can turn into code execution.",
        defense: "No app-level fix exists — this is inside the interpreter. PHP's advisory lists partial reductions if you truly can't patch yet (force memory_limit=-1 via php_admin_value, cap post_max_size), but only upgrading to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 closes it.",
        finalResult: "Half-built entry processed as real during teardown → attacker-influenced execution",
        requests: [
          {
            method: "POST",
            path: "/upload.php",
            contentType: "multipart/form-data; boundary=…",
            bodyNote: "deeply nested field names — exact structure withheld",
            resultNote: "PHP expands the nesting into many internal table entries while parsing",
          },
          {
            method: "—",
            path: "(same request, still parsing)",
            contentType: "—",
            bodyNote: "memory usage climbs past the configured limit mid-registration",
            resultNote: "Fatal hits exactly between \"mark entry live\" and \"finish building it\"",
            critical: true,
          },
        ],
      },
      {
        id: "fpm-path",
        name: "PHP-FPM — stale session state reused across requests",
        detail:
          "PHP-FPM keeps worker processes alive across many requests for performance, and its \"upload progress\" feature can start tracking a session before the rest of PHP has finished initializing for that request. If a request is interrupted at just the right point, PHP frees that request's memory but leaves global pointers still referencing it — and because the worker survives, a second, unrelated request can reach those dangling pointers through the same upload-progress feature and cause PHP to treat freed memory as live data again.",
        defense: "Same fix: upgrade PHP. If you truly can't yet, PHP's own advisory recommends setting session.upload_progress.enabled=0 in php.ini or your FPM pool config (not via ini_set() or .user.ini) and restarting every worker — this blocks the confirmed path, not variants, and isn't a substitute for patching.",
        finalResult: "Second request's cleanup logic treats freed memory from the first as live session data",
        requests: [
          {
            method: "POST",
            path: "/page.php",
            contentType: "multipart/form-data; boundary=…",
            bodyNote: "session ID + upload-progress field + a file part — trigger timing withheld",
            resultNote: "Session tracking starts early, then this worker's request is interrupted",
            critical: true,
          },
          {
            method: "POST",
            path: "/page.php",
            contentType: "multipart/form-data; boundary=…",
            bodyNote: "same session ID + upload-progress field, no file part this time",
            resultNote: "Reaches cleanup logic for the earlier session on the same worker",
          },
        ],
      },
    ],
  },
  {
    id: "blast-radius",
    order: 3,
    title: "Why It Spread So Fast",
    shortLabel: "Blast Radius",
    detail:
      "There is no configuration-only workaround — upgrading PHP itself is the only fix. PHP powers roughly 70–77% of server-side websites, and because the bug lives in the interpreter rather than a plugin or library, it hit WordPress installs, custom enterprise apps, and everything between at the same time. Multiple governments and major platforms took services offline as a precaution while patching.",
    logLines: [
      "[impact] ~70-77% of public web servers run PHP",
      "[impact] Wikipedia, Internet Archive briefly taken offline as a precaution",
      "[impact] 300+ government sites audited in Pakistan alone",
      "[impact] advisories issued: NSA, UK NCSC, Japan PM's office",
    ],
    colorFrom: "#6c76a8",
    colorTo: "#4f5b93",
    stats: [
      { value: "70–77%", label: "of public web servers run PHP" },
      { value: "5", label: "deployment modes affected — FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed" },
      { value: "300+", label: "government sites audited (Pakistan alone)" },
      { value: "NSA · NCSC", label: "national agencies issued advisories" },
    ],
  },
  {
    id: "the-fix",
    order: 4,
    title: "Patch Status",
    shortLabel: "The Fix",
    detail:
      "Fixes landed the same day across every supported branch. PHP 8.1 and earlier no longer receive regular updates — but given the severity, the PHP security team also released minimal source-backports for 7.4, 8.0, and 8.1, so even unsupported branches have an option beyond a full migration. PHP 8.2 itself still reaches end-of-life on December 31, 2026 regardless of this patch. The only complete fix is the version itself; here's what that looks like in practice.",
    logLines: [
      "[fix] PHP 8.5.12 — patched",
      "[fix] PHP 8.4.27 — patched",
      "[fix] PHP 8.3.36 — patched",
      "[fix] PHP 8.2.35 — patched (EOL 2026-12-31)",
      "[backport] minimal source-backports released for 7.4 / 8.0 / 8.1 given severity",
    ],
    colorFrom: "#4f5b93",
    colorTo: "#363f6e",
    example: {
      language: "dockerfile",
      vulnerable: `# Dockerfile
FROM php:8.3-fpm
# Floating tag — silently rebuilds on whatever 8.3.x patch
# release existed when the image was last pulled. If that
# was before Oct 21 2026, you're still exposed.`,
      secure: `# Dockerfile
FROM php:8.3.36-fpm
# Pinned to the patched release (or newer). Rebuild and
# redeploy — a floating tag alone does not retroactively
# patch a container that's already running.

# composer.json
# "config": { "platform": { "php": "8.3.36" } }
# forces CI/local installs to match, catching drift early.`,
    },
  },
];
