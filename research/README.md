# `research/` — Authorized Vulnerability Research Archive

Read-only material from the php2shell (EDB-52704 / CVE-2026-109618, CVE-2026-109619)
cross-version study. Everything here was executed **only** against disposable,
owner-controlled Docker lab containers on a private network. This folder is not part
of the P2S package and nothing in it is imported by the scanner.

📄 **Start here:** [`RESEARCH_REPORT.md`](RESEARCH_REPORT.md) — the single consolidated
report: what was built, every experiment tried, which errors/dead-ends were hit, final
per-version verdicts and how to reproduce.

## Layout

```
research/
├── RESEARCH_REPORT.md   # consolidated deep-dive report (start here)
├── github-survey/       # scripts/output of the public-repo ecosystem survey
├── notes/               # English summaries: lab setup guides + target matrix
│   ├── SETUP_WINDOWS_AMD64.md   # why native amd64 (WSL2) and how to build that lab
│   ├── DOCKER_TEST_ENV.md       # 14-container PHP version matrix setup
│   └── P2S_OTHER_TARGETS.md     # non-PHP lab targets (Ghostcat, h2c, MySQL, CGI/FPM)
└── windows-lab/         # the lab tree captured from the Windows host
    │                    # ("windows" = where the lab ran, NOT a separate research track;
    │                    #  findings apply to the same chain — see RESEARCH_REPORT.md)
    ├── p2s52704/        # main study: exploit.py, per-version poc/, run_all.py, calibrations
    │   ├── REPORT.md    # machine-generated results table (from run_all.py)
    │   ├── STATUS.md    # status snapshot per version
    │   ├── PROGRESS.md  # sequential sub-8.3 deep-dive log
    │   ├── poc/ tools/ debug/ archive/ php72/ php5640/ test/
    └── deploy/          # batch scripts that build/maintain the lab containers
```

## Notes on the raw material

- Scripts under `windows-lab/` are kept **as-experimented**: many are one-off probes or
  superseded calibration attempts (`archive/`). Expect hard-coded lab ports
  (`181xx`) and container names (`p2sXXXX`); they only work with the matching lab up.
- Offset tables (`versions.py`, `STATUS.md`) are per-image values recovered live from
  the containers — do not reuse them for any other build.
- `notes/PUSULA.md` is the historical project compass (kept verbatim as an archival
  document; the actionable summary lives in `RESEARCH_REPORT.md`).

## Safety reminder

The PoCs in this archive achieve real code execution **by design** — that is the point
of the research. Run them exclusively inside your own lab, keep containers isolated,
and delete them after use. Patched PHP releases (≥ 8.4.27 / ≥ 8.5.12) close the window.
