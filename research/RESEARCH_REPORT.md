# Research Report — php2shell (EDB-52704 / CVE-2026-109618, CVE-2026-109619)

**Scope:** Authorized security research against owner-controlled lab containers only.
**Lab host:** Windows x86_64 + WSL2 + Docker Desktop (native amd64), one
`php:<ver>-apache` container per PHP version, single-worker prefork, ports `18101–18124`.
**Status date:** 2026-11-05 · **Score: 4/15 versions with proven RCE** (8.3.33, 8.3.35, 8.4.26, 8.5.11).

This report consolidates everything that was built, tried and ruled out during the
cross-version study of the php2shell chain. It merges the material that previously
lived in a separate "windows" folder — the platform is only the lab host, not a
distinct research track; all findings below apply to the same exploit chain.

---

## 1. The vulnerability & exploit chain

Two adjacent bugs in PHP's session + multipart handling (disclosed as EDB-52704):

| CVE | Class | Mechanism |
|-----|-------|-----------|
| CVE-2026-109618 | Memory corruption (OOM) | Oversized `multipart/form-data` field forces a real `memory_limit` OOM **inside the RFC-1867 upload parser**; on affected versions this is a *soft bailout* (`longjmp`) that skips module teardown, leaving `PS(id)` pointing at a released `zend_string`. |
| CVE-2026-109619 | Use-after-free / stale global | At request shutdown the dangling `PS(id)` (and forged refs in `PS(http_session_vars)`) are dereferenced again — the leak and the RCE sink both ride on this stale state. |

**The three-stage chain (all stages driven by plain HTTP requests):**

1. **Stage 1 — heap leak.** A "carrier"/forged request makes the next `Set-Cookie`
   echo the corrupted `PS(id)` `zend_string`, spilling up to **4096 bytes of raw heap**
   (chunk base + live pointers) into the response header.
2. **Stage 2 — libphp base leak.** Same channel, second calibration, leaks pointers
   into `libphp.so` → ASLR base recovered.
3. **Stage 3 — RCE.** `session.upload_progress` is abused to forge a `zend_array`
   whose `pDestructor` is overwritten with `zif_system`; on session teardown PHP calls
   `php_session_track_init → zval_ptr_dtor → fake_ht.pDestructor(cmd)` → command runs
   as `www-data` (`uid=33`). Proof = `id>/www/p1` then `GET /p1`.

Prerequisites: `session_start()` reachable, `use_strict_mode=0`,
`upload_progress.enabled=1`, a `memory_limit` small enough vs. `post_max_size` that the
parser really OOMs, and **native amd64** (QEMU emulation on Apple-silicon hosts breaks
the glibc heap timing/window — see §4).

## 2. What was built (tooling inventory)

| Artifact | Purpose |
|----------|---------|
| `exploit.py` | Full 3-stage chain driver (bookworm profile, carrier mode, 256 MB OOM field). |
| `poc/poc_<ver>.py` (15 files) | Standalone per-version PoCs, stdlib-only Python. |
| `run_all.py` + `versions.py` | Master runner: sequential/looped testing of all targets, writes `REPORT.md`, per-version offset table (`zif_system`, `zval_ptr_dtor`, `ps_globals`, htdata, spray params). |
| `elf_parse.py`, `so_offsets_all.py`, `extract_offsets.py` | Recover per-image offsets from `nm`/ELF parsing inside each container. |
| `nul_triage.py`, `probe_profiles.py`, `cookie_diag.py`, `dump_ps.py` | Triage arms: classify OOM behavior (hard-fatal vs soft-bailout), measure Set-Cookie spill length, dump `ps_globals` before/after an arm. |
| `php72/read_mem.pl`, `read_mem2.pl` | Perl `/proc/<worker>/mem` readers (dd cannot seek that far; gdb uninstallable on EOL buster images) — used for ground-truth heap verification. |
| `calib_*`, `scan_*`, `sweep_*` scripts | Per-version calibration grids (spray sizes, pads, SID lengths, htdata offsets). |
| Deploy batch scripts (`research/windows-lab/deploy/`) | Bootstrap/maintain the 14-container lab on the Windows box: target setup, probe deploy, `memory_limit=8M`, `max_input_vars`, `display_errors` fixes. |

## 3. Results matrix (final)

| PHP | Port | Verdict | Root cause / calibration |
|-----|------|---------|--------------------------|
| 5.4.45 | 18101 | ❌ BLOCKED | Soft-bailout ✓ but post-arm `PS(id)` stays a **valid** pointer → no dangling state, no UAF. |
| 5.5.38 | 18102 | ❌ BLOCKED | Post-arm `PS(id)` = NULL → no dangled state. |
| 5.6.40 | 18103 | ❌ BLOCKED | Source-confirmed: `PS(id)` is a plain `char*` (no decoupled `len` field to overflow); forged SIDs never adopted (fresh `s_create_sid`); `php_rshutdown_session_globals` frees it to NULL. Strongest block in the tree. |
| 7.0.33 | 18104 | ❌ BLOCKED | `PS(id)` NULL after arm. |
| 7.1.33 | 18105 | ❌ BLOCKED | `PS(id)` NULL after arm. |
| 7.2.34 | 18106 | ❌ BLOCKED | **Closest miss:** arm soft-bailouts ✓, `PS(id)` goes dangling ✓ (0x79eb70fff00) — but the freed page is **reclaimed/uncommitted** (`pread → EFAULT`), so the consumer UAF can never land on it. dinosn worked on 7.2.21; 7.2.34 allocator behavior differs. |
| 7.3.33 | 18107 | ❌ BLOCKED | `PS(id)` NULL after arm. |
| 7.4.33 | 18108 | ❌ BLOCKED | OOM/segfault confirmed in logs, but cookie = 32 B (plain ID only) — no heap spill. |
| 8.0.30 | 18109 | ❌ BLOCKED | **Hard-fatal OOM** ("Allowed memory size exhausted", worker dies) → no residual dangling state. Cookie 0 B. |
| 8.1.32 | 18110 | ❌ BLOCKED | Hard-fatal OOM; cookie 32 B max. |
| 8.2.23 | 18115 | ❌ BLOCKED | OOM confirmed (heap-corruption abort) but cookie 0 B — same broken family as 8.2.34. |
| 8.2.34 | 18111 | ❌ BLOCKED | Hard-fatal OOM (worker dies) → leak channel closed. Verified across four independent OOM shapes (§5). |
| **8.3.33** | 18124 | ✅ **RCE PROVEN** | 9bie spray, `S_off=0xF6398`, `zif 0x3abf80`; proof `id → uid=33 www-data`. |
| **8.3.35** | 18112 | ✅ **RCE PROVEN** | Stage-1/2 leak + 9bie spray, `S_off=0xF6398`. (Earlier passes failed at stage-3 carrier mis-land; solved via spray variant.) |
| **8.4.26** | 18113 | ✅ **RCE PROVEN** | Carrier mode, `htdata=0x690d8`. |
| **8.5.11** | 18114 | ✅ **RCE PROVEN** | Carrier mode, `htdata=0x690d8`. |

Post-patch releases (8.4.27 / 8.5.12) replace the `longjmp` OOM path with a delayed
soft-OOM + `_exit()`, closing the window — consistent with upstream advisories.

## 4. Experiments performed (chronological highlights)

1. **Baseline reproduction (8.4.x/8.5.x).** Carrier-mode chain reproduced end-to-end on
   stock `php:8.4.26-apache` with default `memory_limit=128M` — proved the exploit does
   **not** require the exotic 8 M config (that was only needed for low-memory calibration).
2. **Cross-version sweep (15 targets).** `run_all.py` executed the full matrix repeatedly
   (10+ iterations incl. continuous loops); results stable → table above.
3. **SID-length triage.** Forged `PHPSESSID` of 19/26/32 chars against every version:
   8.3+ spills 4096 B of heap through `Set-Cookie`; sub-8.3 returns 0 B or a clean 32 B ID.
   First hard evidence that the leak itself (not the OOM) is the gating primitive.
4. **OOM-shape variations.** Big-value OOM, ghost-bucket OOM (oversized array *key*),
   9bie cheap-OOM, cumulative-small-fields OOM — all trigger OOM on 8.2.34 yet none leak.
   Ruled out "wrong OOM shape" as the sub-8.3 blocker.
5. **Per-field-limit hypothesis — disproved.** Initially attributed 8.2.x failures to a
   ~1.9 MB per-field cap; source review + experiments showed **no such limit exists**:
   effective max field = `memory_limit − baseline`. (Recorded as a corrected misdiagnosis.)
6. **NUL-byte arm (dinosn-style) + `/proc/mem` ground truth.** Recreated containers with
   `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`; armed with `PHPSESSID=\x00` +
   1.3 MB header; read `ps_globals` directly from the live worker. Findings:
   - 8.0/8.1/8.2: OOM is **hard-fatal** — worker dies, nothing dangling. Genuinely blocked.
   - 7.2.34: soft-bailout ✓, dangling `PS(id)` ✓, **but freed block returns EFAULT**
     (uncommitted) → UAF impossible. "Soft-bailout" is necessary but not sufficient.
   - 7.3/7.4/7.0/7.1/5.5/5.6: `PS(id)` simply NULLed after arm → no dangling state at all.
   - 5.4.45: `PS(id)` remains a valid pointer (never released) → no UAF.
7. **5.6.40 source-level confirmation.** Read `php-5.6.40/ext/session/session.c`:
   id is `char*` + `strlen()` cookie encoding (no `len` field to corrupt), strict
   regeneration of invalid SIDs, and explicit `efree(PS(id)); PS(id)=NULL` on rshutdown
   *and* on `MULTIPART_EVENT_END`. Definitive structural block.
8. **GitHub ecosystem survey (autonomous loop).** Reviewed public php2shell repos
   (JoshRob 1★, egctl 2★, xuehuolll 3★, dismasa0305 49★ self-checking PoC):
   all use the same 8.3+ leak primitive; dismasa0305's exact request structure was
   replicated on 8.2.34 with swept filler counts (64–841), 64/256 MB big fields and
   multipart file upload → still 0 B. Their edge is per-version calibration data,
   **not** a sub-8.3 leak. No public sub-8.3 leak primitive exists.
9. **Platform validation.** macOS/QEMU-amd64 emulation: leak window never reproduces
   (syscall emulation perturbs glibc heap layout). Windows+WSL2 native amd64: works
   unmodified → the lab was moved there permanently.
10. **Config forensics.** `php -i` (CLI) misled about apache worker settings twice;
    switched to a served PHP probe (`poc/probe_helper.php`) reading the *worker's* real
    ini values (`post_max_size=512M` via `php_admin_value` in conf-enabled). Also fixed
    `display_errors` and `max_input_vars` drift across containers with dedicated batch scripts.
11. **Bug found & fixed in our own tooling.** `_hex("465370")` was being parsed as a
    decimal (→ wrong stage-2/3 pointer 0x719DA); forced hex interpretation — after the
    fix, stage-2/3 pointers verified correct.

## 5. Errors & dead ends encountered

| Dead end | How it was recognized |
|----------|---------------------|
| "Per-field input limit blocks 8.2.x" | Misdiagnosis — no such limit in source; real cause is hard-fatal OOM. |
| "HEAP_PROTECTION flag explains 8.3.35 failure" | Wrong: stage-1/2 work fine on 8.3; only stage-3 landing differed (later solved with 9bie spray). |
| Tuning htdata ±0x200 to fix carrier mis-land | No effect; 8.3 needs a different attack shape (spray), not a tuned carrier. |
| Expecting sub-8.3 leak via SID length / OOM shape / filler count / request structure | Exhaustively swept — leak channel is a PHP-internal difference (session-id `zend_string` handling introduced ≥8.3). |
| dinosn NUL-arm assumed portable across 7.x | Only 7.2.21 was ever calibrated; 7.2.34 already fails at the reclaim step; 7.3+/5.x fail earlier (no dangling). |
| CLI `php -i` as config ground truth | Apache workers load different ini context; must probe via served PHP script. |
| gdb-based heap inspection | Uninstallable on EOL Debian buster images; replaced with perl `/proc/PID/mem` readers. |
| QEMU/ARM emulation lab | Heap-timing window not reproducible under emulation; required native amd64. |
| Tooling bug: decimal/hex parse of offsets | Produced silently wrong pointers (stage failures looked like target problems); fixed and re-verified. |

## 6. Conclusion

- The chain is **fully proven on 8.3.33, 8.3.35, 8.4.26, 8.5.11** (pre-patch), with
  real `uid=33` evidence captured in-lab.
- Every sub-8.3 version is blocked at **stage 1**, and the block is now root-caused at
  three distinct levels: hard-fatal OOM (8.0–8.2), non-dangling/NULL `PS(id)` (7.x, 5.x),
  and structurally absent len-decoupled string (≤5.6). These are genuine interpreter
  differences, not calibration gaps.
- Cracking the remaining 11 versions would require a **new heap-leak primitive** that
  does not exist in any public resource as of the report date.
- Patched releases (8.4.27+, 8.5.12+) close the OOM window upstream; upgrade is the fix.

## 7. Repository map for this research

```
research/
├── RESEARCH_REPORT.md      # this document (single consolidated report)
├── github-survey/          # public-repo survey scripts & output
├── notes/                  # lab setup guides, target matrix, project compass
└── windows-lab/            # the lab tree (host = Windows box; same research, not a separate track)
    ├── p2s52704/           # main deep-dive: exploit.py, poc/, run_all.py, calibrations
    │   ├── REPORT.md       # machine-generated results table (run_all.py output)
    │   ├── STATUS.md       # working status snapshot per version
    │   ├── PROGRESS.md     # sequential sub-8.3 deep-dive log
    │   ├── archive/        # superseded experiments (~200 scripts, kept raw)
    │   ├── debug/          # diagnostic helpers (dbg_*, check_*, *_diag)
    │   ├── tools/          # reusable test harnesses (OOM/session/upload tests)
    │   ├── php72/          # dinosn-style 7.2 chain + /proc/mem readers
    │   ├── php5640/        # 5.6.40-specific verification kit
    │   └── test/           # per-version experiment folders (poc8335, poc8510)
    └── deploy/             # Windows batch scripts that build/maintain the lab containers
```

## 8. Reproduction

```bash
cd research/windows-lab/p2s52704
python3 poc/poc_8426.py            # single version (lab containers must be up)
python3 run_all.py                 # full matrix, regenerates REPORT.md
python3 run_all.py --only 8335,8426
python3 run_all.py --loop          # continuous regression
```

Lab bootstrap (Windows host, Docker Desktop): see `research/notes/SETUP_WINDOWS_AMD64.md`,
`research/notes/DOCKER_TEST_ENV.md`, `research/notes/P2S_OTHER_TARGETS.md`, and the batch
scripts in `research/windows-lab/deploy/`.

## 9. Responsible-use note

All experiments ran exclusively against disposable, owner-controlled Docker containers
on a private lab network. Nothing here should be pointed at systems you do not own or
have written authorization to test. Coordinated disclosure has been made; patched
versions exist — upgrade PHP rather than relying on detection alone.
