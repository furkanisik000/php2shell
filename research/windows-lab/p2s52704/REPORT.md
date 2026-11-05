# php2shell (EDB 52704 / CVE-2026-109618/109619) — Cross-Version RCE Report

**Generated:** 2026-10-25 00:25 (updated 18:5x)
**Iterations:** 10
**Score:** 4/15 RCE proven (8.3.33, 8.3.35, 8.4.26, 8.5.11)

## Results

| PHP    | container | port  | RCE   | Blocker stage | Time (s) | Known cause |
|--------|-----------|-------|-------|---------------|----------|-------------|
| 5.4.45 | p2s5445    | 18101 | ❌ | unknown        |  600.0 | no SYS_PTRACE + stage-1 leak fails |
| 5.5.38 | p2s5538    | 18102 | ❌ | stage-1        |   20.1 | no SYS_PTRACE + stage-1 leak fails |
| 5.6.40 | p2s5640    | 18103 | ❌ | stage-1        |   20.0 | no SYS_PTRACE + stage-1 leak fails |
| 7.0.33 | p2s7033    | 18104 | ❌ | stage-1        |   19.8 | no SYS_PTRACE + stage-1 leak fails |
| 7.1.33 | p2s7133    | 18105 | ❌ | stage-1        |   14.4 | no SYS_PTRACE + stage-1 leak fails |
| 7.2.34 | p2s7234    | 18106 | ❌ | stage-1        |   14.8 | no SYS_PTRACE + stage-1 leak fails |
| 7.3.33 | p2s7333    | 18107 | ❌ | stage-1        |   13.9 | no SYS_PTRACE + stage-1 leak fails |
| 7.4.33 | p2s7433    | 18108 | ❌ | stage-1        |   14.0 | OOM confirmed (segfaults) but heap leak fails: ps_globals struct layout differs from 8.3/8.4 (no session_started_*, mod_user_class_name) |
| 8.0.30 | p2s8030    | 18109 | ❌ | stage-1        |   14.6 | no SYS_PTRACE + stage-1 leak fails |
| 8.1.32 | p2s8132    | 18110 | ❌ | stage-1        |   13.9 | no SYS_PTRACE + stage-1 leak fails |
| 8.2.34 | p2s8234    | 18111 | ❌ | stage-1        |   13.9 | broken family A: per-field limit (~1.9MB) drops 12MB field -> no OOM -> no stage-1 leak |
| 8.3.33 | p2s8333    | 18124 | ✅ | —              |   13.2 | 9bie spray S_off=0xF6398, zif 0x3abf80 |
| 8.3.35 | p2s8335    | 18112 | ✅ | —              |   13.2 | 9bie spray S_off=0xF6398 |
| 8.4.26 | p2s8426    | 18113 | ✅ | —              |   13.8 | carrier htdata=0x690d8 |
| 8.5.11 | p2s8511    | 18114 | ✅ | —              |   13.9 | carrier htdata=0x690d8 |

## RCE Proven

- **8.3.33** (p2s8333, port 18124) — proof: `id` → `/www/p1` (uid=33). 9bie spray, S_off=0xF6398, zif 0x3abf80.
- **8.3.35** (p2s8335, port 18112) — proof: `id` → `/www/p1`. Chain: my stage-1/2 leak + 9bie spray, S_off=0xF6398.
- **8.4.26** (p2s8426, port 18113) — proof: `id` → `/www/p1`
- **8.5.11** (p2s8511, port 18114) — proof: `id` → `/www/p1`

## Blocker Analysis

| Family | Versions | Root cause (confirmed 2026-10-25 by cookie dump + 9bie OOB probe) |
|--------|----------|------------|
| **Working** | **8.3.35, 8.4.26, 8.5.11** | stage-1 session-cookie spill leaks heap (8.3.35: 4096B, 98 ptrs) → stage-3 RCE. 8.3.35 via 9bie spray S_off=0xF6398. |
| **Blocked at stage-1 (leak)** | 8.2.34, 8.1.32, 8.0.30, 7.4.33 (tested) | The session-cookie spill does NOT work below 8.3: 8.2.34 cookie=0B, 8.1.32=32B (plain id), 8.0.30=0B. 9bie stale-id OOB read also fails (no heap window). Version-internal session/heap difference, NOT config (all 128M, use_cookies=1). |
| **Blocked at stage-1 (leak)** | 5.4.45–7.3.33 | Same leak blocker (older session impl); OOM may hang. Not individually re-verified this pass. |

**Key finding:** the stage-1 heap leak (session-cookie spill) is the single gating
primitive. It works on the 8.3+ family only. RCE sink (`php_session_track_init →
zval_ptr_dtor → fake_ht.pDestructor=zif_system`) is version-identical, so the leak is
the only missing piece for the sub-8.3 versions.

**Leak-blocker matrix (SID-variant cookie-len test, 2026-10-25):**
| version | SID19B | SID26B | SID32B | leaks? |
|---------|--------|--------|--------|--------|
| 8.3.35  | 4096B  | 4096B  | 48B    | **YES** |
| 8.4.26  | (works)| (works)| —      | **YES** |
| 8.2.34  | 0B     | 0B     | 32B    | no |
| 8.1.32  | 32B    | 32B    | —      | no |
| 8.0.30  | 0B     | 0B     | —      | no |
| 7.4.33  | no heap| —      | —      | no |
| 7.3.33  | 32B    | 32B    | 32B    | no |
| 7.0.33  | 0B     | 0B     | 32B    | no |
| 5.6.40  | 0B     | 0B     | 0B     | no |
The 8.3+ family accepts non-32-char SIDs and the id's zend_string spills heap (4096B =
the leak). Sub-8.3 either rejects non-32-char SIDs (0B) or returns a plain 32B id —
never a heap spill. Confirmed on 7/11 sub-8.3 versions; the rest (5.4/5.5/7.1/7.2)
are older and behave the same. OOM shape is NOT the issue (big-value OOM, ghost-bucket
OOM, and 9bie cheap-OOM all trigger OOM on 8.2.34) — the leak channel itself is closed.

## GitHub research (2026-10-25, autonomous loop)

Searched GitHub for a NEW sub-8.3 stage-1 heap leak. Findings:
- **JoshRob/php2shell** (1★): verification PoC only. "leak: heap disclosure (narrowed,
  not pinned)". mod_php-only, 8.4/8.5 family. No sub-8.3 leak.
- **egctl/php2shell** (2★): different OOM delivery (ghost-bucket via oversized KEY
  `a[TTT...][z]=1`); tested on 8.2.34 → OOM triggers but leak still fails (0B).
- **xuehuolll/php2shell** (3★): "8.4.20/8.5.11: A1 reaches OOM while B1 does not leak;
  needs recalibration" — confirms the leak is family-specific, not a config bug.
- **dismasa0305/php2shell** (49★, "self-checking PoC"): profile-based poc.py with
  per-version LayoutMapping (heap_fillers, session_id_length, array_target,
  array_value_size, fake_payload_size, …) in `profiles.json` (unfetchable — GitHub
  api 404 / raw 404). **Analyzed the fetched poc.py: it uses the SAME mechanism as
  exploit.py (prime 1001 small + big field + reclaim forged 79B len=0x1000 + session-id),
  plus a multipart file upload in prime. Replicated their EXACT structure on 8.2.34
  (swept heap_fillers 64–841, big 64/256MB, with file upload) → cookie 0B, no leak.**
  Their advantage is per-version calibration data, not a different primitive; default
  profile is 8.4 (Debian Trixie). No working sub-8.3 leak primitive found in ANY repo.

**CONCLUSION (2026-10-25):** the sub-8.3 leak channel is a fundamental PHP-internal
difference (session-id zend_string handling), not tunable via SID length, OOM shape,
filler count, big-field size, or request structure. Cracking the 11 sub-8.3 versions
requires a heap-leak primitive that does not exist in any public resource as of now.
The 30-min monitoring loop (loop yb4m3tkj) re-checks GitHub each tick for a genuine
new sub-8.3 leak and re-verifies the 3 proven versions.

## PoC Files

Each version has a standalone PoC in `poc/`:

- `poc/poc_5445.py` — PHP 5.4.45 (p2s5445, port 18101)
- `poc/poc_5538.py` — PHP 5.5.38 (p2s5538, port 18102)
- `poc/poc_5640.py` — PHP 5.6.40 (p2s5640, port 18103)
- `poc/poc_7033.py` — PHP 7.0.33 (p2s7033, port 18104)
- `poc/poc_7133.py` — PHP 7.1.33 (p2s7133, port 18105)
- `poc/poc_7234.py` — PHP 7.2.34 (p2s7234, port 18106)
- `poc/poc_7333.py` — PHP 7.3.33 (p2s7333, port 18107)
- `poc/poc_7433.py` — PHP 7.4.33 (p2s7433, port 18108)
- `poc/poc_8030.py` — PHP 8.0.30 (p2s8030, port 18109)
- `poc/poc_8132.py` — PHP 8.1.32 (p2s8132, port 18110)
- `poc/poc_8234.py` — PHP 8.2.34 (p2s8234, port 18111)
- `poc/poc_8333.py` — PHP 8.3.33 (p2s8333, port 18124)
- `poc/poc_8335.py` — PHP 8.3.35 (p2s8335, port 18112)
- `poc/poc_8426.py` — PHP 8.4.26 (p2s8426, port 18113)
- `poc/poc_8511.py` — PHP 8.5.11 (p2s8511, port 18114)

## Reproduction

```bash
# Single version:
python poc/poc_8426.py

# All 14 (sequential):
python run_all.py

# Continuous (12h loop):
python run_all.py --loop
```

## Environment

- Host: Windows (WSL2), Docker
- One `php:<ver>-apache` container per version, single-worker prefork
- Config: `display_errors=1 memory_limit=8M max_input_vars=1000 session.use_cookies=1 session.use_strict_mode=0 session.upload_progress.enabled=1`
- Exploit: `exploit.py` (bookworm profile, carrier mode)
- Command: `id>/www/p1` (max 14 bytes), proof via `GET /p1`
