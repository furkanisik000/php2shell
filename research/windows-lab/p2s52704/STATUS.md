# php2shell (EDB 52704 / CVE-2026-109618) — Cross-Version RCE Status

Lab: one `php:<ver>-apache` Docker container per version, single-worker prefork,
`memory_limit=128M max_input_vars=1000 display_errors=1 post_max_size=512M`, host port `181xx`.
Working dir: `research/windows-lab/p2s52704\`. Exploit: `exploit.py` (bookworm profile, 256MB OOM field).

**RCE chain:** stage-1 Set-Cookie heap leak → stage-2 Set-Cookie libphp leak →
stage-3 upload_progress fake-ref (pDestructor=zif_system) → RCE on session teardown.
Requires a **real OOM** (256MB field > 128M memory_limit) so the Set-Cookie reads a
corrupted `PS(id)` zend_string. Verified: works with default 128M memory_limit (not just 8M).

## Status (2026-10-24)

| PHP    | port  | container | S1 heap | S2 libphp | S3 RCE | Verdict |
|--------|-------|-----------|---------|-----------|--------|---------|
| 5.4.45 | 18101 | p2s5445   | ❌      | ❌        | ❌     | **BLOCKED** (SYS_PTRACE + /proc/mem): arm soft-bailout ✓ but post-arm PS(id) stays a **valid** pointer (0x5fdabe06b800, unchanged) → not dangling, no UAF |
| 5.5.38 | 18102 | p2s5538   | ❌      | ❌        | ❌     | **BLOCKED** (SYS_PTRACE + /proc/mem): arm soft-bailout ✓ but post-arm PS(id) stays **NULL** (not dangling) → no dangled state |
| 5.6.40 | 18103 | p2s5640   | ❌      | ❌        | ❌     | **BLOCKED** (SYS_PTRACE + /proc/mem): arm soft-bailout ✓ but post-arm PS(id) stays **NULL** (not dangling) → no dangled state |
| 7.0.33 | 18104 | p2s7033   | ❌      | ❌        | ❌     | **BLOCKED** (SYS_PTRACE + /proc/mem): arm soft-bailout ✓ but post-arm PS(id) stays **NULL** (not dangling) → no dangled state |
| 7.1.33 | 18105 | p2s7133   | ❌      | ❌        | ❌     | **BLOCKED** (SYS_PTRACE + /proc/mem): arm soft-bailout ✓ but post-arm PS(id) stays **NULL** (not dangling) → no dangled state |
| 7.2.34 | 18106 | p2s7234   | ❌      | ❌        | ❌     | **BLOCKED** (SYS_PTRACE + /proc/mem): arm soft-bailout ✓, PS(id) dangling ✓ (0x79eb70fff00) but freed block **reclaimed (EFAULT)** → dinosn UAF impossible |
| 7.3.33 | 18107 | p2s7333   | ❌      | ❌        | ❌     | **BLOCKED** (SYS_PTRACE + /proc/mem): arm soft-bailout ✓ but post-arm PS(id) stays **NULL** (not dangling) → no dangled state to leak |
| 7.4.33 | 18108 | p2s7433   | ❌      | ❌        | ❌     | **BLOCKED** (SYS_PTRACE + /proc/mem): arm soft-bailout ✓ but post-arm PS(id) stays **NULL** (not dangling) → no dangled state to leak |
| 8.0.30 | 18109 | p2s8030   | ❌      | ❌        | ❌     | **BLOCKED**: hard-fatal OOM (worker dies, "Allowed memory size exhausted") → no dangling PS(id) state |
| 8.1.32 | 18110 | p2s8132   | ❌      | ❌        | ❌     | **BLOCKED**: hard-fatal OOM (worker dies) → no dangling PS(id) state |
| 8.2.23 | 18115 | p2s8223   | ❌      | ❌        | ❌     | **OOM confirmed** (zend_mm_heap corrupted, worker Abort in logs) but **heap leak fails**: cookie=0B (vs 4096B on 8.4.26) — same broken family as 8.2.34 |
| 8.2.34 | 18111 | p2s8234   | ❌      | ❌        | ❌     | **OOM confirmed** (worker Abort) but **heap leak fails**: cookie=0B (vs 4096B on 8.4.26) — same broken family as 8.2.23 |
| **8.3.33** | 18124 | p2s8333 | ✅     | ✅        | ✅     | **RCE PROVEN** (uid=33 www-data, 9bie spray, S_off=0xF6398, zif 0x3abf80) |
| **8.3.35** | 18112 | p2s8335 | ✅     | ✅        | ✅     | **RCE PROVEN** (uid=33 www-data, 9bie spray, S_off=0xF6398) |
| **8.4.26** | 18113 | p2s8426 | ✅     | ✅        | ✅     | **RCE PROVEN** (uid=33 www-data, carrier htdata=0x690d8) |
| **8.5.11** | 18114 | p2s8511 | ✅     | ✅        | ✅     | **RCE PROVEN** (uid=33 www-data, carrier htdata=0x690d8) |

**Score: 4/15 RCE proven (8.3.33, 8.3.35, 8.4.26, 8.5.11).** 8.0/8.1/8.2 blocked
(hard-fatal OOM, no dangling state). 7.x/5.x blocked (dinosn mechanism:
7.2.34 dangling-PS(id)-reclaimed, 7.3.33/7.4.33 PS(id)-NULL; 7.0/7.1/5.x
expected same — see PROGRESS.md 7.x-family section).

## Family analysis

- **Working family (8.4.26, 8.5.11):** no per-field limit → 12MB field stored → OOM →
  corrupted PS(id) → Set-Cookie heap/libphp leak → full chain → RCE.
- **Broken family A — OOM yes, leak no (7.0.33–7.4.33, 8.2.23, 8.2.34):**
  OOM happens on ALL of them (worker Abort / segfault in logs) but the
  post-OOM residual heap state does not spill into Set-Cookie → no stage-1 leak.
  Two sub-signatures: cookie=0B (7.0.33, 8.2.23, 8.2.34 — no Set-Cookie at all)
  vs cookie=32B (7.1.33–7.4.33 — session ID only, PS(id) stays valid).
  (measured 2026-10-25; control 8.4.26: 4096B + heap ptrs; diag: chk_8223_cookie.py)

- **OOM split (KEY, 2026-10-25, `nul_triage.py`):** the sub-8.3 leak is NOT
  uniform — it splits by OOM behavior. **8.0.30 / 8.1.32 / 8.2.34 = HARD-FATAL**
  (OOM kills the worker, "Allowed memory size exhausted", no dangling `PS(id)`
  → genuinely BLOCKED). **7.0.33–7.4.33 / 5.4.45–5.6.40 = SOFT-bailout**
  (worker survives → dangled state possible → LEAK-ABLE, the dinosn
  prerequisite). So the 8 leak-able versions (7.x/5.x) are the real targets,
  via the dinosn chain (`php72/`); the 8.0/8.1/8.2 are blocked. 7.2.34 is the
  best candidate (dinosn chain is 7.2-calibrated) but needs per-container
  calibration of the arm size + chain9 consumer (see PROGRESS.md).
- **Broken family B — stage-3 mis-land (8.3.35):** stage-1+2 leak works, but stage-3
  heap write mis-lands (PS(http_session_vars) offset differs) → no RCE.
- **No-SYS_PTRACE family (5.4.45–8.1.32):** /proc/<worker>/mem denied → cannot
  read/verify heap; stage-1 leak also fails. Containers need recreation with
  `--cap-add SYS_PTRACE --security-opt seccomp=unconfined` to debug.

## libphp offsets (zif_system / zval_ptr_dtor)

| ver    | zif_system | zval_ptr_dtor |
|--------|-----------|---------------|
| 5.4.45 | 0x2f2e20  | 0x3cd750 |
| 5.5.38 | 0x357e70  | 0x438b80 |
| 5.6.40 | 0x378e80  | 0x466920 |
| 7.0.33 | 0x3948d0  | 0x47b7b0 |
| 7.1.33 | 0x300420  | 0x3e6f60 |
| 7.2.34 | 0x3624e0  | 0x451010 |
| 7.3.33 | 0x35f640  | 0x440dc0 |
| 7.4.33 | 0x335850  | 0x417d60 |
| 8.0.30 | 0x3495d0  | 0x4319a0 |
| 8.1.32 | 0x36b080  | 0x450690 |
| 8.2.23 | 0x391dd0  | 0x479f40 |
| 8.2.34 | 0x39b8a0  | 0x487650 |
| 8.3.35 | 0x3ac080  | 0x49ec50 |
| **8.4.26** | **0x465370** | **0x65eb60** (RCE proven) |
| 8.5.11 | 0x5996e0  | 0x7b47a0 |

## Key findings (2026-10-24 session, CORRECTED)

1. **NO per-field limit exists** in the PHP source (research agent verified).
   The "per-field limit" was a misdiagnosis. The effective max field = `memory_limit - baseline`.
2. **7.4.33 OOM IS happening** (segfaults confirmed in container logs) but
   **heap leak does NOT work** (cookie=32B, no heap pointers). The residual
   heap state after OOM differs from 8.4.
3. **8.3.35 stage-1+2 WORK** — the leak works on 8.3. So the issue is NOT
   simply HEAP_PROTECTION (which is 8.4+). The difference is between 7.4/8.2
   and 8.3 in the post-OOM heap state.
4. **8.3.35 stage-3** is a fundamental heap-layout mismatch — htdata offset
   tuning (±0x200) does not fix the carrier mis-land. The `--no-carrier` mode
   also fails at stage-3.
5. **Session.c diff 8.3→8.4:** 8.4 adds `PS(id)=NULL` after release (8.3 leaves
   dangling), adds PCG random state (16B alloc), adds `php_get_session_var_str()`.
6. **Research** (xuehuolll repo, GHSA): post-patch (8.4.27/8.5.12) replaces
   `longjmp` OOM with delayed soft OOM + `_exit()`. Pre-patch 8.4.26/8.5.11
   use the `longjmp` path (which we exploit).

## Current focus
- **7.0.33–7.4.33 / 8.2.23 / 8.2.34 / 5.4-8.1:** OOM happens but leak fails.
  Need to understand WHY the post-OOM heap state is different. Possible:
  different allocator layout, different session teardown, different PS(id) handling.
  (2026-10-25: all 7.x + both 8.2.x measured — same failure; two sub-signatures:
  cookie=0B [7.0.33, 8.2.x] vs cookie=32B [7.1–7.4]. Whole 5.4–8.2 range broken
  at stage-1; only 8.3+ leaks.)
- **8.3.35:** Stage-3 carrier mis-land. The heap layout is different from 8.4.
  The dangling PS(id) on 8.3 is a unique primitive not available on 8.4.
- **5.4–8.1:** Same stage-1 leak failure family as 7.4.33/8.2.34.
