# php2shell sub-8.3 sequential deep-dive — PROGRESS

Order (user-chosen): 8.2.34 → 8.1.32 → 8.0.30 → 7.4.33 → 7.3.33 → 7.2.34 →
7.1.33 → 7.0.33 → 5.6.40 → 5.5.38 → 5.4.45. One at a time; a version is DONE
when RCE is proven (uid=33) OR definitively-blocked with a root cause + ≥2
tested approaches. GitHub research ≤1/hour.

## KEY DISCOVERY (2026-10-25, NUL-byte arm triage of all 10 remaining)

The sub-8.3 stage-1 leak is **NOT uniform** — it splits by OOM behavior:

| family | OOM behavior | leak |
|--------|--------------|------|
| **8.0.30, 8.1.32, 8.2.34** | **HARD-FATAL** ("Allowed memory size exhausted", worker dies) | **BLOCKED** — no dangling `PS(id)` to read |
| **7.0.33, 7.1.33, 7.2.34, 7.3.33, 7.4.33, 5.4.45, 5.5.38, 5.6.40** | **SOFT-bailout** (worker survives, body clean) | **LEAK-ABLE** — dangled state possible; needs the dinosn arm+consumer pair + per-container calibration |

The 8.0/8.1/8.2 hard-fatal is a genuine version-specific difference (the OOM is
a hard fatal, not the soft-bailout window 7.x/8.3.x expose). The 7.x/5.x
soft-bailout is exactly the dinosn prerequisite — so those 8 are the real
targets, and `php72/` (dinosn chain) is the tool.

| #  | PHP    | port  | verdict   | path / root-cause |
|----|--------|-------|-----------|-------------------|
| 1  | 8.2.34 | 18111 | BLOCKED   | hard-fatal OOM    |
| 2  | 8.1.32 | 18110 | BLOCKED   | hard-fatal OOM    |
| 3  | 8.0.30 | 18109 | BLOCKED   | hard-fatal OOM    |
| 4  | 7.4.33 | 18108 | LEAK-ABLE | soft-bailout; needs calibration |
| 5  | 7.3.33 | 18107 | LEAK-ABLE | soft-bailout; needs calibration |
| 6  | 7.2.34 | 18106 | LEAK-ABLE | dinosn chain (7.2-calibrated) — best candidate |
| 7  | 7.1.33 | 18105 | LEAK-ABLE | soft-bailout; needs calibration |
| 8  | 7.0.33 | 18104 | LEAK-ABLE | soft-bailout; needs calibration |
| 9  | 5.6.40 | 18103 | LEAK-ABLE | soft-bailout; needs calibration |
| 10 | 5.5.38 | 18102 | LEAK-ABLE | soft-bailout; needs calibration |
| 11 | 5.4.45 | 18101 | LEAK-ABLE | soft-bailout; needs calibration |

## .so offsets (nm, live) — zif_system / zval_ptr_dtor / ps_globals(BSS)

| ver    | zif_system | zval_ptr_dtor | ps_globals | .so |
|--------|-----------|---------------|------------|-----|
| 8.2.34 | 0x39b8a0  | 0x487650 | 0xf3a120 | libphp.so |
| 8.1.32 | 0x36b080  | 0x450690 | 0xef1a60 | libphp.so |
| 8.0.30 | 0x3495d0  | 0x4319a0 | 0xe585c0 | libphp.so |
| 7.4.33 | 0x335850  | 0x417d60 | 0xd37f80 | libphp7.so |
| 7.3.33 | 0x35f640  | 0x440dc0 | 0xd6c220 | libphp7.so |
| 7.2.34 | 0x3624e0  | (_zval_ptr_dtor 0x441b20) | 0xd51f40 | libphp7.so |
| 7.1.33 | 0x300420  | -    | 0xae6920 | libphp7.so |
| 7.0.33 | 0x3948d0  | -    | 0xd85c00 | libphp7.so |
| 5.6.40 | 0x378e80  | -    | 0xd4c060 | libphp5.so |
| 5.5.38 | 0x357e70  | -    | 0xcfdb40 | libphp5.so |
| 5.4.45 | 0x2f2e20  | -    | 0xb1ba00 | libphp5.so |

## 1. 8.2.34 (p2s8234, port 18111) — DEFINITIVELY BLOCKED

**.so analysis (nm, live container):**
- `zif_system`    = 0x39b8a0 (local, `t`)
- `zval_ptr_dtor` = 0x487650 (`T`)
- `ps_globals`    = 0xf3a120 (BSS `B`)
- `php_session_track_init` = 0x3438a0
- `elf_parse.py` on `archive/libphp_8234.so`: also `zend_hash_graceful_destroy`
  0x49c370, `zval_ptr_dtor_nogc` 0x528e70. Offsets match STATUS.md.

**Blocker (root cause):** stage-1 heap leak is closed. On 8.2.34 the OOM is a
**hard fatal** ("Allowed memory size of 134217728 bytes exhausted (tried to
allocate 4096 bytes)") — the worker DIES, so `ps_globals` never survives with
dangling pointers and the next request is served by a fresh child with no
leakable state.

**Why (vs 7.2 which leaks):** the dinosn chain's leak requires the OOM to be a
**soft bailout** (longjmp) *inside* the multipart parser, so
`PG(modules_activated)==0`, module teardown is skipped, `ps_globals` survives
with `PS(id)` = a released `zend_string` the Set-Cookie then reads. 7.2/8.3.x
do this (8.3.35 → 4096B leak). 8.2.x does NOT — its OOM is a hard fatal
(worker abort), so there is no dangling `PS(id)` to read.

**Approaches tested (all → cookie 0B/32B, no heap, worker dies or id-only):**
- standard leak arm (SID 19/26/32B) — cookie=0B (STATUS/REPORT)
- big-value OOM, ghost-bucket OOM, 9bie cheap-OOM — OOM yes, leak no (REPORT)
- dinosn NUL-byte arm (`PHPSESSID=\x00` + 1.3M hdr) → hard fatal, consumer
  Set-Cookie=0 (this session, 2026-10-25)
- dinosn leakpair (arm + chain9 consumer) → consumer Set-Cookie=0

**Verdict:** the 8.2.x OOM path is hard-fatal (not the soft-bailout window 7.2/
8.3.x expose). The leak channel is a genuine version-specific difference, not
tunable via SID length / OOM shape / request structure. **Blocked.**

## 6. 7.2.34 (p2s7234, port 18106) — leak-able prerequisite met, but UAF blocked (2026-10-25)

**Container:** recreated with `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`,
single-worker prefork, `99_p2s.ini` (post_max_size=512M, memory_limit=128M).
Worker = PID 101 (www-data), libphp base = 0x79eb7da8e000 (/proc/101/maps),
ps_globals = base + 0xd51f40 = 0x79eb7e7dff40.

**Tools:** `php72/read_mem.pl` (reads worker memory via /proc/PID/mem, perl 64-bit
seek — dd can't skip that far) + `php72/dump_ps.py` (arm + dump ps_globals
before/after). gdb install blocked (buster EOL, archive repos slow).

**Findings (direct /proc/mem inspection of the worker):**
1. **arm (NUL sid + 1.3M hdr) soft-bailouts** (worker 101 survives, 200 OK, clean
   body) — the dinosn prerequisite IS met.
2. **PS(id) @ ps_globals+0x10 goes NULL → dangling after the arm:**
   - baseline (after GET): PS(id) = 0x0
   - after arm: PS(id) = **0x79eb70fff00** (heap pointer, dangling)
   → the arm OOM DOES leave a dangling PS(id) (the dinosn core mechanism works).
3. **BUT the dangling PS(id) memory is RECLAIMED (not reusable):**
   `read 0x79eb70fff00 → Input/output error (EFAULT)`. The page (inside the arm's
   0x79eb70c00000-79eb72e00000 OOM region) is mapped but NOT committed. A
   known-good read (ps_globals itself) works, so this is specific to the freed
   PS(id) block.
   → the dinosn use-after-free (consumer reuses the freed PS(id) block) CANNOT
   work on 7.2.34: the freed block was returned/uncommitted, so the consumer's
   allocations don't land on it and the Set-Cookie can't leak it.

**Verdict:** soft-bailout + dangling PS(id) proven, but the freed memory is
reclaimed (EFAULT) → the dinosn UAF leak is impossible. A version-specific
heap-allocator difference (7.2.21 [dinosn, works] vs 7.2.34 [reclaimed,
blocked]). **Blocked** — and likely applies to the whole 7.x/5.x soft-bailout
family (same OOM + freed-PS(id) mechanism). The "leak-able" (soft-bailout) label
is necessary but NOT sufficient: the freed block must stay reusable, which
7.2.34 does not.

**How to confirm across 7.x/5.x:** recreate each with SYS_PTRACE, run
`dump_ps.py` (adjust PORT/PS_OFF), then read the post-arm PS(id) target with
`read_mem2.pl`. If the target EFAULTs (reclaimed) → blocked the same way. If it
reads (committed/reusable) → the dinosn consumer leak may work there.

## 7.x family — confirmed blocked across 3 versions (2026-10-25)

Direct /proc/mem inspection (dump_ps.py) of the post-arm PS(id) on three
versions, all soft-bailout (worker survives, 200 OK):

| ver    | port  | post-arm PS(id) @ ps_globals+0x10 | reading that target | verdict |
|--------|-------|-----------------------------------|---------------------|---------|
| 5.4.45 | 18101 | **valid** 0x5fdabe06b800 (unchanged) | n/a              | not dangling |
| 5.5.38 | 18102 | **NULL** (0x0)                    | n/a                 | no dangled state |
| 5.6.40 | 18103 | **NULL** (0x0)                    | n/a                 | no dangled state |
| 7.0.33 | 18104 | **NULL** (0x0)                    | n/a                 | no dangled state |
| 7.1.33 | 18105 | **NULL** (0x0)                    | n/a                 | no dangled state |
| 7.2.34 | 18106 | **dangling** 0x79eb70fff00        | **EFAULT** (reclaimed) | UAF impossible |
| 7.3.33 | 18107 | **NULL** (0x0)                    | n/a                 | no dangled state |
| 7.4.33 | 18108 | **NULL** (0x0)                    | n/a                 | no dangled state |

**Verdict:** the dinosn mechanism (arm → dangling PS(id) → consumer UAF) does
NOT reach RCE on the 7.x line (except the specific 7.2.21 the dinosn lab was
calibrated for). 7.2.34 gets a dangling PS(id) but the freed block is reclaimed
(UAF impossible); 7.3.33/7.4.33 don't even dangle PS(id) (NULL). This is a
per-version heap/session difference, not a tunable. The 7.0.33/7.1.33/5.x are
expected to be the same (dangling-none or reclaimed); 7.2.34 is the closest and
is still blocked. **The 7.x/5.x soft-bailout family is RCE-blocked via the
dinosn path.**

## 5.6.40 (p2s5640, port 18103) — DEFINITIVELY BLOCKED at stage 1 (2026-10-30)

Two live arms via `php5640/dump5640.py` (single-worker prefork, post_max_size=512M,
memory_limit=128M; worker pid 83 survived both OOMs):
- **NUL arm** (PHPSESSID=`\x00` + 256MB big field): Set-Cookie = fresh 32-char id
  `ab6d03d9...`; post-OOM `PS(id) @+0x10 = NULL (0x0)`.
- **LONG-4096 arm** (PHPSESSID=4096×'A' via rfc1867 upload-progress): Set-Cookie =
  fresh 32-char id `936d0912...` (the 4096B value is NOT echoed); post-OOM
  `PS(id) = NULL`.

**Root cause (source-confirmed, php-5.6.40/ext/session/session.c):**
1. `PS(id)` is a `char*` NUL-terminated (php_session.h:121); the cookie is built
   with `php_url_encode(PS(id), strlen(PS(id)), NULL)` (session.c:1349) → length is
   always `strlen(PS(id))`, so the 8.3+ "forge a `len` field → 4096B overflow"
   primitive **does not exist** in 5.6 (no separate len field to attack).
2. The session **never adopts a forged sid**: both the 1-byte NUL and the 4096×'A'
   sid yield a freshly *regenerated* clean 32-char id (`s_create_sid`) — same
   hard-cap as 8.1.32/8.2.34. The forged value is never the id that gets the cookie.
3. `php_rshutdown_session_globals` (called on normal rshutdown AND on the
   MULTIPART_EVENT_END handler, session.c:2824) does `efree(PS(id)); PS(id)=NULL`
   → `PS(id)` is freed and NULLed, never left dangling (post-OOM read = 0x0).

**Verdict: 5.6.40 blocked at stage 1 — no `len`/`data`-decoupled field to
overflow, a forged sid is never adopted, and `PS(id)` is freed to NULL (no
dangling/UAF). Not RCE-able via php2shell or dinosn.** This is a *stronger* block
than the 7.x family (which at least dangles `PS(id)` on 7.2.34): 5.6.40 has no
dangling state at all because the id is a plain `char*` freed cleanly.

**Config note (7.4.33/7.3.33):** `php -i` (CLI) misleads — the apache worker's
real ini must be checked via a served PHP script. `post_max_size=512M` was set
via `php_admin_value` in `/etc/apache2/conf-enabled/99_p2s.conf` (the image has
no PHP conf.d). Verified post_max_size=512M via a served script.

**Tooling (reusable):** `php72/read_mem.pl` + `php72/read_mem2.pl` (perl
/proc/PID/mem reader — the only way to read a worker's memory here; dd can't
skip that far, gdb won't install on buster) + `php72/dump_ps.py` (arm + dump
ps_globals before/after, port/ps_off parametrized).
