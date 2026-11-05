# PHP 7.2 — the same stale-globals class, end to end under `post_max_size=8M`

CVE-2026-109618 / CVE-2026-109619 are fixed for the supported branches
(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). PHP 7.2 is EOL: there is no patch to
diff, no fixed build to use as a truth-negative, and nothing upstream to
coordinate with. The interesting question for a defender is therefore not
"is 7.2 patched" (it is not, and never will be) but **whether the 7.2
geometry still yields the class**, and what a front control has to stop.

This document answers that on two official images, `php:7.2-apache`
(7.2.34) and `php:7.2.21-apache`. Everything below was measured on
loopback containers; no third-party host contributed to it.

**Verdict.** The class is live on 7.2 and the chain is **complete on the
lab**: both address bases leak from a single in-band `Set-Cookie` and the
dispatch executes as `uid=33(www-data)` — **6/6 end-to-end runs under
`post_max_size=8M`**, including 5-worker prefork pools, plus 4/4
gdb-verified runs across three ASLR generations. The wire cost is small:
the leak arm is **3.9 MB** and the leak consumer **6.3 MB**.

| gate | result |
|---|---|
| source map, 7.2.34 vs 8.4.26 | **identical mechanism** — same window, different geometry (re-derived below) |
| OOM site | inside `rfc1867_post_handler` during `php_hash_environment()`, i.e. **before `zend_activate_modules()`** |
| leak: both bases from one cookie | **yes** — 73/73 `pDestructor` records agree, 4 KiB-aligned |
| fire: `zif_system` dispatch | **yes** — network-only, no debugger, `uid=33` |
| reliability | **6/6** end-to-end at `memory_limit≈160M`, **stock** `post_max_size=8M` / `max_input_vars=1000` |

Tools: `tools/php72/` (`drive.py`, `chain72.py`, `fullchain.py`).

---

## 1. Why 7.2 has the same window as 8.4

Nothing in the window is branch-specific. Three facts, identical in both
trees:

1. `php_request_startup()` calls `php_hash_environment()` — which parses the
   request body — *before* `zend_activate_modules(); PG(modules_activated)=1;`,
   and the whole body sits inside `zend_try`.
2. A bailout raised from the POST parse therefore leaves
   `PG(modules_activated) == 0` and skips `zend_activate_modules()`.
3. `php_request_shutdown()` guards every module teardown step with
   `if (PG(modules_activated))`. The session RSHUTDOWN —
   `php_rshutdown_session_globals()` — is skipped, while the request heap is
   still freed by `shutdown_memory_manager()`.

So `ps_globals` survives request #1 holding **freed** pointers:
`PS(http_session_vars)` is a zval reference (`type_info = 0x40A`) pointing at
a released `zend_reference`, and `PS(id)` points at a released
`zend_string`. Request #2 observes both at `php_request_startup`, before
RINIT would reset them.

What differs between the branches is *geometry*: the allocator's chunk map
offset, `sizeof(zend_reference)`, and the field offsets inside
`php_ps_globals`. Those are measured, not assumed (§2).

## 2. The 7.2 geometry (x86-64, gdb-verified)

| property | 7.2.34 | 8.4.26 |
|---|---|---|
| chunk | 2 MiB / 512 × 4 KiB pages | same |
| `chunk->free_map` | **+0x1c0** | +0x260-class |
| `chunk->map[512]` | **+0x200** | +0x260-class |
| page info encoding | `0x80000000\|bin` SRUN, `0x40000000\|pages` LRUN, `0xC0000000\|bin\|off` NRUN | same |
| bins | 8,16,24,32,40,48,56,64,80,96,112,128,160,192,224,256,320,384,448,512,640,… | same ladder |
| `zend_reference` | **24 B** (`gc` 8 + `zval` 16) | 40 B (adds `sources`) |
| `zend_array` | 0x38 B, `pDestructor` at **+0x30** | same |
| `zend_string` | 24 B header, inline `val` at **+0x18** | same |
| `zend_execute_data` | `num_args` **+0x2C**, arg1 value **+0x50**, type **+0x58** | same |

Measured `php_ps_globals` (7.2.34, `sizeof(zend_mm_heap)=0x180` so the chunk
header is `heap@0x00 next@0x08 prev@0x10 free_pages@0x18 free_tail@0x1c
num@0x20 reserve@0x24 heap_slot@0x40 free_map@0x1c0 map@0x200`):

| field | offset |
|---|---|
| `id` | **0x10** |
| `session_status` | 0x60 |
| `http_session_vars` (zval) | **0x130** |
| `send_cookie` | **0x158** |
| `rfc1867_progress` | 0x160 |

Per-build symbols (chunk of a symbol's file offset, not a virtual address):

| symbol | 7.2.34 | 7.2.21 |
|---|---|---|
| `zif_system` | **+0x3624e0** | **+0x430870** |
| `_zval_ptr_dtor` (nm) | +0x441b20 | +0x50f8f0 |
| stored `pDestructor` value | **+0x441b2b** (`sym+0xb`) | **+0x50f8f0** (delta 0) |
| `_zend_bailout` | +0x163561 | +0x16d2a9 |

The stored `pDestructor` is *not* the symbol address on every 7.2 build,
which is why the window decoder tries a candidate list and accepts a
candidate only when `candidate - delta` is 4 KiB-aligned. The alignment
test is build-independent; a single hardcoded delta is not.

## 3. The OOM site, and what it preserves

The trip must land **inside the multipart parser**. Backtrace at the
`memory_limit` fatal (7.2.34):

```text
zend_mm_alloc_pages.cold
zend_mm_alloc_small_slow
rfc1867_post_handler
sapi_handle_post
php_default_treat_data
php_auto_globals_create_post
zend_activate_auto_globals
php_hash_environment
php_request_startup
```

That is the precondition for everything else: module teardown is skipped, so
whatever session state the *failed* init left behind is still there on the
next request.

Cost per part-header line on 7.2 (measured): ≈128 B at PEAK granularity,
≈44 B at the Zend-MM real-size granularity that triggers the limit. A 3-byte
line (`a:\n`, empty value) is the cheapest amplifier; 1,299,780 of them in
one file part is **3,899,616 B of wire** and reaches a 160 MB limit.

## 4. The arm split: leak and fire need *different* session states

This is the structural point of the 7.2 chain, and it is worth stating
plainly because it looks like a tuning problem and is not.

The cookie is emitted only from `php_session_reset_id()`, and only when
`PS(send_cookie)` is set — which happens only in the two *create-a-new-id*
branches of `php_session_initialize()`, and `php_session_track_init()` (the
fire's dtor target) runs *after* `reset_id()`. Inside one request the two
are mutually exclusive:

| arm | `PHPSESSID` | init outcome | state left across the bailout | usable for |
|---|---|---|---|---|
| **arm1** | `\x00` (NUL) | fails inside `php_url_encode` → `reset_id` | `send_cookie=1`, `PS(id)` = fresh id (bin-7), `mod_data` = `ps_files` | **leak** |
| **arm2** | valid 32-byte | init #1 completes (`track_init` runs) | `PS(http_session_vars)` = live `zend_reference` (`type 0x40A`), `send_cookie=0` | **fire** |

Measured: arm1 → `send_cookie=1` at the next request's startup (3/3);
arm2 → `send_cookie=0` at every bailout (7/7 sweep, 4/4 pool). The cookie
cannot be extracted from an arm2 state, and the dtor vector cannot be
reached from an arm1 state, so the chain uses **two pairs** — one per arm —
and that is why the 8M budget is spent twice.

arm1's OOM window is narrow and calibratable: at 160 MB the trip lands in
`php_url_encode` for `nheaders ∈ [1,299,740, 1,299,780]`; two steps below
that land in `smart_str_erealloc` (also inside `php_session_send_cookie`);
at ≥1,299,800 the OOM moves *ahead* of the create path and `send=0`, which
loses the primitive.

arm2 needs the trip *after* `track_init`, which a single-flood arm cannot
guarantee — the flood fills the heap before FILE_START. Splitting the body
into two file parts (the boundary line matters: an attempt that omitted it
silently swallowed part 2 as part 1's body and every sweep looked inert)
gives FILE_START with headroom, a successful init, and *then* a parse-side
trip at `nh1=1,299,500, nh2=1,000` (`track_init=1..2`, `status=2`).

## 5. The leak: two bases from one cookie

### 5.1 What has to be planted

arm1 leaves the stale pair at the **last two pages of the arm's oldest
kept chunk**: `ps_files` at `chunk+0x1fe000` (page 510) and the id at
`chunk+0x1ff000` (page 511). Both pages are FREE at the consumer's session
init, so the consumer must

1. make `ps_close_files(stale PS(mod_data))` survivable — a `ps_files`
   overlay with `lastkey=NULL, basedir=NULL, fd=-1` (note `efree(NULL)` *is*
   safe: `zend_mm_free_heap` guards `page_offset == 0`), and
2. plant a fake `zend_string` with `ZSTR_LEN = 0x180000` at the stale id, so
   `php_url_encode` reads 1.5 MiB past it into the still-live flood data and
   the resulting cookie carries the heap's pointers.

Payloads cannot ride **header values**: `multipart_buffer_headers()` stores
them with `smart_string_appends` (the `strlen` variant), so any embedded NUL
truncates the copy. They ride **form-field values** instead, which become
`zend_string`s.

### 5.2 Placement law (measured, then reproduced 3/3)

1. The consumer's page allocations fill chunks **FIFO from the cache head**;
   a large allocation (`>3072 B`) takes the *smallest sufficient* free run.
2. A payload block must therefore **exactly fill** the stale chunk's
   remaining free tail (`T == fp`). `T < fp` leaves page 511 uncovered;
   `T > fp` pops the next cached chunk and the payload lands elsewhere.
3. With the pre-drain shape the tail is taken by the **raw multipart value
   buffer**, which grows in place — so the planting offsets are **raw**
   (content at block start, no `-0x18`). Using the registered-`zend_string`
   offsets on this shape plants `ps_files` 24 bytes early and the child dies
   in `_efree` (measured 3/3).
4. **Windowed payloads remove the ±1-page sensitivity**: plant the dual-use
   pair at the offsets for *every* candidate block-start page
   `S ∈ [512-T, 509]`. Whatever page the block really starts on, page 510
   carries `ps_files{…}` and page 511 carries the fake `zend_string`.
5. The multipart line buffer must be **pre-grown** (one 82,000-byte header
   early in the flood); otherwise the payload's own buffer growth competes
   for the same tail and the block never reaches page 510.

Working parameters: arm `nheaders=1,299,780`; consumer one file part with
the 82,000-byte primer + 646,955 × `a:\n` + a **73,600-byte** (or
84,000-byte with a 21-page tail) form value, then the session fields.

### 5.3 The second half: a HashTable must land inside the window

A 1.5 MiB window of pure flood data decodes the chunk base and nothing
else — every pointer in it is either flood text or points inside the same
chunk. The libphp half needs a `HashTable` (56 B, **bin-56**) *inside* the
window, and the window is the stale chunk's upper **+2 MiB neighbour**.

The page allocator only hands out a new bin page when the bin's free list is
empty (~73 slots). Without a pre-drain that boundary is crossed at carrier
~73 — deep inside the stale chunk, *below* the window. Sliding the carrier
phase (`na`) moves the crossing between chunks but loses the payload fit.

**The lever is a bin-56 pre-drain.** `npred` nested-name parts (`qNNNN[j]`,
`depth` array levels, one bin-56 HashTable per level) placed between the
flood and the carriers consume bin-56 slots at ~70 B of wire each, moving
the boundary crossing into the neighbour chunk's page range:

| `npred` (depth 1) | bin-56 page | inside the window (0..383)? |
|---|---|---|
| 0 | stale chunk 176 | no |
| 20 | neighbour 486 | no |
| **40** | **neighbour 291** | **yes** |
| 60 | neighbour 463 | no |
| **80** | **neighbour 261** | **yes** |

At `npred=40` the decode yields both bases from one cookie, with **73/73**
independent `HashTable` records agreeing on `pDestructor` and a 4 KiB-aligned
`LIBPHP_BASE` that matches the process's own mapping byte for byte:

```text
arm_wire  = 3,899,616   -> "Allowed memory size of 167772160 bytes exhausted"
chain9    = 6,337,236   -> HTTP 200, Set-Cookie (encoded 2,203,272 B)
decoded   = 1,572,864   = 0x180000
CHUNK_BASE  : 14,643 votes (2 MiB alignment)
LIBPHP_BASE : 73/73 dtor agreement, 4 KiB-aligned, equals /proc/<pid>/maps
```

Consumers never need to know which build produced the cookie: they try the
candidate `pDestructor` deltas and require the alignment test to pass.

## 6. The fire: exhaust bin-24, land a 615-byte carrier in bin-640

The dispatch is `zval_ptr_dtor(&PS(http_session_vars))` at request shutdown:
`IS_REFERENCE` → `i_zval_ptr_dtor(&ref->val)` → `IS_ARRAY` →
`zend_array_destroy` → `zend_hash_destroy` (static-keys, no holes) →
`pDestructor(&bucket->val)` = `zif_system`.

So the stale `zend_reference` address must be reclaimed by **one
page-aligned large-run block whose content is the fake structures**. On a
*freshly forked* child the reference sits at `chunk+0x69498` (page 105,
offset 0x498 = `21 × 640`); the 22nd 615-byte carrier in the right run lands
there — but only if the allocation sequence is the same, and that is exactly
what a warmed child changes (measured shift to page 104 → miss).

**The lever.** Header keys of 17–24 bytes go through `estrdup` into
**bin-24** and stay live until the part body is read. `nlong=3,820` of them
(before the flood, in the same file part) exhaust bin-24 so that the live
reference is placed *after* `track_init` and lands at **chunk page 244,
offset 0x798** — which is the content offset (`0x780 + 0x18`) of **bin-640
slot 3**. Bin-640 pages follow a fixed 5-page phase in the consumer
(`107,117,127,132,138,147,152,158,163,168,174,179,184,189,194,199,204,209,
214,219,224,229,234,239,244,…`), so page 244 is bin-640 and a **615-byte
form value** written at that slot *is* the fake object.

The 615-byte blob, raw (one block, offsets from the block start):

| offset | content |
|---|---|
| 0x00 | fake `zend_reference`: `gc={rc, IS_REFERENCE}` |
| 0x08 | `ref.val = table` |
| 0x10 | `val.u1.type_info = 0x1407` (IS_ARRAY) |
| 0x18 | fake `zend_array`: `u.flags=0x10` (static keys), `nTableMask=-8`, `arData=table+0x20`, `nNumUsed=nNumOfElements=1`, `nTableSize=8` |
| 0x48 | `pDestructor = zif_system` (`table+0x30`) |
| 0x64 | fake call frame: `num_args=1` at `exec+0x2C` |
| 0x88 | arg1 value `table+0x80`, type `IS_STRING` at `+0x78` |
| 0x98 | fake `zend_string` for the command: `rc=1, type=6, len`, inline data |

Consumer shape: `[400 × blob form values][file part: 82,000-byte primer +
1,260,000 × a:\n + body][PHPSESSID, PHP_SESSION_UPLOAD_PROGRESS]`. The flood
re-maps ~40 chunks so the END-init's `ps_close_files(stale PS(mod_data))`
survives (a small body dies with `zend_mm_heap corrupted` before
`track_init`), and the session fields come **last** so the rfc1867 callback
runs `php_session_initialize()` during the parse, before module RINIT.

## 7. Deriving the address, and the ladder

`MAIN_CHUNK = CHUNK_BASE + 0xBE00000` — measured constant across
generations on both images. From there two shapes are published:

| driver | `R0` | carrier count | note |
|---|---|---|---|
| `chain72.py --mode firepair` | `MAIN + 0x69018` | 40–760 × 615 B | fresh child (page 105 after `track_init`) |
| `chain72.py --mode full` / `fullchain.py` | `MAIN + 0xf4798` | 400 × 615 B | post-leak shape with the long-header lever |

`table = R0 + 0x18`, `system = LIBPHP_BASE + zif_system`.

The stale chunk can be either the one containing `MAIN` page 244 or the one
below it, so the fire runs a **three-candidate ladder**:
`kref ∈ {0xBCF4798, 0xBEF4798, 0xBAF4798}` (±2 MiB), one attempt per
candidate on a fresh connection/child. A hit is identified by the proof
file, not by the response (the worker aborts *after* the command runs, in
`php_exec`'s `RETVAL` write, because `execute_data->return_value` (+0x10)
aliases `pDestructor` (+0x30) and points at libphp text — the same
post-command abort the 8.x chain accepts; the proof is written first).

## 8. Receipts

End-to-end under **stock** `post_max_size=8M` and `max_input_vars=1000`,
`memory_limit≈160M`, network only, no debugger:

| # | pool | leak | fire | proof |
|---|---|---|---|---|
| 0 | single worker (probe) | — (absolute addrs) | arm2 long-header | `uid=33(www-data)` |
| 1 | 5 workers, pristine | CHUNK/LIBPHP 73/73 | `kref 0xBCF4798` | `uid=33` |
| 2 | 5 workers, restarted | new generation | ladder | `uid=33` |
| 3 | 5 workers, restarted | new generation | ladder | `uid=33` |
| 4 | 5 workers, restarted | new generation | ladder | `uid=33` |
| 5 | 5 workers, restarted | new generation | ladder + tagged cmd | `uid=33` |

Rows 1–5 are full A → leak → fire sequences on the 5-worker pool; row 0 is
the single-worker fire probe used to derive the landing. Plus 4/4
gdb-verified runs (single worker) across three independent ASLR generations,
and arm2 alone 4/4 on the 5-worker pool. The fire needs neither
`post_max_size=0` (chunked framing skips the Content-Length gate) nor
`max_input_vars>1000` (the consumer uses 20 GET vars + 42 POST fields).

## 9. Limits (honest)

- **7.2 only, and only the two images tested.** 7.2.34 and 7.2.21 are
  calibrated. A different 7.2 build needs its own `zif_system`,
  `pDestructor` delta, and geometry pass; the constants do not carry over.
- **Chunked framing is required** to exceed a stock `post_max_size=8M`, and
  a front that de-chunks and re-frames with a Content-Length cap blocks the
  arm entirely. On such a front nothing in this chain runs: the bodies are
  dropped unparsed, which is observable as "the app stub answers, PHP never
  parses" (no `$_POST`, no session init).
- **Same-child placement.** arm and consumer must be served by one prefork
  child. Use **one keep-alive connection** (works at any pool width,
  verified on 5 workers) or a single-worker pool. The intra-pair gap must
  stay under `KeepAliveTimeout` (5 s); 6 s silently loses the connection.
- **Fresh child for the fire.** A child that just served the leak, or a pool
  warmed by ~100 requests, shifts `R0` and the 40-carrier body misses (the
  ladder covers ±2 MiB, not an arbitrary shift). The fire's own abort
  rotates the child for the next attempt.
- **`memory_limit` bracket.** The calibration is for ≈160 MB. At 128 MB the
  fill sizes change; at 192 MB+ the arm no longer trips with these counts.
- **No truth-negative exists.** PHP 7.2 is EOL and unpatched, so there is no
  fixed build to test against. The honest boundary is "7.2 is EOL forever",
  and the control work belongs on the front (a body cap that the parser
  never sees), not on a patch.

## 10. Files

```text
tools/php72/drive.py       one-connection driver: arm / fill / chain2..chain9 / arm2 / arm3
tools/php72/chain72.py     arm2_long_body, fire_body, blob, decode; leakpair / firepair / full
tools/php72/fullchain.py   A -> leak -> ladder -> fire in one shot
```

Run against a local mirror with a single-worker prefork and
`memory_limit=160M`:

```bash
python3 tools/php72/drive.py --port 7211 --plan "arm,chain9:614000:40:1:77:60000:0" \
        --carlen 84000 --primlen 82000 --json leak.json
python3 tools/php72/chain72.py --mode full --port 7211 --json full.json
python3 tools/php72/fullchain.py --port 7211 --krefs 0xBCF4798,0xBEF4798,0xBAF4798
```

`--mode firepair` takes `--table/--system` explicitly when the bases come
from an out-of-band source (a debugger, or a previous leak), which is how
the gdb-verified runs were made.
