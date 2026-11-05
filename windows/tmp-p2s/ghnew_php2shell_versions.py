"""
CVE-2026-109618 — Complete version matrix and default config database.

Fix commits: 01a40e89fb / 3584a98bda0f (21-22 Oct 2026)
Fix versions: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
All PHP ≤ 8.1 is EOL and permanently vulnerable.

The CVE fires in PHP's POST parsing layer (zend_hash.c) before any
CMS code runs. Default configs are unchanged across PHP 7.2–8.5:
  memory_limit=128M, max_input_vars=1000, post_max_size=8M
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import NamedTuple


class VulnStatus(Enum):
    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    EOL_VULNERABLE = "eol_vulnerable"
    UNKNOWN = "unknown"


class PHPFixBound(NamedTuple):
    major: int
    minor: int
    fix_patch: int


FIX_BOUNDS: list[PHPFixBound] = [
    PHPFixBound(8, 5, 12),
    PHPFixBound(8, 4, 27),
    PHPFixBound(8, 3, 36),
    PHPFixBound(8, 2, 35),
]

EOL_LAST_RELEASES: dict[tuple[int, int], str] = {
    (8, 1): "8.1.31",
    (8, 0): "8.0.30",
    (7, 4): "7.4.33",
    (7, 3): "7.3.33",
    (7, 2): "7.2.34",
    (7, 1): "7.1.33",
    (7, 0): "7.0.33",
    (5, 6): "5.6.40",
}

PHP_DEFAULTS: dict[str, int | str] = {
    "memory_limit": 128 * 1024 * 1024,
    "max_input_vars": 1000,
    "post_max_size": 8 * 1024 * 1024,
    "max_input_time": 60,
    "max_execution_time": 30,
    "upload_max_filesize": 2 * 1024 * 1024,
}


@dataclass
class VersionCheck:
    version: str
    major: int
    minor: int
    patch: int
    status: VulnStatus
    fix_version: str | None = None
    eol: bool = False

    @property
    def branch(self) -> str:
        return f"{self.major}.{self.minor}"

    @property
    def display(self) -> str:
        if self.status == VulnStatus.EOL_VULNERABLE:
            return f"{self.version} — VULNERABLE (EOL, no fix available)"
        if self.status == VulnStatus.VULNERABLE:
            return f"{self.version} — VULNERABLE (fix: {self.fix_version})"
        if self.status == VulnStatus.FIXED:
            return f"{self.version} — FIXED"
        return f"{self.version} — UNKNOWN"


def parse_version(version: str) -> tuple[int, int, int] | None:
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def check_version(version: str) -> VersionCheck:
    parsed = parse_version(version)
    if not parsed:
        return VersionCheck(version, 0, 0, 0, VulnStatus.UNKNOWN)

    major, minor, patch = parsed

    for fb in FIX_BOUNDS:
        if major == fb.major and minor == fb.minor:
            if patch < fb.fix_patch:
                return VersionCheck(
                    version, major, minor, patch,
                    VulnStatus.VULNERABLE,
                    fix_version=f"{fb.major}.{fb.minor}.{fb.fix_patch}",
                )
            return VersionCheck(
                version, major, minor, patch, VulnStatus.FIXED,
                fix_version=f"{fb.major}.{fb.minor}.{fb.fix_patch}",
            )

    if major < 8 or (major == 8 and minor <= 1):
        return VersionCheck(
            version, major, minor, patch,
            VulnStatus.EOL_VULNERABLE, eol=True,
        )

    if major > 8 or (major == 8 and minor > 5):
        return VersionCheck(version, major, minor, patch, VulnStatus.UNKNOWN)

    return VersionCheck(version, major, minor, patch, VulnStatus.UNKNOWN)


def is_vulnerable(version: str) -> bool | None:
    vc = check_version(version)
    if vc.status in (VulnStatus.VULNERABLE, VulnStatus.EOL_VULNERABLE):
        return True
    if vc.status == VulnStatus.FIXED:
        return False
    return None


VULN_RANGES: dict[str, str] = {
    "8.5": "< 8.5.12",
    "8.4": "< 8.4.27",
    "8.3": "< 8.3.36",
    "8.2": "< 8.2.35",
    "8.1": "ALL (EOL — 8.1.31 was last)",
    "8.0": "ALL (EOL — 8.0.30 was last)",
    "7.4": "ALL (EOL — 7.4.33 was last)",
    "7.3": "ALL (EOL — 7.3.33 was last)",
    "7.2": "ALL (EOL — 7.2.34 was last)",
    "7.1": "ALL (EOL)",
    "7.0": "ALL (EOL)",
    "5.x": "ALL (EOL)",
}


# -- CMS compatibility --------------------------------------------------------

class CMSType(Enum):
    WORDPRESS = "wordpress"
    LARAVEL = "laravel"
    BACKPACK = "backpack"
    DRUPAL = "drupal"
    GENERIC_PHP = "generic"


@dataclass
class CMSProfile:
    cms: CMSType
    typical_memory_limits: list[int] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    csrf_blocks_trigger: bool = False
    notes: str = ""


WP_PROFILE = CMSProfile(
    cms=CMSType.WORDPRESS,
    typical_memory_limits=[
        40 * 1024 * 1024,
        64 * 1024 * 1024,
        128 * 1024 * 1024,
        256 * 1024 * 1024,
        512 * 1024 * 1024,
    ],
    endpoints=[
        "/wp-login.php",
        "/wp-comments-post.php",
        "/wp-admin/admin-ajax.php",
        "/wp-json/wp/v2/posts",
        "/xmlrpc.php",
        "/index.php",
    ],
    csrf_blocks_trigger=False,
    notes="WP memory_limit often 40M-256M via wp-config.php WP_MEMORY_LIMIT. "
          "CVE fires before WP code, so any .php endpoint works. "
          "WAF plugins (Wordfence > 10MB block, Sucuri) are main obstacle.",
)

LARAVEL_PROFILE = CMSProfile(
    cms=CMSType.LARAVEL,
    typical_memory_limits=[
        128 * 1024 * 1024,
        256 * 1024 * 1024,
        512 * 1024 * 1024,
        1024 * 1024 * 1024,
    ],
    endpoints=[
        "/login",
        "/register",
        "/password/email",
        "/api/login",
        "/",
    ],
    csrf_blocks_trigger=False,
    notes="CSRF token required but irrelevant: PHP parses POST body before "
          "Laravel middleware runs. Ghost bucket created even on 419 response. "
          "nginx default client_max_body_size=1M limits payload for high mem.",
)

BACKPACK_PROFILE = CMSProfile(
    cms=CMSType.BACKPACK,
    typical_memory_limits=[
        128 * 1024 * 1024,
        256 * 1024 * 1024,
        512 * 1024 * 1024,
    ],
    endpoints=[
        "/admin/login",
        "/admin/dashboard",
        "/api/login",
        "/",
    ],
    csrf_blocks_trigger=False,
    notes="Backpack v6/v7 on Laravel 10-13, all on vulnerable PHP. "
          "Same as Laravel: CSRF doesn't prevent ghost creation.",
)

DRUPAL_PROFILE = CMSProfile(
    cms=CMSType.DRUPAL,
    typical_memory_limits=[
        128 * 1024 * 1024,
        256 * 1024 * 1024,
    ],
    endpoints=[
        "/user/login",
        "/node",
        "/index.php",
    ],
    csrf_blocks_trigger=False,
    notes="Drupal 9/10 on PHP 8.1-8.3. Same PHP parsing layer trigger.",
)

GENERIC_PROFILE = CMSProfile(
    cms=CMSType.GENERIC_PHP,
    typical_memory_limits=[
        128 * 1024 * 1024,
    ],
    endpoints=[
        "/index.php",
        "/",
    ],
    csrf_blocks_trigger=False,
    notes="Default PHP config. CVE works on any endpoint accepting POST.",
)

CMS_PROFILES: dict[CMSType, CMSProfile] = {
    CMSType.WORDPRESS: WP_PROFILE,
    CMSType.LARAVEL: LARAVEL_PROFILE,
    CMSType.BACKPACK: BACKPACK_PROFILE,
    CMSType.DRUPAL: DRUPAL_PROFILE,
    CMSType.GENERIC_PHP: GENERIC_PROFILE,
}


# -- Server limits ------------------------------------------------------------

NGINX_DEFAULT_BODY_SIZE = 1 * 1024 * 1024
APACHE_DEFAULT_BODY_LIMIT = 0  # unlimited by default


@dataclass
class ServerLimits:
    """Known or inferred server-side constraints."""
    client_max_body_size: int | None = None
    post_max_size: int | None = None
    max_input_vars: int | None = None
    memory_limit: int | None = None
    server_software: str | None = None

    @property
    def effective_body_limit(self) -> int:
        limits = []
        if self.client_max_body_size and self.client_max_body_size > 0:
            limits.append(self.client_max_body_size)
        if self.post_max_size and self.post_max_size > 0:
            limits.append(self.post_max_size)
        return min(limits) if limits else PHP_DEFAULTS["post_max_size"]

    @property
    def effective_memory_limit(self) -> int:
        if self.memory_limit and self.memory_limit > 0:
            return self.memory_limit
        return PHP_DEFAULTS["memory_limit"]

    @property
    def effective_max_input_vars(self) -> int:
        if self.max_input_vars and self.max_input_vars > 0:
            return self.max_input_vars
        return PHP_DEFAULTS["max_input_vars"]
