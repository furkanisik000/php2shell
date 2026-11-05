"""lib/version.py — cek versi otomatis: lokal vs rilis publik di GitHub.

Tiga peran:
  1. `local_version()`      — versi toolkit yang sedang jalan.
  2. `remote_version()`     — versi terbaru di repo publik (tag rilis, fallback
                              ke `VERSION` di branch main).
  3. `check()`              — bandingkan keduanya, kembalikan hasil terstruktur.

Prinsip:
  - TANPA dependensi baru (urllib dari stdlib + curl_cffi kalau ada).
  - Gagal-aman: offline, DNS mati, GitHub rate-limit, repo 404 → tidak pernah
    melempar exception ke pemanggil, hanya `status="unknown"` + alasan.
  - Tidak mengirim data apa pun selain request GET biasa; tidak ada telemetry.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = "aarsaputra/php2shell"
BRANCH = "main"
RAW_VERSION_URL = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/php2shell.py"
API_TAGS_URL = f"https://api.github.com/repos/{REPO}/tags"
API_RELEASE_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
TIMEOUT = 8.0
CACHE_TTL = 3600  # detik; cek ulang paling sering 1 jam sekali
UA = "php2shell-version-check"

_STATUS_ORDER = ("unknown", "ahead", "current", "behind")


@dataclass
class VersionCheck:
    local: str
    remote: str | None = None
    remote_source: str = ""  # "tag" | "branch" | ""
    status: str = "unknown"  # current | behind | ahead | unknown
    message: str = ""
    url: str = f"https://github.com/{REPO}"
    checked_at: float = field(default_factory=time.time)

    @property
    def up_to_date(self) -> bool:
        return self.status == "current"

    @property
    def update_available(self) -> bool:
        return self.status == "behind"

    def as_dict(self) -> dict[str, Any]:
        return {
            "local": self.local,
            "remote": self.remote,
            "remote_source": self.remote_source,
            "status": self.status,
            "message": self.message,
            "url": self.url,
        }


# ---------------------------------------------------------------- versi lokal


def local_version(default: str = "0.0.0") -> str:
    """Versi toolkit yang sedang jalan.

    Urutan sumber: `VERSION` di php2shell.py (import), lalu git describe, lalu default.
    """
    try:  # jalur normal: diimpor dari paket yang sama
        import php2shell as _m  # type: ignore

        v = getattr(_m, "VERSION", None)
        if v:
            return str(v)
    except Exception:  # noqa: BLE001
        pass

    here = Path(__file__).resolve().parent
    py = here.parent / "php2shell.py"
    try:
        m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', py.read_text(encoding="utf-8"), re.M)
        if m:
            return m.group(1)
    except Exception:  # noqa: BLE001
        pass

    try:
        import subprocess

        out = subprocess.run(
            ["git", "-C", str(here.parent), "describe", "--tags", "--abbrev=0"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip().lstrip("v")
    except Exception:  # noqa: BLE001
        pass
    return default


# --------------------------------------------------------------- versi remote


def _http_get(url: str, timeout: float = TIMEOUT) -> str:
    """GET sederhana; pakai curl_cffi kalau ada (biar tidak ditolak CDN)."""
    headers = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    try:
        from curl_cffi import requests as creq  # type: ignore

        r = creq.get(url, headers=headers, timeout=timeout, impersonate="chrome")
        if r.status_code == 200:
            return r.text
        raise RuntimeError(f"HTTP {r.status_code} dari {url}")
    except ImportError:
        pass
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _norm(v: str) -> str:
    return v.strip().lstrip("vV")


def _parse_triple(v: str) -> tuple[int, ...] | None:
    parts = re.findall(r"\d+", _norm(v))
    if not parts:
        return None
    return tuple(int(p) for p in parts[:4])


def compare(local: str, remote: str) -> str:
    """current | behind | ahead | unknown — bandingkan per komponen numerik."""
    a, b = _parse_triple(local), _parse_triple(remote)
    if not a or not b:
        return "unknown"
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    if a == b:
        return "current"
    return "behind" if a < b else "ahead"


def remote_version(timeout: float = TIMEOUT) -> tuple[str | None, str, str]:
    """(versi, sumber, error). Sumber: 'tag' | 'branch' | ''."""
    # 1) tag rilis / API tags
    for url in (API_RELEASE_URL, API_TAGS_URL):
        try:
            body = _http_get(url, timeout=timeout)
            data = json.loads(body)
            if isinstance(data, dict) and data.get("tag_name"):
                return _norm(data["tag_name"]), "tag", ""
            if isinstance(data, list) and data:
                names = [str(t.get("name", "")) for t in data if isinstance(t, dict)]
                names = [n for n in names if _parse_triple(n)]
                if names:
                    names.sort(key=lambda s: _parse_triple(s) or (0,))
                    return _norm(names[-1]), "tag", ""
        except Exception as exc:  # noqa: BLE001 - lanjut ke sumber berikutnya
            last = f"{type(exc).__name__}: {exc}"
            continue

    # 2) fallback: VERSION di branch main
    try:
        body = _http_get(RAW_VERSION_URL, timeout=timeout)
        m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', body, re.M)
        if m:
            return _norm(m.group(1)), "branch", ""
        return None, "", "VERSION tidak ditemukan di branch main"
    except Exception as exc:  # noqa: BLE001
        return None, "", f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------- cache


def _cache_path() -> Path:
    return Path(__file__).resolve().parent.parent / "out" / "version-check.json"


def _cache_read() -> VersionCheck | None:
    p = _cache_path()
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        if time.time() - float(raw.get("checked_at", 0)) > CACHE_TTL:
            return None
        return VersionCheck(**raw)
    except Exception:  # noqa: BLE001
        return None


def _cache_write(vc: VersionCheck) -> None:
    p = _cache_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({**vc.as_dict(), "checked_at": vc.checked_at}, indent=2),
                     encoding="utf-8")
    except Exception:  # noqa: BLE001 - cache gagal bukan alasan menggagalkan cek
        pass


# ---------------------------------------------------------------------- publik


def check(local: str | None = None, *, use_cache: bool = True,
          timeout: float = TIMEOUT) -> VersionCheck:
    """Bandingkan versi lokal dengan rilis publik. Tidak pernah melempar exception."""
    lv = local or local_version()

    if use_cache:
        cached = _cache_read()
        if cached and cached.local == lv:
            return cached

    rv, source, err = remote_version(timeout=timeout)
    if not rv:
        vc = VersionCheck(
            local=lv, status="unknown",
            message=f"tidak bisa cek versi terbaru ({err or 'remote kosong'})",
        )
        return vc

    status = compare(lv, rv)
    msg = {
        "current": f"php2shell {lv} — sudah versi terbaru",
        "behind": f"update tersedia: {lv} → {rv} (sumber: {source})",
        "ahead": f"versi lokal {lv} lebih baru dari rilis publik {rv} (belum dirilis)",
        "unknown": f"tidak bisa membandingkan {lv!r} dengan {rv!r}",
    }[status]
    vc = VersionCheck(local=lv, remote=rv, remote_source=source, status=status, message=msg)
    if status in ("current", "behind", "ahead"):
        _cache_write(vc)
    return vc


def format_line(vc: VersionCheck) -> str:
    """Satu baris ringkas untuk banner / log."""
    mark = {"current": "✓", "behind": "↑", "ahead": "·", "unknown": "?"}[vc.status]
    return f"versi {vc.local} {mark} {vc.message}"
