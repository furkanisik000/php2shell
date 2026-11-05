"""Unit tests for php2shell core modules."""
import pytest
from copy import deepcopy

from php2shell.versions import check_version, is_vulnerable, VulnStatus, CMSType
from php2shell.calibrate import calibrate_for_target, ExploitPreset
from php2shell.fingerprint import TargetInfo, PHPInfo, CMSInfo, MEMORY_AMPLIFICATION
from php2shell.exploit import (
    _detect_oom, _detect_crash, DeliveryResult, ExploitResult, RCEPath,
)


# ── Version checks ──────────────────────────────────────────────────

class TestVersionCheck:

    def test_vulnerable_8335(self):
        r = check_version("8.3.35")
        assert r.status == VulnStatus.VULNERABLE

    def test_patched_8336(self):
        r = check_version("8.3.36")
        assert r.status == VulnStatus.FIXED

    def test_vulnerable_8234(self):
        r = check_version("8.2.34")
        assert r.status == VulnStatus.VULNERABLE

    def test_patched_8235(self):
        r = check_version("8.2.35")
        assert r.status == VulnStatus.FIXED

    def test_vulnerable_8426(self):
        r = check_version("8.4.26")
        assert r.status == VulnStatus.VULNERABLE

    def test_patched_8427(self):
        r = check_version("8.4.27")
        assert r.status == VulnStatus.FIXED

    def test_vulnerable_8511(self):
        r = check_version("8.5.11")
        assert r.status == VulnStatus.VULNERABLE

    def test_patched_8512(self):
        r = check_version("8.5.12")
        assert r.status == VulnStatus.FIXED

    def test_eol_81(self):
        r = check_version("8.1.30")
        assert r.status == VulnStatus.EOL_VULNERABLE

    def test_is_vulnerable_bool(self):
        assert is_vulnerable("8.3.35") is True
        assert is_vulnerable("8.3.36") is False


# ── Calibration ─────────────────────────────────────────────────────

class TestCalibration:

    def _make_target(self, mem_mb=128, sapi="apache2handler"):
        t = TargetInfo(url="http://test.local")
        t.php = PHPInfo(
            version="8.3.35",
            sapi=sapi,
            memory_limit=mem_mb * 1024 * 1024,
        )
        t.cms = CMSInfo(cms_type=CMSType("generic"))
        return t

    def test_128m_produces_feasible(self):
        p = calibrate_for_target(self._make_target(128))
        assert p.feasible
        assert p.n_pad > 0
        assert p.trigger_key_len > 0

    def test_256m_produces_feasible(self):
        p = calibrate_for_target(self._make_target(256))
        assert p.feasible

    def test_payload_size_set(self):
        p = calibrate_for_target(self._make_target(128))
        assert p.payload_size > 0

    def test_total_vars_within_limit(self):
        p = calibrate_for_target(self._make_target(128))
        assert p.total_vars <= p.max_input_vars


# ── Payload building ────────────────────────────────────────────────

class TestPayloadBuild:

    def _preset(self):
        t = TargetInfo(url="http://test.local")
        t.php = PHPInfo(version="8.3.35", sapi="apache2handler",
                        memory_limit=128 * 1024 * 1024)
        t.cms = CMSInfo(cms_type=CMSType("generic"))
        return calibrate_for_target(t)

    def test_preset_encoding_urlencoded(self):
        p = self._preset()
        assert p.encoding == "urlencoded"

    def test_pad_value_size(self):
        p = self._preset()
        assert p.pad_value_size == 32767

    def test_n_array_keys_default(self):
        p = self._preset()
        assert p.n_array_keys >= 1

    def test_preset_notes(self):
        p = self._preset()
        assert isinstance(p.notes, list)


# ── OOM detection ───────────────────────────────────────────────────

class TestDetectOOM:

    def test_oom_in_body(self):
        resp = {"body": "Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 65536 bytes)"}
        found, msg = _detect_oom(resp)
        assert found is True
        assert "134217728" in msg

    def test_generic_exhaustion(self):
        resp = {"body": "PHP Fatal: memory exhausted in /var/www"}
        found, _ = _detect_oom(resp)
        assert found is True

    def test_no_oom(self):
        resp = {"body": "<html>OK</html>"}
        found, _ = _detect_oom(resp)
        assert found is False

    def test_empty_body(self):
        resp = {"body": ""}
        found, _ = _detect_oom(resp)
        assert found is False


# ── Crash detection ─────────────────────────────────────────────────

class TestDetectCrash:

    def test_502_is_crash(self):
        assert _detect_crash({"code": 502}) is True

    def test_503_is_crash(self):
        assert _detect_crash({"code": 503}) is True

    def test_0_with_error_is_crash(self):
        assert _detect_crash({"code": 0, "error": "Connection reset"}) is True

    def test_0_without_error_is_not_crash(self):
        assert _detect_crash({"code": 0}) is False

    def test_200_is_not_crash(self):
        assert _detect_crash({"code": 200}) is False

    def test_200_with_error_key_is_not_crash(self):
        assert _detect_crash({"code": 200, "error": "something"}) is False

    def test_missing_code_defaults_200(self):
        assert _detect_crash({}) is False

    def test_500_is_not_crash(self):
        assert _detect_crash({"code": 500}) is False

    def test_504_is_crash(self):
        assert _detect_crash({"code": 504}) is True


# ── OOM detection: extended ─────────────────────────────────────────

class TestDetectOOMExtended:

    def test_out_of_memory(self):
        found, _ = _detect_oom({"body": "Out of memory"})
        assert found is True

    def test_case_insensitive_oom(self):
        found, _ = _detect_oom({"body": "OUT OF MEMORY in allocator"})
        assert found is True


# ── Payload body limit ──────────────────────────────────────────────

class TestPayloadBodyLimit:

    def test_urlencoded_respects_body_limit(self):
        from php2shell.exploit import build_oom_payload
        p = ExploitPreset(n_pad=100, pad_value_size=32767, n_array_keys=30,
                          trigger_key_len=5_000_000, payload_size=8_000_000,
                          memory_target=128 * 1024 * 1024, body_limit=4_000_000)
        payload, _ = build_oom_payload(p, "urlencoded")
        assert len(payload) <= p.body_limit

    def test_multipart_respects_body_limit(self):
        from php2shell.exploit import build_oom_payload
        p = ExploitPreset(n_pad=100, pad_value_size=32767, n_array_keys=30,
                          trigger_key_len=5_000_000, payload_size=8_000_000,
                          memory_target=128 * 1024 * 1024, body_limit=4_000_000)
        payload, _ = build_oom_payload(p, "multipart")
        assert len(payload) <= p.body_limit


# ── Preset mutation safety ──────────────────────────────────────────

class TestPresetMutationSafety:

    def test_deliver_does_not_mutate_preset(self):
        preset = ExploitPreset(
            n_pad=100, trigger_key_len=50000, payload_size=3_300_000,
            memory_target=128 * 1024 * 1024,
        )
        original_n_pad = preset.n_pad
        original_trigger = preset.trigger_key_len
        backup = deepcopy(preset)
        assert preset.n_pad == backup.n_pad
        assert preset.trigger_key_len == backup.trigger_key_len
        assert original_n_pad == preset.n_pad
        assert original_trigger == preset.trigger_key_len
