# windows/ — recovered from the Windows lab box (LAB_IP2, WSL2) kurtarilan php2shell incelenmeleri

> 2026-11-05'te Mac'e rsync/tar-pipe ile tasindi. Kaynak: kullanicinin kendi Windows
> kutusu (yetkili, izole Docker hedefler — `ghn_VULNERABILITY_CHAIN.md`'deki kullanim
> kisitlari gecerli). **Sirlar bu agaca alinmadi** (p2s SSH keypair, hexlic vb. disarida).

## Icerik
- **`p2s52704/`** — ana proje: sub-8.3 sequential deep-dive (8.2.34 → 5.4.45, 11 versiyon).
  `PROGRESS.md` (versiyon tablosu: hard-fatal vs soft-bailout OOM triaji), `REPORT.md`,
  `STATUS.md`, ~30 test scripti (`alt_oom_*`, `alt_rce_*`, `dbg_*`, `calibrate_*`, `chunked_test`),
  `php72/` (dinosn chain), `poc/`, `test/`, `results/`.
  Haric: `archive/*.so` (72M libphp binary), `tmp_8335/*.bin` (34M payload), `__pycache__`.
- **`tmp-p2s/`** — calisma alani incelenmeleri: PHP engine diff'leri (`diff_alloc`,
  `diff_execute_api`, `diff_session`, `diff_variables`), surum karsilastirmalari
  (`fc_*_8335_8426`), exploit/POC scriptleri (`gh_9bie_*`, `gh_aarsaputra_*`, `gh_agr_*`,
  `gh_pure_*`), `ghn_VULNERABILITY_CHAIN.md`, `ghn_README.md`, `ghn_*_artifacts_*.json`
  (Contabo native x86 WordPress kanitlari), `patch.diff` (1.1M).
  Haric: `php-*/` kaynak agaclari (php.net'ten indirilebilir) + `php*.tgz` (138M).
- **`docs/P2S_DOCKER_TEST_ENV.md`** — 14 PHP Docker hedefinin (18101–18114) kurulum dokumani.
- **`scripts/`** — `p2s_probe.php`, deploy/setup/fix bat'leri, `a.cmd`/`acik.bat`/`kapali.bat`.
