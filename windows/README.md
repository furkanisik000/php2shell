# windows/ — Windows kutusundan (192.168.8.153, WSL2) kurtarılan php2shell ıncelenmeleri

> 2026-11-05'te Mac'e rsync/tar-pipe ile taşındı. Kaynak: kullanıcının kendi Windows
> kutusu (yetkili, izole Docker hedefler — `ghn_VULNERABILITY_CHAIN.md`'deki kullanım
> kısıtları geçerli). **Sırlar bu ağaca alınmadı** (p2s SSH keypair, hexlic vb. dışarıda).

## İçerik
- **`p2s52704/`** — ana proje: sub-8.3 sequential deep-dive (8.2.34 → 5.4.45, 11 versiyon).
  `PROGRESS.md` (versiyon tablosu: hard-fatal vs soft-bailout OOM triajı), `REPORT.md`,
  `STATUS.md`, ~30 test scripti (`alt_oom_*`, `alt_rce_*`, `dbg_*`, `calibrate_*`, `chunked_test`),
  `php72/` (dinosn chain), `poc/`, `test/`, `results/`.
  Hariç: `archive/*.so` (72M libphp binary), `tmp_8335/*.bin` (34M payload), `__pycache__`.
- **`tmp-p2s/`** — çalışma alanı ıncelenmeleri: PHP engine diff'leri (`diff_alloc`,
  `diff_execute_api`, `diff_session`, `diff_variables`), sürüm karşılaştırmaları
  (`fc_*_8335_8426`), exploit/POC scriptleri (`gh_9bie_*`, `gh_aarsaputra_*`, `gh_agr_*`,
  `gh_pure_*`), `ghn_VULNERABILITY_CHAIN.md`, `ghn_README.md`, `ghn_*_artifacts_*.json`
  (Contabo native x86 WordPress kanıtları), `patch.diff` (1.1M).
  Hariç: `php-*/` kaynak ağaçları (php.net'ten indirilebilir) + `php*.tgz` (138M).
- **`docs/P2S_DOCKER_TEST_ENV.md`** — 14 PHP Docker hedefinin (18101–18114) kurulum dokümanı.
- **`scripts/`** — `p2s_probe.php`, deploy/setup/fix bat'leri, `a.cmd`/`acik.bat`/`kapali.bat`.
