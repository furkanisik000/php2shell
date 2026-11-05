# php2shell

Aktif CVE (PHP RCE → webshell) arastirma projesi: PoC kaynaklari, hedef simulasyon
cevreleri (Docker), kanit loglari ve raporlar. Proje pusulasi `PUSULA.md`, orijinal
upstream PoC referansi `upstream-reference/` altinda.

Yerel yol: `~/projects/php2shell` · GitHub: `OWNER/php2shell` (private)

Not: `.tmp/labs/` (PHP build lab'i) ve derlenmis binary'ler bu repoda tutulmaz (boyut kurali).

## windows/ (2026-11-05)
recovered from the Windows lab box (LAB_IP2, WSL2) kurtarilan incelenmeler: `p2s52704/` (sub-8.3 deep-dive), `tmp-p2s/` (engine diff+POC+kanit), `docs/`+`scripts/` (Docker hedef kurulumu). Detay: `windows/README.md`.
