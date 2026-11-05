# php2shell

Aktif CVE (PHP RCE → webshell) araştırma projesi: PoC kaynakları, hedef simülasyon
çevreleri (Docker), kanıt logları ve raporlar. Proje pusulası `PUSULA.md`, orijinal
upstream PoC referansı `upstream-reference/` altında.

Yerel yol: `~/Desktop/php2shell` · GitHub: `furkanisik000/php2shell` (private)

Not: `.tmp/labs/` (PHP build lab'ı) ve derlenmiş binary'ler bu repoda tutulmaz (boyut kuralı).

## windows/ (2026-11-05)
Windows kutusundan (192.168.8.153 WSL2) kurtarılan ıncelenmeler: `p2s52704/` (sub-8.3 deep-dive), `tmp-p2s/` (engine diff+POC+kanıt), `docs/`+`scripts/` (Docker hedef kurulumu). Detay: `windows/README.md`.
