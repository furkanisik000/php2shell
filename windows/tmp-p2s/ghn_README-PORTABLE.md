# PHP2Shell — unchained (Portable Paket)

**By Leviticus-Triage**

## 1. Entpacken

```bash
tar -xzf php2shell-lab-vtbw-portable-*.tar.gz -C ~/Schreibtisch/
cd ~/Schreibtisch/php2shell-lab-vtbw-portable-*
chmod +x vtbw-php2shell-lab php2shell-unchained vtbw-php2shell-doctor
```

## 2. Menü starten

```bash
./php2shell-unchained
```

Vollständige Schritt-für-Schritt-Anleitung:  
`php2shell-lab-vtbw/docs/HOWTO-DE.md`

## 3. Bundles (Internet nötig, einmalig)

```bash
./vtbw-php2shell-lab fetch-zer061
./vtbw-php2shell-lab fetch-jackalsyn
./vtbw-php2shell-lab fetch-reverse-shell    # optional
cd php2shell-lab-vtbw && docker compose --profile tools build attacker
```

## 4. Kurz-Workflows

| Ziel | Befehle |
|------|---------|
| Interaktiv www-data (FPM) | `up` → `test` → `shell` |
| Heap-RCE mod_php | `apache-up` → `zer061` → `zer061-shell` |
| Jackalsyn | `fetch-jackalsyn` → `up` → `jackalsyn selftest` → `jackalsyn lab` |
| 2 Targets scannen | `apache-multi-up` → `scan` |

## 5. Paketinhalt

```
php2shell-lab-vtbw-portable-<datum>/
├── php2shell-unchained      # Menü
├── vtbw-php2shell-lab       # alle CLI-Befehle (siehe: help)
├── vtbw-php2shell-doctor
├── README-PORTABLE.md       # diese Datei
└── php2shell-lab-vtbw/      # Docker-Lab + docs/
    ├── README.md
    ├── docs/HOWTO-DE.md
    ├── docker-compose.yml
    ├── scripts/
    └── targets/lab-targets.txt
```

**Nicht im Archiv** (nach Entpacken laden): `third_party/zer061-php2shell`, `php-up-2026`, `reverse-shell`, `jackalsyn-reup`.

## 6. Hinweise

- Lab-Netzwerk ist **internal** (kein Internet aus Containern).
- Jackalsyn `lab` nutzt FCGI `target:9000` (php-fpm im FPM-Target).
- Zer061 und Chain-A sind **getrennte** Exploit-Pfade.
