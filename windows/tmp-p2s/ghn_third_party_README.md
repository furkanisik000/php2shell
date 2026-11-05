# Third-party exploit bundles (manuell, nicht im Git)

Hier legst du **selbst** heruntergeladene Forschungs-Bundles ab (nur autorisierte Lab-Nutzung).

## Jackalsyn (PHP-UP-2026)

```bash
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab fetch-jackalsyn   # einmalig
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab up
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab jackalsyn selftest
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab jackalsyn syms
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab jackalsyn lab
```

- Framework: `third_party/php-up-2026/bin/php_up_framework.py` (Mirror-Layout wie Jackalsyn-Bundle)
- Repro-ZIP: `third_party/jackalsyn-reup/` von [jackalsyn.com](https://jackalsyn.com/posts/php-up-2026.html) (`php2shell-reup.zip`, SHA256 geprüft)

`php_up_framework.py` wird im Attacker-Container unter `/opt/third_party/` gemountet.

## Zer061 mod_php Exploit

```bash
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab apache-up
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab fetch-zer061
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab zer061
```

Target: `php:8.4.26-apache`, Host-Port **19288**, Container `vtbw-php2shell-apache`.

Multi-Target: `apache-multi-up` → **19288** + **19289**, Liste `targets/lab-targets.txt`.

Kit-Extras (nach `fetch-zer061`):

```bash
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab scan
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab exploit-list
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab docs list
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab tools list
```

## reverse-shell.sh ([lukechilds/reverse-shell](https://github.com/lukechilds/reverse-shell))

```bash
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab fetch-reverse-shell
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab reverse-shell fetch
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab reverse-shell listen
```

Payload landet in `zer061-php2shell/out/r` (gemeinsames `/out` am Apache-Target). Zer061-Trigger: `sh</out/r` (8 Bytes).

## Sliver C2 (Post-Exploit Adversary Emulation)

```bash
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab fetch-sliver
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab sliver server-up
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab sliver operator
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab sliver listener
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab sliver implant
```

Externe Sicht: `tunnel up web` (Web-Target) oder `sliver http-listener` + `tunnel up sliver-http` (C2 über Cloudflare Quick Tunnel). Ops-Logs: `out/sliver/ops.log`, `out/tunnel/ops.log`. Menü **[6]**.

## Singularity (Post-Exploit LKM)

```bash
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab fetch-singularity
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab singularity status
~/Schreibtisch/cursor-projects/vtbw-php2shell-lab singularity runtime
```

Nur VM / Host / Compose-Profil `singularity` — **nicht** in FPM/Apache-PHP-Containern. Doku: `docs/SINGULARITY-LAB.md`, Menü **[7]**.

## Menü

```bash
~/Schreibtisch/cursor-projects/php2shell-unchained
```

## Sicherheit

- Ordner in `.gitignore` — keine Commits von Exploit-Code.
- Keine Produktions-URLs in Skripten.
