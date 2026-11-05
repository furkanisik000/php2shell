#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=scripts/docker-env.sh
source "$ROOT/scripts/docker-env.sh"
export LAB="$ROOT"
WRAPPER="${VTBW_LAB_WRAPPER:-$HOME/Schreibtisch/cursor-projects/vtbw-php2shell-lab}"

banner() {
  clear 2>/dev/null || true
  cat <<'BANNER'

  ╔══════════════════════════════════════════════════════════════════╗
  ║   ██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗    ║
  ║   ██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║    ║
  ║   ██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║    ║
  ║   ██╔═══╝ ██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║    ║
  ║   ██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗║
  ║   ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝║
  ║                                                                  ║
  ║              ░▒▓  P H P 2 S h e l l  -  u n c h a i n e d  ▓▒░   ║
  ║                      B y   L e v i t i c u s - T r i a g e       ║
  ╚══════════════════════════════════════════════════════════════════╝

BANNER
}

run_spec() {
  local spec="$1"
  local -a cmdparts=() env_prefix=() args=()
  IFS='|' read -ra cmdparts <<< "$spec"
  local p
  for p in "${cmdparts[@]}"; do
    if [[ ${#args[@]} -eq 0 && "$p" == *=* ]]; then
      env_prefix+=("$p")
    else
      args+=("$p")
    fi
  done
  echo
  echo "──► ${env_prefix[*]} $WRAPPER ${args[*]}"
  echo "────────────────────────────────────────"
  env "${env_prefix[@]}" "$WRAPPER" "${args[@]}" || true
  echo
  read -r -p "Enter für Menü… " _
}

dispatch_sub() {
  local title="$1"
  shift
  local -a labels=() specs=()
  while [[ $# -ge 2 ]]; do
    labels+=("$1")
    specs+=("$2")
    shift 2
  done
  while true; do
    banner
    echo "  $title"
    echo
    local i=1
    for label in "${labels[@]}"; do
      printf "    [%d] %s\n" "$i" "$label"
      i=$((i + 1))
    done
    echo "    [0] Zurück"
    echo
    read -r -p "Auswahl: " choice
    [[ -z "$choice" || "$choice" == "0" ]] && return 0
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#labels[@]} )); then
      run_spec "${specs[$((choice - 1))]}"
    fi
  done
}

main_loop() {
  while true; do
    banner
    cat <<'MENU'

    Sec-Team zuerst: [8] → erster Eintrag (Workarounds, 1 Terminal, mit Log).
    Pfad: [1] dann [2] oder [3], dann C2 [6] / LKM [7].
    Terminal 2 brauchst du nur bei: shell, sliver console, reverse-shell listen, logs.

    [1] FPM-Lab (VTBW)     up · test · doctor · rce · shell · monitor
    [2] Zer061 mod_php     apache-up · fetch · zer061 · zer061-shell (Kit)
    [3] Jackalsyn          fetch einmalig · selftest · syms · lab
    [4] Multi-Target       apache-multi-up · scan · fingerprint · exploit-list
    [5] Reverse Shell      lukechilds-Payload (nicht der Kit-Weg aus [2])
    [6] Sliver C2+External Post-Exploit · Implant · Tunnel (+Tor-Verschleierung)
    [7] Singularity        Post-Exploit LKM (VM / Host / Container)
    [8] Workarounds+Audit  SCHRITT-FÜR-SCHRITT · Patch/WAF prüfen · Log+Auswertung
    [9] Kit Docs & Tools   docs · tools
    [d] Docker             ps · logs · down · export
    [h] Hilfe (alle CLI-Befehle)

    [0] Beenden

MENU
    read -r -p "Auswahl: " top
    case "${top:-}" in
      0|q|Q) echo "Bye."; exit 0 ;;
      h|H) run_spec help ;;
      d|D)
        dispatch_sub "Docker" \
          "ps" ps \
          "logs target" "logs|target" \
          "logs apache" "logs|apache" \
          "logs singularity" "logs|singularity" \
          "logs sliver" "logs|sliver" \
          "logs tor" "logs|tor" \
          "logs tunnel-sliver" "logs|tunnel-sliver" \
          "tunnel status" "tunnel|status" \
          "external status" "external|status" \
          "down" down \
          "export" export
        ;;
      1)
        dispatch_sub "FPM-Lab" \
          "Target starten" up \
          "PoC UAF" test \
          "Doctor" doctor \
          "Chain-A id" rce \
          "Interaktive Shell (belegt Terminal 1 → Terminal 2 öffnen)" shell \
          "Monitor" monitor
        ;;
      2)
        dispatch_sub "Zer061 Heap RCE" \
          "Apache Target" apache-up \
          "fetch Zer061" fetch-zer061 \
          "Proof" zer061 \
          "Reverse Shell (Kit, nicht [5])" zer061-shell
        ;;
      3)
        dispatch_sub "Jackalsyn (fetch einmalig)" \
          "fetch-jackalsyn (einmalig)" "fetch-jackalsyn" \
          "Status & Pfade" "jackalsyn|status" \
          "selftest" "jackalsyn|selftest" \
          "syms (FPM up + Bundle)" "jackalsyn|syms" \
          "lab" "jackalsyn|lab"
        ;;
      4)
        dispatch_sub "Scan / Multi-Exploit" \
          "2× Apache" apache-multi-up \
          "Mass-Scan" scan \
          "Fingerprint" fingerprint \
          "Exploit Liste" exploit-list
        ;;
      5)
        dispatch_sub "reverse-shell.sh (lukechilds; Kit-Shell ist [2])" \
          "Clone Repo" fetch-reverse-shell \
          "Payload → out/r" "reverse-shell|fetch" \
          "Listener nc (Terminal 1, Auslöser in Terminal 2)" "reverse-shell|listen" \
          "Zer061 + rs payload" "reverse-shell|zer061"
        ;;
      6)
        dispatch_sub "Sliver C2 + External-Attacker" \
          "──► EXTERNAL up (Tunnel, direkt)" "external|up" \
          "──► EXTERNAL up (Tunnel via TOR)" "external|up|--tor" \
          "──► EXTERNAL Status/URLs" "external|status" \
          "──► EXTERNAL down" "external|down" \
          "── Tor Exit-IP (Verschleierungs-Beweis)" "tor|ip" \
          "── Implant external (HTTPS via Tunnel)" "sliver|implant-external" \
          "── Patch-Audit extern (Tunnel+Tor)" "external|patch-audit|waf-bypass-top10" \
          "fetch Sliver (einmalig)" fetch-sliver \
          "Status & Pfade" "sliver|status" \
          "Server starten" "sliver|server-up" \
          "Operator (einmalig)" "sliver|operator" \
          "mTLS Listener 8888" "sliver|listener" \
          "HTTPS Listener 8889 (Tunnel)" "sliver|http-listener" \
          "Implant erzeugen (mtls, lab-intern)" "sliver|implant" \
          "Implant staging" "sliver|stage" \
          "Interaktive Konsole (belegt Terminal 1 → Terminal 2)" "sliver|console" \
          "Ops-Log" "sliver|ops" \
          "Tunnel einzeln: Web" "tunnel|up|web" \
          "Tunnel einzeln: Sliver HTTPS" "tunnel|up|sliver-http" \
          "Tunnel Status" "tunnel|status" \
          "Tunnel down" "tunnel|down" \
          "Server down" "sliver|down"
        ;;
      7)
        dispatch_sub "Singularity (Post-Exploit)" \
          "fetch (einmalig)" fetch-singularity \
          "Status & Pfade" "singularity|status" \
          "Laufzeit wählen" "singularity|runtime" \
          "Container: up" "singularity|container-up" \
          "Container: build" "singularity|container-build" \
          "Container: shell" "singularity|container-shell" \
          "Host: Preflight" "singularity|host-check" \
          "Host: build" "singularity|host-build" \
          "VM: Wizard" "singularity|vm-wizard" \
          "VM: start (Stub)" "singularity|vm-up" \
          "Detection (Blue Team)" "singularity|detect" \
          "Hilfe" "singularity|help"
        ;;
      8)
        dispatch_sub "Workarounds + Patch-Audit — START: Eintrag 1 (nur Terminal 1)" \
          "▶ START: Workarounds Schritt-für-Schritt (Log+Auswertung)" "workarounds|run" \
          "Workarounds nur messen (Baseline, auto)" "workarounds|auto" \
          "Workarounds Übersicht (Reihenfolge/Terminal)" "workarounds" \
          "Auswertung letzte Workaround-Sitzung" "workarounds|last" \
          "Workaround-Sitzungen (Logs)" "workarounds|logs" \
          "── Einzelprüfungen: Szenarien anzeigen ──" "patch-audit|list" \
          "Alle Checks (Lab)" "patch-audit|run|all" \
          "Vendor-Patch-Version" "patch-audit|run|vendor-patch" \
          "WAF-Signaturen" "patch-audit|run|waf-php2shell-signature" \
          "WAF Top-10 Bypass" "patch-audit|run|waf-bypass-top10" \
          "Chain-A LFI" "patch-audit|run|chain-a-lfi" \
          "Zer061 Apache" "patch-audit|run|zer061-heap" \
          "UAF (destructive)" "PATCH_AUDIT_DESTRUCTIVE=1|patch-audit|run|upload-progress-off" \
          "Audit-Logs (JSONL)" "patch-audit|logs" \
          "Hilfe" "patch-audit|help"
        ;;
      9)
        dispatch_sub "Docs & Tools" \
          "Docs list" "docs|list" \
          "Tools list" "tools|list" \
          "Tool run (interaktiv)" tools
        ;;
      *) ;;
    esac
  done
}

if [[ -t 0 ]]; then
  main_loop
else
  banner
  "$WRAPPER" help
fi
