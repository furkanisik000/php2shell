# Singularity — disposable VM

LKM-Tests gehören in eine **Wegwerf-VM** mit Snapshot, nicht auf dem Host mit produktiven Daten.

## Empfohlen

1. Ubuntu 24.04+ oder Debian mit **Kernel 6.x**
2. Snapshot **vor** `setup.sh`
3. Nur Netz/Lab-Zugang, den du kontrollierst

## QEMU (Host)

```bash
# Beispiel — Image/ISO selbst bereitstellen
qemu-system-x86_64 -m 4096 -smp 2 -enable-kvm \
  -cdrom ~/Downloads/ubuntu-24.04-live-amd64.iso
```

## Nach dem Boot in der VM

```bash
sudo apt update && sudo apt install -y linux-headers-$(uname -r) build-essential git
git clone https://github.com/MatheuZSecurity/Singularity
cd Singularity
# Nur mit ausdrücklicher Erlaubnis und Verständnis: Reboot nötig zum Entfernen
```

## Lab-Netz (optional)

Bridged NIC zur Docker-Bridge `php2shell-lab-vtbw_lab_isolated` ist host-spezifisch — siehe Docker-Doku. PHP-Exploit-Kette bleibt in Containern; Singularity läuft **nicht** in `target` / `target-apache`.
