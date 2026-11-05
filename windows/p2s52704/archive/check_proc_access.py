import subprocess

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

containers = ["p2s8030", "p2s7433", "p2s7333", "p2s7234", "p2s7133", "p2s7033",
              "p2s5640", "p2s5538", "p2s5445", "p2s8132"]

for c in containers:
    # find worker (2nd apache2 pid)
    r = sh(f'docker exec {c} sh -c "ps -eo pid,comm | grep apache2 | grep -v grep"')
    pids = [l.split()[0] for l in r.stdout.strip().splitlines() if l.strip()]
    worker = pids[1] if len(pids) >= 2 else (pids[0] if pids else "0")
    # try to read worker maps
    r2 = sh(f'docker exec {c} sh -c "head -1 /proc/{worker}/maps 2>&1 | head -c 80"')
    out = r2.stdout.strip().replace("\n", " ")
    # find libphp base
    r3 = sh(f'docker exec {c} sh -c "grep libphp /proc/{worker}/maps 2>/dev/null | head -1"')
    libphp = r3.stdout.strip().split("-")[0] if r3.stdout.strip() else "NO_LIBPHP"
    print(f"{c}: worker={worker} libphp={libphp} maps={out[:70]}", flush=True)
