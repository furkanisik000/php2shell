import subprocess
CS = ["p2s5445","p2s5538","p2s5640","p2s7033","p2s7133","p2s7234","p2s7333","p2s7433",
      "p2s8030","p2s8132","p2s8234","p2s8335","p2s8426","p2s8511"]
for c in CS:
    r = subprocess.run(f'docker exec {c} sh -c "test -f /usr/local/etc/php/php.ini && echo ROGUE || echo clean"',
                       shell=True, capture_output=True, text=True)
    print(c, r.stdout.strip())
