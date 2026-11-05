#!/usr/bin/env bash
# Apache mod_php reproduction rate: fresh httpd process per iteration.
set -u
cd /mnt/c/Users/user/Downloads/php
run=/home/phplab/php-lab/evidence/apache-lab
iterations=${1:-3}
for i in $(seq 1 "$iterations"); do
  bash linux/apache-lab.sh stop 18088 >/dev/null 2>&1
  sleep 0.3
  mkdir -p "$run/asan-archive"
  mv "$run"/asan.* "$run/asan-archive/" 2>/dev/null || true
  if ! bash linux/apache-lab.sh start 18088 >/dev/null; then
    echo "iter $i: start failed"
    continue
  fi
  POC_SESSION_DIR="$run/sessions" POC_ASAN_DIR="$run" POC_ERROR_LOG="$run/php-error.log" \
    POC_PROCESS_PID="$(cat "$run/httpd.pid" 2>/dev/null || true)" \
    python3 linux/poc-bgserialize.py --external --port 18088 --iterations 1 \
    > "/tmp/poc-apache-$i.json" 2>/dev/null || true
  python3 -c "import json; d=json.load(open('/tmp/poc-apache-$i.json')); print('iter', $i, 'reproduced', d['reproduced'], '/', d['iterations'], 'rate', d['reproduction_rate'])"
done
bash linux/apache-lab.sh stop 18088 >/dev/null 2>&1
echo "asan archive count: $(ls "$run"/asan-archive 2>/dev/null | wc -l)"
