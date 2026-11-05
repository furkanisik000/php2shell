#!/usr/bin/env bash
set -euo pipefail
TARGET_HOST="${TARGET_HOST:-target}"
TARGET_PORT="${TARGET_PORT:-80}"
exec python3 /opt/lab/scripts/chain_a_session_lfi.py \
  -t "$TARGET_HOST" -p "$TARGET_PORT" --shell
