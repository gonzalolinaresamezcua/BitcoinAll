#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export BTCA_EXPLORER_PORT="${BTCA_EXPLORER_PORT:-8081}"
# Force LIVE creds via demo/explorer/run.sh preference order
exec "$ROOT/demo/explorer/run.sh"
