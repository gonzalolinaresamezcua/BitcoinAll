#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
set -a
# shellcheck disable=SC1091
source "$ROOT/demo/live/credentials.env"
set +a
export BTCA_NODE1_RPC="$BTCA_LIVE_NODE1_RPC"
export BTCA_NODE2_RPC="$BTCA_LIVE_NODE2_RPC"
export BTCA_RPC_USER="$BTCA_LIVE_RPC_USER"
export BTCA_RPC_PASSWORD="$BTCA_LIVE_RPC_PASSWORD"
export BTCA_NODE1_ADDR="$BTCA_LIVE_NODE1_ADDR"
export BTCA_NODE2_ADDR="$BTCA_LIVE_NODE2_ADDR"
export BTCA_EXPLORER_PORT="${BTCA_EXPLORER_PORT:-8081}"
cd "$ROOT/explorer"
exec python3 server.py
