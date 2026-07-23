#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Load saved demo credentials when present
CREDS="$(cd .. && pwd)/demo/credentials.env"
if [[ -f "$CREDS" ]]; then
  # shellcheck disable=SC1090
  set -a
  source "$CREDS"
  set +a
fi

export BTCA_NODE1_RPC="${BTCA_NODE1_RPC:-http://127.0.0.1:18443}"
export BTCA_NODE2_RPC="${BTCA_NODE2_RPC:-http://127.0.0.1:18453}"
export BTCA_RPC_USER="${BTCA_RPC_USER:-btca}"
export BTCA_RPC_PASSWORD="${BTCA_RPC_PASSWORD:-btca-demo}"
export BTCA_NODE1_ADDR="${BTCA_NODE1_ADDR:-rbtca1qw508d6qejxtdg4y5r3zarvary0c5xw7k5c4835}"
export BTCA_NODE2_ADDR="${BTCA_NODE2_ADDR:-rbtca1qq6hag67dl53wl99vzg42z8eyzfz2xlkv7xypgq}"
export BTCA_EXPLORER_HOST="${BTCA_EXPLORER_HOST:-0.0.0.0}"
export BTCA_EXPLORER_PORT="${BTCA_EXPLORER_PORT:-8080}"
exec python3 server.py
