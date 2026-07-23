#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export BTCA_NODE1_RPC="${BTCA_NODE1_RPC:-http://127.0.0.1:18443}"
export BTCA_NODE2_RPC="${BTCA_NODE2_RPC:-http://127.0.0.1:18453}"
export BTCA_RPC_USER="${BTCA_RPC_USER:-btca}"
export BTCA_RPC_PASSWORD="${BTCA_RPC_PASSWORD:-btca-demo}"
export BTCA_EXPLORER_HOST="${BTCA_EXPLORER_HOST:-0.0.0.0}"
export BTCA_EXPLORER_PORT="${BTCA_EXPLORER_PORT:-8080}"
exec python3 server.py
