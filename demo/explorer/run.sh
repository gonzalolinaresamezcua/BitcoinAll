#!/usr/bin/env bash
# BitcoinAll block explorer — open http://127.0.0.1:8080 in Chrome after starting.
set -euo pipefail
cd "$(dirname "$0")"
DEMO="$(cd .. && pwd)"

# Prefer LIVE credentials if present, else regtest demo credentials
if [[ -f "$DEMO/live/credentials.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source "$DEMO/live/credentials.env"; set +a
  export BTCA_NODE1_RPC="${BTCA_LIVE_NODE1_RPC:-http://127.0.0.1:8332}"
  export BTCA_NODE2_RPC="${BTCA_LIVE_NODE2_RPC:-http://127.0.0.1:8333}"
  export BTCA_RPC_USER="${BTCA_LIVE_RPC_USER:-btca-live}"
  export BTCA_RPC_PASSWORD="${BTCA_LIVE_RPC_PASSWORD:-BtcaLive-Demo-9333!}"
  export BTCA_NODE1_ADDR="${BTCA_LIVE_NODE1_ADDR:-btca1qw508d6qejxtdg4y5r3zarvary0c5xw7kj7tmhx}"
  export BTCA_NODE2_ADDR="${BTCA_LIVE_NODE2_ADDR:-btca1qq6hag67dl53wl99vzg42z8eyzfz2xlkvcq6awj}"
  export BTCA_NODE1_WALLET="${BTCA_LIVE_NODE1_WALLET:-wallet_node1}"
  export BTCA_NODE2_WALLET="${BTCA_LIVE_NODE2_WALLET:-wallet_node2}"
elif [[ -f "$DEMO/credentials.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source "$DEMO/credentials.env"; set +a
fi

# Fallback LIVE defaults if no credentials file was sourced
export BTCA_NODE1_RPC="${BTCA_NODE1_RPC:-http://127.0.0.1:8332}"
export BTCA_NODE2_RPC="${BTCA_NODE2_RPC:-http://127.0.0.1:8333}"
export BTCA_RPC_USER="${BTCA_RPC_USER:-btca-live}"
export BTCA_RPC_PASSWORD="${BTCA_RPC_PASSWORD:-BtcaLive-Demo-9333!}"
export BTCA_NODE1_ADDR="${BTCA_NODE1_ADDR:-btca1qw508d6qejxtdg4y5r3zarvary0c5xw7kj7tmhx}"
export BTCA_NODE2_ADDR="${BTCA_NODE2_ADDR:-btca1qq6hag67dl53wl99vzg42z8eyzfz2xlkvcq6awj}"
export BTCA_NODE1_WALLET="${BTCA_NODE1_WALLET:-wallet_node1}"
export BTCA_NODE2_WALLET="${BTCA_NODE2_WALLET:-wallet_node2}"
export BTCA_EXPLORER_HOST="${BTCA_EXPLORER_HOST:-0.0.0.0}"
export BTCA_EXPLORER_PORT="${BTCA_EXPLORER_PORT:-8080}"

echo "BitcoinAll explorer → http://127.0.0.1:${BTCA_EXPLORER_PORT}"
echo "  node1 RPC: ${BTCA_NODE1_RPC}"
echo "  node2 RPC: ${BTCA_NODE2_RPC}"
echo "Open that URL in Chrome (do not open index.html as a file://)."
exec python3 server.py
