#!/usr/bin/env bash
# Start LIVE nodes (if needed) + explorer. Run this on the machine that has bitcoind.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LIVE="$ROOT/demo/live"
EXP="$(cd "$(dirname "$0")" && pwd)"

bash "$LIVE/start-live.sh"
# ensure wallets present/loaded (ignore errors if already loaded)
CLI="${BTCA_BITCOIN_CLI:-$ROOT/build/bin/bitcoin-cli}"
"$CLI" -datadir="$LIVE/node1" loadwallet wallet_node1 >/dev/null 2>&1 || true
"$CLI" -datadir="$LIVE/node2" loadwallet wallet_node2 >/dev/null 2>&1 || true
"$CLI" -datadir="$LIVE/node2" addnode 127.0.0.1:9333 onetry >/dev/null 2>&1 || true

echo
echo "Nodos:"
echo "  node1 height=$("$CLI" -datadir="$LIVE/node1" getblockcount) peers=$("$CLI" -datadir="$LIVE/node1" getconnectioncount)"
echo "  node2 height=$("$CLI" -datadir="$LIVE/node2" getblockcount) peers=$("$CLI" -datadir="$LIVE/node2" getconnectioncount)"
echo
echo "Arrancando explorador → http://127.0.0.1:8080/"
exec "$EXP/run.sh"
