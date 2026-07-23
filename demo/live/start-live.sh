#!/usr/bin/env bash
# Start BitcoinAll LIVE (main) two-node network with wallets.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BTCA_BITCOIND:-$ROOT/build/bin/bitcoind}"
CLI="${BTCA_BITCOIN_CLI:-$ROOT/build/bin/bitcoin-cli}"
N1="$ROOT/demo/live/node1"
N2="$ROOT/demo/live/node2"

mkdir -p "$N1" "$N2"

start_one() {
  local datadir="$1"; shift
  if "$CLI" -datadir="$datadir" getblockchaininfo >/dev/null 2>&1; then
    echo "already running: $datadir"
    return 0
  fi
  echo "starting $datadir $*"
  "$BIN" -datadir="$datadir" "$@" >"$datadir/stdout.log" 2>&1 &
  echo $! >"$datadir/bitcoind.pid"
}

start_one "$N1" -btcaallowgenerate=1
sleep 2
start_one "$N2"
sleep 2

for i in $(seq 1 40); do
  if "$CLI" -datadir="$N1" getblockchaininfo >/dev/null 2>&1 && \
     "$CLI" -datadir="$N2" getblockchaininfo >/dev/null 2>&1; then
    echo "LIVE nodes RPC ready"
    "$CLI" -datadir="$N1" getblockchaininfo | head -c 400; echo
    exit 0
  fi
  sleep 1
done
echo "timeout waiting for LIVE nodes" >&2
exit 1
