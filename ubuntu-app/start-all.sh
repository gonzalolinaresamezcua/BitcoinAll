#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
export PATH="$ROOT/bin:$PATH"
export BITCOINALL_DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"
export BITCOINALL_WALLET="${BITCOINALL_WALLET:-primera}"
export BITCOINALL_RPC_HOST="${BITCOINALL_RPC_HOST:-127.0.0.1}"
export BITCOINALL_RPC_PORT="${BITCOINALL_RPC_PORT:-8332}"

BITCOIND="$ROOT/bin/bitcoind"
CLI="$ROOT/bin/bitcoin-cli"

mkdir -p "$BITCOINALL_DATADIR"
[[ -f "$BITCOINALL_DATADIR/bitcoin.conf" ]] || cp "$REPO/bitcoin.conf.example" "$BITCOINALL_DATADIR/bitcoin.conf"

if [[ ! -x "$BITCOIND" ]]; then
  echo "No está compilado. Ejecuta primero: $ROOT/build.sh"
  exit 1
fi

start_node() {
  if pgrep -f "bitcoind.*-datadir=$BITCOINALL_DATADIR" >/dev/null 2>&1 || \
     "$CLI" -datadir="$BITCOINALL_DATADIR" getblockchaininfo >/dev/null 2>&1; then
    echo "Nodo ya activo (datadir=$BITCOINALL_DATADIR)"
    return 0
  fi
  echo "Iniciando bitcoind…"
  "$BITCOIND" -datadir="$BITCOINALL_DATADIR" -server -txindex=1 -wallet=primera -daemon
  for _ in $(seq 1 30); do
    if "$CLI" -datadir="$BITCOINALL_DATADIR" getblockchaininfo >/dev/null 2>&1; then
      echo "Nodo listo."
      return 0
    fi
    sleep 1
  done
  echo "ERROR: el nodo no respondió a RPC."
  exit 1
}

load_wallet() {
  if "$CLI" -datadir="$BITCOINALL_DATADIR" -rpcwallet=primera getwalletinfo >/dev/null 2>&1; then
    return 0
  fi
  "$CLI" -datadir="$BITCOINALL_DATADIR" loadwallet primera 2>/dev/null || \
  "$CLI" -datadir="$BITCOINALL_DATADIR" createwallet primera 2>/dev/null || true
}

start_node
load_wallet

BITCOINALL_DATADIR="$BITCOINALL_DATADIR" "$REPO/wallet-app/run.sh" start
BITCOINALL_DATADIR="$BITCOINALL_DATADIR" "$REPO/explorer-app/run.sh" start

echo ""
echo "══════════════════════════════════════════"
echo " BitcoinAll Ubuntu — servicios activos"
echo "══════════════════════════════════════════"
echo " Nodo RPC:  $BITCOINALL_DATADIR"
echo " Wallet:    http://127.0.0.1:9335"
echo " Explorer:  http://127.0.0.1:9336"
if [[ -x "$ROOT/bin/bitcoin-qt" ]]; then
  echo " GUI Qt:    $ROOT/bin/bitcoin-qt -datadir=$BITCOINALL_DATADIR"
fi
echo " Parar:     $ROOT/stop-all.sh"
echo "══════════════════════════════════════════"
