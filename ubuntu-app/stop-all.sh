#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
export BITCOINALL_DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"

"$REPO/explorer-app/run.sh" stop 2>/dev/null || true
"$REPO/node-app/run.sh" stop 2>/dev/null || true
"$REPO/wallet-app/run.sh" stop 2>/dev/null || true

if pgrep -x bitcoin-qt >/dev/null 2>&1; then
  pkill -x bitcoin-qt || true
  sleep 2
  echo "bitcoin-qt detenido."
fi

if pgrep -x bitcoind >/dev/null 2>&1; then
  "$ROOT/bin/bitcoin-cli" -datadir="$BITCOINALL_DATADIR" stop 2>/dev/null || pkill -x bitcoind || true
  echo "Nodo detenido."
else
  echo "bitcoind no estaba corriendo."
fi
