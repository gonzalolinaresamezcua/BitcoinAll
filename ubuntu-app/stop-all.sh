#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
export BITCOINALL_DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"

"$REPO/explorer-app/run.sh" stop 2>/dev/null || true
"$REPO/wallet-app/run.sh" stop 2>/dev/null || true

if pgrep -x bitcoind >/dev/null 2>&1; then
  "$ROOT/bin/bitcoin-cli" -datadir="$BITCOINALL_DATADIR" stop 2>/dev/null || pkill -x bitcoind || true
  echo "Nodo detenido."
else
  echo "Nodo no estaba corriendo."
fi
