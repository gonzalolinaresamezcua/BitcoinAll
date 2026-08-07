#!/usr/bin/env bash
# Arranca la GUI Qt de BitcoinAll (incluye nodo + wallet gráfica).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"
REALDATA="$(cd "$DATADIR" 2>/dev/null && pwd -P || echo "$DATADIR")"
QT="$ROOT/bin/bitcoin-qt"
CLI="$ROOT/bin/bitcoin-cli"

mkdir -p "$DATADIR"
[[ -f "$DATADIR/bitcoin.conf" ]] || cp "$REPO/bitcoin.conf.example" "$DATADIR/bitcoin.conf"

if [[ ! -x "$QT" ]]; then
  echo "No encontrado: $QT"
  echo "Compila primero: $ROOT/build.sh"
  exit 1
fi

if [[ -z "${DISPLAY:-}" ]]; then
  echo "ERROR: no hay DISPLAY (entorno gráfico)."
  exit 1
fi

stop_bitcoin_processes() {
  # Parar wallet/explorer web (opcional; la GUI no los necesita)
  "$REPO/explorer-app/run.sh" stop 2>/dev/null || true
  "$REPO/wallet-app/run.sh" stop 2>/dev/null || true

  if pgrep -x bitcoind >/dev/null 2>&1; then
    echo "Deteniendo bitcoind…"
    "$CLI" -datadir="$DATADIR" stop 2>/dev/null || pkill -x bitcoind || true
  fi

  if pgrep -x bitcoin-qt >/dev/null 2>&1; then
    echo "Deteniendo bitcoin-qt anterior…"
    pkill -x bitcoin-qt || true
  fi

  for _ in $(seq 1 25); do
    pgrep -x bitcoind >/dev/null 2>&1 && sleep 1 && continue
    pgrep -x bitcoin-qt >/dev/null 2>&1 && sleep 1 && continue
    [[ -f "$REALDATA/.lock" ]] || break
    sleep 1
  done

  if [[ -f "$REALDATA/.lock" ]] && ! pgrep -x bitcoind >/dev/null && ! pgrep -x bitcoin-qt >/dev/null; then
    echo "Eliminando .lock huérfano en $REALDATA"
    rm -f "$REALDATA/.lock"
  fi
}

if pgrep -x bitcoin-qt >/dev/null 2>&1; then
  echo "bitcoin-qt ya está corriendo."
  exit 0
fi

stop_bitcoin_processes

echo "BitcoinAll GUI → datadir=$DATADIR"
exec "$QT" -datadir="$DATADIR"
