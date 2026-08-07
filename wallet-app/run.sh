#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/wallet-app"
VENV="$APP_DIR/.venv"

export BITCOINALL_DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"
export BITCOINALL_WALLET="${BITCOINALL_WALLET:-primera}"
export BITCOINALL_RPC_HOST="${BITCOINALL_RPC_HOST:-127.0.0.1}"
export BITCOINALL_RPC_PORT="${BITCOINALL_RPC_PORT:-8332}"
export BITCOINALL_WALLET_BIND="${BITCOINALL_WALLET_BIND:-127.0.0.1}"
export BITCOINALL_WALLET_PORT="${BITCOINALL_WALLET_PORT:-9335}"

URL="http://${BITCOINALL_WALLET_BIND}:${BITCOINALL_WALLET_PORT}"

stop_wallet() {
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${BITCOINALL_WALLET_PORT}/tcp" 2>/dev/null || true
  else
    pkill -f "${APP_DIR}/server.py" 2>/dev/null || true
  fi
  sleep 1
}

is_running() {
  curl -sf "${URL}/api/status" >/dev/null 2>&1
}

case "${1:-start}" in
  stop)
    stop_wallet
    echo "Wallet detenida (puerto ${BITCOINALL_WALLET_PORT})."
    exit 0
    ;;
  restart)
    stop_wallet
    ;;
  status)
    if is_running; then
      echo "Wallet activa → ${URL}"
      exit 0
    fi
    echo "Wallet no responde en ${URL}"
    exit 1
    ;;
  start)
    if is_running; then
      echo "Wallet ya está corriendo → ${URL}"
      exit 0
    fi
    stop_wallet
    ;;
  *)
    echo "Uso: $0 [start|stop|restart|status]"
    exit 1
    ;;
esac

if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt"
fi

echo "Abre en el navegador: ${URL}"
exec "$VENV/bin/python" "$APP_DIR/server.py"
