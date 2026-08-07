#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/explorer-app"
VENV="$APP_DIR/.venv"

export BITCOINALL_DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"
export BITCOINALL_RPC_HOST="${BITCOINALL_RPC_HOST:-127.0.0.1}"
export BITCOINALL_RPC_PORT="${BITCOINALL_RPC_PORT:-8332}"
export BITCOINALL_EXPLORER_BIND="${BITCOINALL_EXPLORER_BIND:-127.0.0.1}"
export BITCOINALL_EXPLORER_PORT="${BITCOINALL_EXPLORER_PORT:-9336}"

URL="http://${BITCOINALL_EXPLORER_BIND}:${BITCOINALL_EXPLORER_PORT}"

stop_explorer() {
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${BITCOINALL_EXPLORER_PORT}/tcp" 2>/dev/null || true
  else
    pkill -f "${APP_DIR}/server.py" 2>/dev/null || true
  fi
  sleep 1
}

is_running() {
  curl -sf "${URL}/api/chain" >/dev/null 2>&1
}

case "${1:-start}" in
  stop)
    stop_explorer
    echo "Explorer detenido (puerto ${BITCOINALL_EXPLORER_PORT})."
    exit 0
    ;;
  restart)
    stop_explorer
    ;;
  status)
    if is_running; then
      echo "Explorer activo → ${URL}"
      exit 0
    fi
    echo "Explorer no responde en ${URL}"
    exit 1
    ;;
  start)
    if is_running; then
      echo "Explorer ya está corriendo → ${URL}"
      exit 0
    fi
    stop_explorer
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
