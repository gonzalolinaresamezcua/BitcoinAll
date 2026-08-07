#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/wallet-app"
VENV="$APP_DIR/.venv"
LOG="$APP_DIR/wallet.log"

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

ensure_venv() {
  if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV"
  fi
  if ! "$VENV/bin/python" -c "import flask" 2>/dev/null; then
    "$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt"
  fi
}

start_background() {
  ensure_venv
  stop_wallet
  nohup "$VENV/bin/python" "$APP_DIR/server.py" >>"$LOG" 2>&1 &
  for _ in $(seq 1 15); do
    if is_running; then
      echo "Wallet lista → ${URL}"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: wallet no respondió. Log: $LOG"
  tail -10 "$LOG" 2>/dev/null || true
  exit 1
}

start_foreground() {
  ensure_venv
  stop_wallet
  echo "Abre en el navegador: ${URL}"
  exec "$VENV/bin/python" "$APP_DIR/server.py"
}

case "${1:-start}" in
  stop)
    stop_wallet
    echo "Wallet detenida (puerto ${BITCOINALL_WALLET_PORT})."
    ;;
  restart)
    stop_wallet
    start_background
    ;;
  status)
    if is_running; then
      echo "Wallet activa → ${URL}"
    else
      echo "Wallet no responde en ${URL}"
      exit 1
    fi
    ;;
  fg|foreground)
    start_foreground
    ;;
  start)
    if is_running; then
      echo "Wallet ya está corriendo → ${URL}"
      exit 0
    fi
    start_background
    ;;
  *)
    echo "Uso: $0 [start|stop|restart|status|fg]"
    exit 1
    ;;
esac
