#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/explorer-app"
VENV="$APP_DIR/.venv"
LOG="$APP_DIR/explorer.log"
PIDFILE="$APP_DIR/explorer.pid"

export BITCOINALL_DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"
export BITCOINALL_RPC_HOST="${BITCOINALL_RPC_HOST:-127.0.0.1}"
export BITCOINALL_RPC_PORT="${BITCOINALL_RPC_PORT:-8332}"
export BITCOINALL_EXPLORER_BIND="${BITCOINALL_EXPLORER_BIND:-127.0.0.1}"
export BITCOINALL_EXPLORER_PORT="${BITCOINALL_EXPLORER_PORT:-9336}"

URL="http://${BITCOINALL_EXPLORER_BIND}:${BITCOINALL_EXPLORER_PORT}"

stop_explorer() {
  if [[ -f "$PIDFILE" ]]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
  fi
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

ensure_venv() {
  if [[ ! -d "$VENV" ]]; then
    echo "Creando entorno Python (primera vez, ~15 s)…"
    python3 -m venv "$VENV"
  fi
  if ! "$VENV/bin/python" -c "import flask" 2>/dev/null; then
    echo "Instalando Flask…"
    "$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt"
  fi
}

check_node() {
  if ! pgrep -x bitcoind >/dev/null 2>&1; then
    echo "AVISO: bitcoind no está corriendo. Arranca el nodo primero:"
    echo "  $ROOT/build/bin/bitcoind -datadir=$ROOT/data -server -txindex=1 -wallet=primera -daemon"
  fi
}

start_background() {
  ensure_venv
  check_node
  stop_explorer
  echo "Iniciando explorer en segundo plano…"
  nohup "$VENV/bin/python" "$APP_DIR/server.py" >>"$LOG" 2>&1 &
  echo $! >"$PIDFILE"
  for _ in $(seq 1 30); do
    if is_running; then
      echo "Explorer listo → ${URL}"
      echo "Log: ${LOG}"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: el explorer no respondió. Revisa el log:"
  tail -20 "$LOG" 2>/dev/null || true
  exit 1
}

start_foreground() {
  ensure_venv
  check_node
  stop_explorer
  echo "Explorer en primer plano → ${URL}"
  echo "(Ctrl+C para parar; cierra la terminal y se detendrá)"
  exec "$VENV/bin/python" "$APP_DIR/server.py"
}

case "${1:-start}" in
  stop)
    stop_explorer
    echo "Explorer detenido (puerto ${BITCOINALL_EXPLORER_PORT})."
    ;;
  restart)
    stop_explorer
    start_background
    ;;
  status)
    if is_running; then
      echo "Explorer activo → ${URL}"
    else
      echo "Explorer no responde en ${URL}"
      echo "Arranca con: $0 start"
      exit 1
    fi
    ;;
  start|fg|foreground)
    if is_running && [[ "${1:-start}" == "start" ]]; then
      echo "Explorer ya está corriendo → ${URL}"
      exit 0
    fi
    if [[ "${1:-start}" == "fg" || "${1:-start}" == "foreground" ]]; then
      start_foreground
    else
      start_background
    fi
    ;;
  log)
    tail -f "$LOG"
    ;;
  *)
    echo "Uso: $0 [start|stop|restart|status|fg|log]"
    echo "  start   — arranca en segundo plano (recomendado)"
    echo "  fg      — arranca en esta terminal"
    echo "  status  — comprueba si responde"
    echo "  log     — ver log en vivo"
    exit 1
    ;;
esac
