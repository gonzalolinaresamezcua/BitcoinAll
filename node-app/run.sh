#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/node-app"
VENV="$APP_DIR/.venv"
LOG="$APP_DIR/node.log"
PIDFILE="$APP_DIR/node.pid"

export BITCOINALL_DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"
export BITCOINALL_RPC_HOST="${BITCOINALL_RPC_HOST:-127.0.0.1}"
export BITCOINALL_RPC_PORT="${BITCOINALL_RPC_PORT:-8332}"
export BITCOINALL_NODE_BIND="${BITCOINALL_NODE_BIND:-127.0.0.1}"
export BITCOINALL_NODE_PORT="${BITCOINALL_NODE_PORT:-9337}"

URL="http://${BITCOINALL_NODE_BIND}:${BITCOINALL_NODE_PORT}"

stop_node_app() {
  if [[ -f "$PIDFILE" ]]; then
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
  fi
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${BITCOINALL_NODE_PORT}/tcp" 2>/dev/null || true
  else
    pkill -f "${APP_DIR}/server.py" 2>/dev/null || true
  fi
  sleep 1
}

is_running() {
  curl -sf "${URL}/api/overview" >/dev/null 2>&1
}

ensure_venv() {
  if [[ ! -d "$VENV" ]]; then
    echo "Creando entorno Python (primera vez)…"
    python3 -m venv "$VENV"
  fi
  if ! "$VENV/bin/python" -c "import flask" 2>/dev/null; then
    echo "Instalando Flask…"
    "$VENV/bin/pip" install -q -r "$APP_DIR/requirements.txt"
  fi
}

check_node() {
  if ! pgrep -x bitcoind >/dev/null 2>&1; then
    echo "AVISO: bitcoind no está corriendo. Arranca el nodo primero."
  fi
}

start_background() {
  ensure_venv
  check_node
  stop_node_app
  echo "Iniciando node monitor en segundo plano…"
  nohup "$VENV/bin/python" "$APP_DIR/server.py" >>"$LOG" 2>&1 &
  echo $! >"$PIDFILE"
  for _ in $(seq 1 30); do
    if is_running; then
      echo "Node monitor listo → ${URL}"
      echo "Log: ${LOG}"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: node monitor no respondió. Revisa el log:"
  tail -20 "$LOG" 2>/dev/null || true
  exit 1
}

start_foreground() {
  ensure_venv
  check_node
  stop_node_app
  echo "Node monitor en primer plano → ${URL}"
  exec "$VENV/bin/python" "$APP_DIR/server.py"
}

case "${1:-start}" in
  stop)
    stop_node_app
    echo "Node monitor detenido (puerto ${BITCOINALL_NODE_PORT})."
    ;;
  restart)
    stop_node_app
    start_background
    ;;
  status)
    if is_running; then
      echo "Node monitor activo → ${URL}"
    else
      echo "Node monitor no responde en ${URL}"
      echo "Arranca con: $0 start"
      exit 1
    fi
    ;;
  start|fg|foreground)
    if is_running && [[ "${1:-start}" == "start" ]]; then
      echo "Node monitor ya está corriendo → ${URL}"
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
    exit 1
    ;;
esac
