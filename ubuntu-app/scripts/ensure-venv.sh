#!/usr/bin/env bash
# Crea venv e instala Flask si hace falta (usado por systemd).
set -euo pipefail

APP="${1:?wallet, explorer o node}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"

case "$APP" in
  wallet)
    VENV="$REPO/wallet-app/.venv"
    REQ="$REPO/wallet-app/requirements.txt"
    ;;
  explorer)
    VENV="$REPO/explorer-app/.venv"
    REQ="$REPO/explorer-app/requirements.txt"
    ;;
  node)
    VENV="$REPO/node-app/.venv"
    REQ="$REPO/node-app/requirements.txt"
    ;;
  *)
    echo "App desconocida: $APP" >&2
    exit 1
    ;;
esac

if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -q -r "$REQ"
