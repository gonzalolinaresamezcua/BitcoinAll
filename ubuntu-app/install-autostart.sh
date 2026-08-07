#!/usr/bin/env bash
# Instala servicios systemd para arrancar BitcoinAll al inicio de Ubuntu.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
REAL_USER="${SUDO_USER:-$USER}"
DATADIR="${BITCOINALL_DATADIR:-$ROOT/data}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Ejecuta con sudo: sudo $0"
  exit 1
fi

if [[ ! -x "$ROOT/bin/bitcoind" ]]; then
  echo "ERROR: compila primero (como $REAL_USER): $ROOT/build.sh"
  exit 1
fi

REAL_DATADIR="$DATADIR"
if [[ -L "$REAL_DATADIR" ]]; then
  REAL_DATADIR="$(readlink -f "$REAL_DATADIR")"
fi

mkdir -p "$REAL_DATADIR"
if [[ ! -f "$REAL_DATADIR/bitcoin.conf" ]]; then
  cp "$REPO/bitcoin.conf.example" "$REAL_DATADIR/bitcoin.conf"
fi
chown -R "$REAL_USER:$REAL_USER" "$REAL_DATADIR" 2>/dev/null || true

chmod +x "$ROOT/scripts/ensure-venv.sh"
sudo -u "$REAL_USER" "$ROOT/scripts/ensure-venv.sh" wallet
sudo -u "$REAL_USER" "$ROOT/scripts/ensure-venv.sh" explorer
sudo -u "$REAL_USER" "$ROOT/scripts/ensure-venv.sh" node

render() {
  local src="$1" dst="$2"
  sed -e "s|__BITCOINALL_HOME__|$ROOT|g" \
      -e "s|__BITCOINALL_REPO__|$REPO|g" \
      -e "s|__BITCOINALL_DATADIR__|$REAL_DATADIR|g" \
      -e "s|__BITCOINALL_USER__|$REAL_USER|g" \
      "$src" > "$dst"
}

render "$ROOT/systemd/bitcoinall-node.service.in" /etc/systemd/system/bitcoinall-node.service
render "$ROOT/systemd/bitcoinall-wallet.service.in" /etc/systemd/system/bitcoinall-wallet.service
render "$ROOT/systemd/bitcoinall-explorer.service.in" /etc/systemd/system/bitcoinall-explorer.service
render "$ROOT/systemd/bitcoinall-node-app.service.in" /etc/systemd/system/bitcoinall-node-app.service
chmod 644 /etc/systemd/system/bitcoinall-*.service

# Detener procesos manuales
sudo -u "$REAL_USER" pkill -x bitcoin-qt 2>/dev/null || true
sudo -u "$REAL_USER" pkill -x bitcoind 2>/dev/null || true
fuser -k 9335/tcp 9336/tcp 9337/tcp 2>/dev/null || true
sleep 2

systemctl daemon-reload
systemctl enable bitcoinall-node.service bitcoinall-wallet.service bitcoinall-explorer.service bitcoinall-node-app.service
systemctl restart bitcoinall-node.service
sleep 4
systemctl restart bitcoinall-wallet.service bitcoinall-explorer.service bitcoinall-node-app.service

echo ""
echo "══════════════════════════════════════════"
echo " BitcoinAll autostart activado (arranca con Ubuntu)"
echo "══════════════════════════════════════════"
echo " Usuario:  $REAL_USER"
echo " Datadir:  $REAL_DATADIR"
echo " Nodo:     $ROOT/bin/bitcoind"
echo ""
echo " Estado:"
systemctl is-active bitcoinall-node.service && echo "  ✓ Nodo activo" || echo "  ✗ Nodo — journalctl -u bitcoinall-node -n 30"
systemctl is-active bitcoinall-wallet.service && echo "  ✓ Wallet  http://127.0.0.1:9335" || true
systemctl is-active bitcoinall-explorer.service && echo "  ✓ Explorer http://127.0.0.1:9336" || true
systemctl is-active bitcoinall-node-app.service && echo "  ✓ Nodos P2P http://127.0.0.1:9337" || true
echo ""
echo " Logs: sudo journalctl -u bitcoinall-node -f"
echo " Quitar: sudo $ROOT/uninstall-autostart.sh"
