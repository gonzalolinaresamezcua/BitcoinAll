#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Ejecuta con sudo: sudo $0"
  exit 1
fi

for unit in bitcoinall-node bitcoinall-wallet bitcoinall-explorer bitcoinall-node-app; do
  systemctl disable --now "${unit}.service" 2>/dev/null || true
  rm -f "/etc/systemd/system/${unit}.service"
done
systemctl daemon-reload
echo "Autostart BitcoinAll desactivado."
