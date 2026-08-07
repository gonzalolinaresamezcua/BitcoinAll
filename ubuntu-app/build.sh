#!/usr/bin/env bash
# Compila BitcoinAll para Ubuntu e instala en esta carpeta (bin/, lib/, share/).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/.." && pwd)"
BUILD_DIR="$ROOT/.build"
JOBS="${JOBS:-$(nproc)}"

echo "==> BitcoinAll Ubuntu — compilación"
echo "    Repo:   $REPO"
echo "    Instala en: $ROOT"
echo "    GUI Qt: ON"

cmake -S "$REPO" -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INSTALL_PREFIX="$ROOT" \
  -DBUILD_GUI=ON \
  -DWITH_ZMQ=ON \
  -DENABLE_WALLET=ON

cmake --build "$BUILD_DIR" -j"$JOBS"
install_bins() {
  mkdir -p "$ROOT/bin"
  shopt -s nullglob
  for bin in "$BUILD_DIR"/bin/bitcoin-* "$BUILD_DIR"/bin/bitcoind; do
    [[ -f "$bin" ]] && cp -a "$bin" "$ROOT/bin/"
  done
}
if ! cmake --install "$BUILD_DIR"; then
  echo "AVISO: install parcial; copiando binarios desde .build/bin/…"
  install_bins
fi
# Asegurar GUI y nodo aunque install omita algún target
install_bins

[[ -f "$ROOT/bitcoin.conf.example" ]] || cp "$REPO/bitcoin.conf.example" "$ROOT/bitcoin.conf.example"

mkdir -p "$ROOT/data"
if [[ -d "$REPO/data" && ! -e "$ROOT/data/blockchain" && ! -L "$ROOT/data" ]]; then
  echo "Enlazando data existente del repo → $REPO/data"
  rm -rf "$ROOT/data"
  ln -sf "$REPO/data" "$ROOT/data"
fi
if [[ ! -f "$ROOT/data/bitcoin.conf" && ! -L "$ROOT/data" ]]; then
  cp "$ROOT/bitcoin.conf.example" "$ROOT/data/bitcoin.conf"
  echo "Creado $ROOT/data/bitcoin.conf"
fi

echo ""
echo "==> Listo. Binarios:"
ls -la "$ROOT/bin/" 2>/dev/null || ls -la "$ROOT/build/bin/" 2>/dev/null || true
echo ""
echo "Arrancar todo:  $ROOT/start-all.sh"
echo "Parar todo:     $ROOT/stop-all.sh"
