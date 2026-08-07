# BitcoinAll — instalación Ubuntu

Carpeta autocontenida con binarios compilados, nodo, wallet web y explorador.

## Compilar (primera vez)

```bash
./build.sh
```

Instala dependencias del sistema si faltan (ver `doc/build-unix.md`):

```bash
sudo apt-get install build-essential cmake pkgconf python3 python3-venv \
  libevent-dev libboost-dev libsqlite3-dev libzmq3-dev \
  qt6-base-dev qt6-tools-dev qt6-l10n-tools qt6-tools-dev-tools libgl-dev libqrencode-dev
```

## Arrancar todo

```bash
./start-all.sh
```

- **Wallet:** http://127.0.0.1:9335  
- **Explorer:** http://127.0.0.1:9336  
- **Datadir nodo:** `./data/`

## GUI Qt (opcional)

```bash
./bin/bitcoin-qt -datadir="$(pwd)/data"
```

## Parar

```bash
./stop-all.sh
```

## Estructura

| Ruta | Descripción |
|------|-------------|
| `bin/bitcoind` | Nodo |
| `bin/bitcoin-cli` | CLI RPC |
| `bin/bitcoin-qt` | GUI Qt |
| `bin/bitcoin-wallet` | Herramienta wallet |
| `data/` | Blockchain y wallets (no subir a git) |
| `wallet-app/` | Wallet web (en la raíz del repo) |
| `explorer-app/` | Explorador web (en la raíz del repo) |

Los binarios compilados (`bin/`, `.build/`) no se suben a git; se generan con `./build.sh`.
