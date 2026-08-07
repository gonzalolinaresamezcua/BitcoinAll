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
- **Nodos P2P:** http://127.0.0.1:9337  
- **Datadir nodo:** `./data/`

## GUI Qt

```bash
./start-gui.sh
```

O directamente:

```bash
./bin/bitcoin-qt -datadir="$(pwd)/data"
```

**Nota:** no ejecutes `bitcoind` y `bitcoin-qt` a la vez con el mismo `data/` — la GUI incluye el nodo. `start-gui.sh` detiene `bitcoind` automáticamente.

## Parar

```bash
./stop-all.sh
```

## Arrancar con Ubuntu (systemd)

Para que el **nodo**, la **wallet web**, el **explorador** y el **monitor de nodos** arranquen solos al encender el PC:

```bash
./build.sh
sudo ./install-autostart.sh
```

Comprueba:

```bash
sudo systemctl status bitcoinall-node
sudo journalctl -u bitcoinall-node -f
```

Desactivar:

```bash
sudo ./uninstall-autostart.sh
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
| `node-app/` | Monitor de peers P2P (en la raíz del repo) |

Los binarios compilados (`bin/`, `.build/`) no se suben a git; se generan con `./build.sh`.
