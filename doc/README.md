BitcoinAll Core
===============

Documentación del nodo, wallet y herramientas de BitcoinAll (BTCA · Proof of Uptime).

Repositorio oficial: https://github.com/gonzalolinaresamezcua/BitcoinAll

Setup
---------------------
BitcoinAll Core se conecta a la red P2P de BitcoinAll, valida bloques y transacciones, e incluye wallet. La GUI (`bitcoin-qt`) es opcional al compilar.

Para obtener el software:

- **Compilar:** [doc/build-unix.md](build-unix.md) (Linux), [build-osx.md](build-osx.md), [build-windows-msvc.md](build-windows-msvc.md)
- **Releases:** https://github.com/gonzalolinaresamezcua/BitcoinAll/releases

Running
---------------------
Tras compilar, los binarios están en `build/bin/`:

- `bin/bitcoin-qt` (GUI) o
- `bin/bitcoind` (nodo en segundo plano)
- `bin/bitcoin-cli` (RPC)

Apps web locales (opcional):

- Wallet: `wallet-app/run.sh start` → http://127.0.0.1:9335
- Explorer: `explorer-app/run.sh start` → http://127.0.0.1:9336

### Need Help?

* Abre un [issue en GitHub](https://github.com/gonzalolinaresamezcua/BitcoinAll/issues).
* Consulta [CONTRIBUTING.md](../CONTRIBUTING.md) para contribuir.

Building
---------------------
Notas de compilación por plataforma:

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows-msvc.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)

Development
---------------------
El [README principal](../README.md) describe el proyecto, consenso PoU y el flujo de desarrollo.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [REST Interface](REST-interface.md)
- [BIPS](bips.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources

* Discusión y PRs: https://github.com/gonzalolinaresamezcua/BitcoinAll

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [bitcoin.conf Configuration File](bitcoin-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial](multisig-tutorial.md)
- [Offline Signing Tutorial](offline-signing-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
