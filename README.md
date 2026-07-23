# BitcoinAll Core

**BitcoinAll** — decentralized money for everyone / moneda descentralizada para todo el público / 面向所有人的去中心化货币

| Language | Section |
|----------|---------|
| English | [English](#english) |
| Español | [Español](#español) |
| 中文 | [中文](#中文) |

---

## English

### What is BitcoinAll?

BitcoinAll Core is a full peer-to-peer node derived from Bitcoin Core. In the current design, **nodes are validation-compatible** (sync and verify the chain) and **do not mine with Proof-of-Work**, similar in role to an Ethereum full node: they validate blocks and transactions, keep consensus, and relay data.

Block production uses a **designated proposer** model: each block header must carry a valid signature from the configured proposer public key instead of a PoW hash puzzle.

### Recent changes

- **No PoW mining on nodes** — peers validate and sync; they are not miners.
- **Proposer signature consensus** — `CheckBlockHeader` verifies the designated proposer’s signature (`bad-blk-sig` if invalid). Genesis may be unsigned.
- **Mining RPCs disabled** — `getblocktemplate`, `submitblock`, and `submitheader` are unavailable. `generate*` works only on **regtest**.
- **`getmininginfo`** reports `mining: false`, `proof: "designated-proposer"`, and the proposer pubkey.
- **Header sync fix** — block identity hash excludes the signature; `CBlockIndex` persists `vchBlockSignature` so peers can relay continuous headers.
- **Live block explorer** — see [`explorer/`](explorer/) for blocks, live mining, and reward distribution between demo nodes.

### Regtest proposer key (demo)

| Field | Value |
|-------|-------|
| PubKey | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| PrivKey WIF (regtest) | `cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA` |
| PrivKey hex | `0000000000000000000000000000000000000000000000000000000000000001` |
| Demo address (node 1) | `rbtca1qw508d6qejxtdg4y5r3zarvary0c5xw7k5c4835` |
| Demo address (node 2) | `rbtca1qq6hag67dl53wl99vzg42z8eyzfz2xlkv7xypgq` |

> This key is for **regtest / local demos only**. Do not use it on any public network with real value.
>
> All demo credentials (RPC, ports, proposer key, reward addresses) are saved in [`demo/credentials.env`](demo/credentials.env) and [`demo/credentials.json`](demo/credentials.json).

On regtest, `generatetoaddress` signs blocks automatically with the embedded proposer key:

```bash
bitcoin-cli -datadir=/tmp/btca-node1 \
  generatetoaddress 101 rbtca1qw508d6qejxtdg4y5r3zarvary0c5xw7k5c4835
```

### Run two nodes (regtest)

Build (example, wallet may be off depending on your tree):

```bash
cmake -B build -DENABLE_WALLET=OFF
cmake --build build -j"$(nproc)" --target bitcoind bitcoin-cli
```

Example configs (network-specific options under `[regtest]`):

**Node 1** (`/tmp/btca-node1/bitcoin.conf`):

```ini
regtest=1
server=1
rpcuser=btca
rpcpassword=btca-demo
discover=0
listenonion=0
dnsseed=0
fixedseeds=0

[regtest]
port=19444
bind=127.0.0.1
rpcport=18443
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
```

**Node 2** (`/tmp/btca-node2/bitcoin.conf`):

```ini
regtest=1
server=1
rpcuser=btca
rpcpassword=btca-demo
discover=0
listenonion=0
dnsseed=0
fixedseeds=0

[regtest]
port=19455
bind=127.0.0.1
rpcport=18453
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
addnode=127.0.0.1:19444
```

```bash
./build/bin/bitcoind -datadir=/tmp/btca-node1 &
./build/bin/bitcoind -datadir=/tmp/btca-node2 &
./build/bin/bitcoin-cli -datadir=/tmp/btca-node1 getblockchaininfo
./build/bin/bitcoin-cli -datadir=/tmp/btca-node2 getpeerinfo
```

### Block explorer

With both nodes running:

```bash
cd explorer
./run.sh
# open http://127.0.0.1:8080
```

The explorer shows node status, recent blocks, live activity, manual/auto block generation, and coinbase reward shares between the two demo addresses.

### Docs, license, development

- Build and developer docs: [`doc/`](doc/)
- License: [MIT](COPYING)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## Español

### ¿Qué es BitcoinAll?

BitcoinAll Core es un nodo completo P2P derivado de Bitcoin Core. En el diseño actual, **los nodos son compatibles de validación** (sincronizan y verifican la cadena) y **no minan con Prueba de Trabajo**, en un rol parecido al de un full node de Ethereum: validan bloques y transacciones, mantienen el consenso y retransmiten datos.

La producción de bloques usa un modelo de **proposer designado**: cada cabecera debe llevar una firma válida de la clave pública del proposer configurado, en lugar de un puzzle PoW.

### Cambios recientes

- **Sin minado PoW en los nodos** — los peers validan y sincronizan; no son mineros.
- **Consenso por firma del proposer** — `CheckBlockHeader` verifica la firma del proposer designado (`bad-blk-sig` si es inválida). El genesis puede ir sin firma.
- **RPCs de minería deshabilitados** — no estánan `getblocktemplate`, `submitblock` ni `submitheader`. `generate*` solo en **regtest**.
- **`getmininginfo`** indica `mining: false`, `proof: "designated-proposer"` y la pubkey del proposer.
- **Sync de headers corregido** — el hash de identidad del bloque excluye la firma; `CBlockIndex` guarda `vchBlockSignature` para retransmitir headers de forma continua.
- **Explorador en vivo** — en [`explorer/`](explorer/) puedes ver bloques, minar y el reparto de premios entre nodos de demo.

### Clave del proposer en regtest (demo)

| Campo | Valor |
|-------|-------|
| PubKey | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| PrivKey WIF (regtest) | `cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA` |
| PrivKey hex | `0000000000000000000000000000000000000000000000000000000000000001` |
| Dirección demo (nodo 1) | `rbtca1qw508d6qejxtdg4y5r3zarvary0c5xw7k5c4835` |
| Dirección demo (nodo 2) | `rbtca1qq6hag67dl53wl99vzg42z8eyzfz2xlkv7xypgq` |

> Esta clave es **solo para regtest / demos locales**. No la uses en redes públicas con valor real.
>
> Todas las credenciales de demo (RPC, puertos, clave del proposer, direcciones de premio) están en [`demo/credentials.env`](demo/credentials.env) y [`demo/credentials.json`](demo/credentials.json).

En regtest, `generatetoaddress` firma automáticamente con la clave embebida del proposer:

```bash
bitcoin-cli -datadir=/tmp/btca-node1 \
  generatetoaddress 101 rbtca1qw508d6qejxtdg4y5r3zarvary0c5xw7k5c4835
```

### Lanzar dos nodos (regtest)

Compilación (ejemplo; la wallet puede ir desactivada según tu árbol):

```bash
cmake -B build -DENABLE_WALLET=OFF
cmake --build build -j"$(nproc)" --target bitcoind bitcoin-cli
```

Configs de ejemplo (opciones de red bajo `[regtest]`):

**Nodo 1** (`/tmp/btca-node1/bitcoin.conf`):

```ini
regtest=1
server=1
rpcuser=btca
rpcpassword=btca-demo
discover=0
listenonion=0
dnsseed=0
fixedseeds=0

[regtest]
port=19444
bind=127.0.0.1
rpcport=18443
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
```

**Nodo 2** (`/tmp/btca-node2/bitcoin.conf`):

```ini
regtest=1
server=1
rpcuser=btca
rpcpassword=btca-demo
discover=0
listenonion=0
dnsseed=0
fixedseeds=0

[regtest]
port=19455
bind=127.0.0.1
rpcport=18453
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
addnode=127.0.0.1:19444
```

```bash
./build/bin/bitcoind -datadir=/tmp/btca-node1 &
./build/bin/bitcoind -datadir=/tmp/btca-node2 &
./build/bin/bitcoin-cli -datadir=/tmp/btca-node1 getblockchaininfo
./build/bin/bitcoin-cli -datadir=/tmp/btca-node2 getpeerinfo
```

### Explorador de bloques

Con ambos nodos en marcha:

```bash
cd explorer
./run.sh
# abrir http://127.0.0.1:8080
```

Muestra el estado de los nodos, bloques recientes, actividad en vivo, minado manual/automático y el reparto de premios coinbase entre las dos direcciones de demo.

### Docs, licencia y desarrollo

- Documentación: [`doc/`](doc/)
- Licencia: [MIT](COPYING)
- Contribuciones: [`CONTRIBUTING.md`](CONTRIBUTING.md)

---

## 中文

### BitcoinAll 是什么？

BitcoinAll Core 是基于 Bitcoin Core 的完整点对点节点。在当前设计中，**节点以验证兼容方式运行**（同步并验证链），**不再通过工作量证明（PoW）挖矿**，角色类似以太坊全节点：验证区块与交易、维护共识并转发数据。

出块采用 **指定提议者（designated proposer）** 模型：每个区块头必须带有已配置提议者公钥的有效签名，而不再依赖 PoW 哈希谜题。

### 近期变更

- **节点不再 PoW 挖矿** — 对等节点负责验证与同步，不是矿工。
- **提议者签名共识** — `CheckBlockHeader` 校验指定提议者签名（无效则为 `bad-blk-sig`）。创世块可以无签名。
- **挖矿 RPC 已禁用** — 不可用 `getblocktemplate`、`submitblock`、`submitheader`。`generate*` 仅在 **regtest** 可用。
- **`getmininginfo`** 返回 `mining: false`、`proof: "designated-proposer"` 以及提议者公钥。
- **区块头同步修复** — 区块身份哈希不包含签名；`CBlockIndex` 持久化 `vchBlockSignature`，以便连续转发 headers。
- **实时区块浏览器** — 见 [`explorer/`](explorer/)，可查看区块、实时出块以及演示节点间的奖励分配。

### Regtest 提议者密钥（演示）

| 字段 | 值 |
|------|----|
| 公钥 PubKey | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` |
| 私钥 WIF（regtest） | `cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA` |
| 私钥十六进制 | `0000000000000000000000000000000000000000000000000000000000000001` |
| 演示地址（节点 1） | `rbtca1qw508d6qejxtdg4y5r3zarvary0c5xw7k5c4835` |
| 演示地址（节点 2） | `rbtca1qq6hag67dl53wl99vzg42z8eyzfz2xlkv7xypgq` |

> 该密钥**仅用于 regtest / 本地演示**。请勿在任何有真实价值的公网中使用。
>
> 全部演示凭证（RPC、端口、提议者密钥、奖励地址）保存在 [`demo/credentials.env`](demo/credentials.env) 与 [`demo/credentials.json`](demo/credentials.json)。

在 regtest 上，`generatetoaddress` 会使用内嵌提议者密钥自动签名：

```bash
bitcoin-cli -datadir=/tmp/btca-node1 \
  generatetoaddress 101 rbtca1qw508d6qejxtdg4y5r3zarvary0c5xw7k5c4835
```

### 运行两个节点（regtest）

编译示例（视代码树情况可关闭钱包）：

```bash
cmake -B build -DENABLE_WALLET=OFF
cmake --build build -j"$(nproc)" --target bitcoind bitcoin-cli
```

配置示例（网络相关选项放在 `[regtest]` 下）：

**节点 1**（`/tmp/btca-node1/bitcoin.conf`）：

```ini
regtest=1
server=1
rpcuser=btca
rpcpassword=btca-demo
discover=0
listenonion=0
dnsseed=0
fixedseeds=0

[regtest]
port=19444
bind=127.0.0.1
rpcport=18443
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
```

**节点 2**（`/tmp/btca-node2/bitcoin.conf`）：

```ini
regtest=1
server=1
rpcuser=btca
rpcpassword=btca-demo
discover=0
listenonion=0
dnsseed=0
fixedseeds=0

[regtest]
port=19455
bind=127.0.0.1
rpcport=18453
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
addnode=127.0.0.1:19444
```

```bash
./build/bin/bitcoind -datadir=/tmp/btca-node1 &
./build/bin/bitcoind -datadir=/tmp/btca-node2 &
./build/bin/bitcoin-cli -datadir=/tmp/btca-node1 getblockchaininfo
./build/bin/bitcoin-cli -datadir=/tmp/btca-node2 getpeerinfo
```

### 区块浏览器

两个节点运行后：

```bash
cd explorer
./run.sh
# 打开 http://127.0.0.1:8080
```

浏览器展示节点状态、最近区块、实时活动、手动/自动出块，以及两个演示地址之间的 coinbase 奖励分配。

### 文档、许可证与开发

- 文档：[`doc/`](doc/)
- 许可证：[MIT](COPYING)
- 贡献指南：[`CONTRIBUTING.md`](CONTRIBUTING.md)
