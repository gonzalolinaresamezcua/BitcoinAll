# BitcoinAll demo wallets — recover BTCA

**Regtest / demo only.** These private keys control the reward addresses used in the local two-node demo.

## Addresses and recovery keys

| Wallet | Address | PrivKey WIF (regtest) | PrivKey hex |
|--------|---------|------------------------|-------------|
| Node 1 · Proposer rewards | `rbtca1qw508d6qejxtdg4y5r3zarvary0c5xw7k5c4835` | `cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA` | `...0001` |
| Node 2 · Validator rewards | `rbtca1qq6hag67dl53wl99vzg42z8eyzfz2xlkv7xypgq` | `cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87K7XCyj5v` | `...0002` |
| Spare demo | `rbtca1q0ht9tyks4vh7p5p904t340cr9nvahy7ufu9gcf` | `cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87KcLPVfXz` | `...0003` |

Full machine-readable copies: [`credentials.env`](credentials.env), [`credentials.json`](credentials.json).

## How to recover / spend

1. Run a BitcoinAll node with **wallet support** enabled (`-DENABLE_WALLET=ON`), or import into a compatible wallet.
2. Import the WIF of the address that received the coinbase.
3. Wait for **coinbase maturity** (typically 100 confirmations) before spending.

Example (descriptor wallet):

```bash
# after creating a wallet on regtest
bitcoin-cli -datadir=/tmp/btca-wallet getdescriptorinfo \
  "wpkh(cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA)"
# use returned descriptor with checksum, then:
bitcoin-cli -datadir=/tmp/btca-wallet importdescriptors \
  '[{"desc":"wpkh(cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA)#<checksum>","timestamp":0}]'
bitcoin-cli -datadir=/tmp/btca-wallet getbalance
```

Legacy import (if available):

```bash
bitcoin-cli importprivkey "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA" "node1" false
bitcoin-cli importprivkey "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87K7XCyj5v" "node2" false
```

## Notes

- Node 1 reward key **is the same** as the designated proposer signing key.
- Current demo build may have been compiled with `ENABLE_WALLET=OFF`; keys still recover funds once a wallet-capable binary (or external wallet) is used against this chain.
- Do **not** reuse these keys outside local regtest.
