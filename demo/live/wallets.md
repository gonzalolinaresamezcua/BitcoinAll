# BitcoinAll LIVE (main) — wallets & recovery

Local **main/live** network (not regtest). Nodes validate like Ethereum full nodes; block production on the proposer uses `-btcaallowgenerate=1`.

## Start / stop

```bash
demo/live/start-live.sh
# stop: kill $(cat demo/live/node1/bitcoind.pid demo/live/node2/bitcoind.pid)
```

## RPC

| | Node 1 (proposer) | Node 2 (validator) |
|--|--|--|
| RPC | `http://127.0.0.1:8332` | `http://127.0.0.1:8333` |
| P2P | `127.0.0.1:9333` | `127.0.0.1:9334` |
| User / pass | `btca-live` / `BtcaLive-Demo-9333!` | same |
| Wallet | `wallet_node1` | `wallet_node2` |

```bash
build/bin/bitcoin-cli -datadir=demo/live/node1 -rpcwallet=wallet_node1 getbalance
build/bin/bitcoin-cli -datadir=demo/live/node2 -rpcwallet=wallet_node2 getbalance
```

## Reward address keys (imported into wallets)

| Wallet | Address | WIF (main) | Hex |
|--------|---------|------------|-----|
| Node 1 | `btca1qw508d6qejxtdg4y5r3zarvary0c5xw7kj7tmhx` | `KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn` | `...0001` |
| Node 2 | `btca1qq6hag67dl53wl99vzg42z8eyzfz2xlkvcq6awj` | `KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4` | `...0002` |

Node 1 key is also the **designated proposer** signing key.

## Generated wallet descriptors (xprv)

Full exports with private keys:

- `demo/live/wallet_node1_descriptors.json`
- `demo/live/wallet_node2_descriptors.json`
- `demo/live/credentials.json` / `credentials.env`

Restore on a fresh wallet:

```bash
bitcoin-cli -datadir=demo/live/node1 createwallet wallet_node1
bitcoin-cli -datadir=demo/live/node1 -rpcwallet=wallet_node1 importdescriptors "$(jq -c '[.descriptors[] | {desc, timestamp:0, active, internal}]' demo/live/wallet_node1_descriptors.json)"
```

## Sending BTCA (amount units)

Consensus uses `COIN = 100`, but RPC amount parsing still assumes 8 decimals.  
Wallet **balances** show values with `COIN=100` (e.g. coinbase = `50`).

To send **10 BTCA** (as shown in `getbalance`):

```bash
bitcoin-cli -datadir=demo/live/node1 -rpcwallet=wallet_node1 \
  -named sendtoaddress address=<addr> amount=0.00001 fee_rate=1
```

Rule of thumb: `rpc_amount = display_btca / 1_000_000`.

## Files

| File | Purpose |
|------|---------|
| `credentials.env` | Env vars for scripts |
| `credentials.json` | Full access map + balances snapshot |
| `wallet_*_descriptors.json` | Descriptor wallets with secrets (xprv) |
| `wallet_*_addresses.json` | Addresses that received funds |
| `start-live.sh` | Boot both live nodes |
| `setup-wallets.sh` | Recreate wallets + mine bootstrap BTCA |
| `run-explorer.sh` | Explorer pointed at LIVE RPCs (port 8081) |
