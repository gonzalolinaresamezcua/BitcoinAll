#!/usr/bin/env bash
# Create LIVE wallets, import recovery keys, mine bootstrap BTCA, save credentials.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLI="${BTCA_BITCOIN_CLI:-$ROOT/build/bin/bitcoin-cli}"
N1="$ROOT/demo/live/node1"
N2="$ROOT/demo/live/node2"

WIF1="KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
WIF2="KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4"
ADDR1="btca1qw508d6qejxtdg4y5r3zarvary0c5xw7kj7tmhx"
ADDR2="btca1qq6hag67dl53wl99vzg42z8eyzfz2xlkvcq6awj"

rpc1() { "$CLI" -datadir="$N1" "$@"; }
rpc2() { "$CLI" -datadir="$N2" "$@"; }

ensure_wallet() {
  local rpc=$1 name=$2 ddir=$3
  if $rpc -rpcwallet="$name" getwalletinfo >/dev/null 2>&1; then
    echo "wallet loaded: $name"
    return 0
  fi
  if $rpc loadwallet "$name" >/dev/null 2>&1; then
    echo "wallet loaded from disk: $name"
    return 0
  fi
  rm -rf "$ddir/$name"
  $rpc -named createwallet wallet_name="$name" descriptors=true load_on_startup=true >/dev/null
  echo "created wallet: $name"
}

import_wif() {
  local rpc=$1 name=$2 wif=$3
  local chk
  chk=$($rpc getdescriptorinfo "wpkh($wif)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["checksum"])')
  $rpc -rpcwallet="$name" importdescriptors "[{\"desc\":\"wpkh($wif)#$chk\",\"timestamp\":0}]" >/dev/null
  echo "imported wpkh key into $name"
}

bash "$(dirname "$0")/start-live.sh"

ensure_wallet rpc1 wallet_node1 "$N1"
ensure_wallet rpc2 wallet_node2 "$N2"
import_wif rpc1 wallet_node1 "$WIF1"
import_wif rpc2 wallet_node2 "$WIF2"

NEW1=$(rpc1 -rpcwallet=wallet_node1 getnewaddress "live-generated")
NEW2=$(rpc2 -rpcwallet=wallet_node2 getnewaddress "live-generated")
echo "generated addresses: $NEW1 / $NEW2"

echo "Mining bootstrap BTCA..."
rpc1 generatetoaddress 101 "$ADDR1" >/dev/null
rpc1 generatetoaddress 20 "$ADDR2" >/dev/null
rpc1 generatetoaddress 10 "$NEW1" >/dev/null
rpc1 generatetoaddress 10 "$NEW2" >/dev/null
rpc1 generatetoaddress 100 "$ADDR1" >/dev/null  # maturity

for i in $(seq 1 30); do
  [[ "$(rpc1 getblockcount)" == "$(rpc2 getblockcount)" ]] && break
  sleep 1
done

rpc1 -rpcwallet=wallet_node1 rescanblockchain 0 >/dev/null
rpc2 -rpcwallet=wallet_node2 rescanblockchain 0 >/dev/null

rpc1 -rpcwallet=wallet_node1 listdescriptors true >"$ROOT/demo/live/wallet_node1_descriptors.json"
rpc2 -rpcwallet=wallet_node2 listdescriptors true >"$ROOT/demo/live/wallet_node2_descriptors.json"
rpc1 -rpcwallet=wallet_node1 listreceivedbyaddress 0 true true >"$ROOT/demo/live/wallet_node1_addresses.json"
rpc2 -rpcwallet=wallet_node2 listreceivedbyaddress 0 true true >"$ROOT/demo/live/wallet_node2_addresses.json"

python3 - "$ROOT" "$NEW1" "$NEW2" <<'PY'
import json, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
cli = str(root / "build/bin/bitcoin-cli")
def rpc(ddir, wallet, *args):
    cmd = [cli, f"-datadir={ddir}"]
    if wallet:
        cmd.append(f"-rpcwallet={wallet}")
    cmd.extend(map(str, args))
    return json.loads(subprocess.check_output(cmd, text=True))
b1 = rpc(root/"demo/live/node1", "wallet_node1", "getbalances")["mine"]
b2 = rpc(root/"demo/live/node2", "wallet_node2", "getbalances")["mine"]
h = int(subprocess.check_output([cli, f"-datadir={root}/demo/live/node1", "getblockcount"], text=True))
d1 = json.load(open(root/"demo/live/wallet_node1_descriptors.json"))
d2 = json.load(open(root/"demo/live/wallet_node2_descriptors.json"))
a1 = json.load(open(root/"demo/live/wallet_node1_addresses.json"))
a2 = json.load(open(root/"demo/live/wallet_node2_addresses.json"))
def wpkh_desc(d):
    for x in d["descriptors"]:
        if x["desc"].startswith("wpkh(") and "/84h/" in x["desc"]:
            return x["desc"]
    return d["descriptors"][0]["desc"]
cred = {
  "network": "main",
  "mode": "live",
  "warning": "LIVE BitcoinAll main-chain demo. These keys control BTCA on this local live network.",
  "height": h,
  "rpc": {"user": "btca-live", "password": "BtcaLive-Demo-9333!"},
  "nodes": {
    "node1": {
      "datadir": str(root/"demo/live/node1"),
      "rpc": "http://127.0.0.1:8332",
      "p2p": "127.0.0.1:9333",
      "wallet_name": "wallet_node1",
      "balances": b1,
      "reward_address_imported": "btca1qw508d6qejxtdg4y5r3zarvary0c5xw7kj7tmhx",
      "reward_privkey_wif_main": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
      "reward_privkey_hex": "0000000000000000000000000000000000000000000000000000000000000001",
      "wallet_generated_sample": sys.argv[2],
      "wallet_generated_addresses": [x["address"] for x in a1],
      "wallet_descriptor_export_file": "demo/live/wallet_node1_descriptors.json",
      "wallet_wpkh_descriptor_with_key": wpkh_desc(d1),
    },
    "node2": {
      "datadir": str(root/"demo/live/node2"),
      "rpc": "http://127.0.0.1:8333",
      "p2p": "127.0.0.1:9334",
      "wallet_name": "wallet_node2",
      "balances": b2,
      "reward_address_imported": "btca1qq6hag67dl53wl99vzg42z8eyzfz2xlkvcq6awj",
      "reward_privkey_wif_main": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
      "reward_privkey_hex": "0000000000000000000000000000000000000000000000000000000000000002",
      "wallet_generated_sample": sys.argv[3],
      "wallet_generated_addresses": [x["address"] for x in a2],
      "wallet_descriptor_export_file": "demo/live/wallet_node2_descriptors.json",
      "wallet_wpkh_descriptor_with_key": wpkh_desc(d2),
    },
  },
  "designated_proposer": {
    "pubkey": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "privkey_wif_main": "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
    "privkey_hex": "0000000000000000000000000000000000000000000000000000000000000001",
  },
}
(root/"demo/live/credentials.json").write_text(json.dumps(cred, indent=2) + "\n")
(root/"demo/live/credentials.env").write_text(f"""# BitcoinAll LIVE (main) — access credentials
BTCA_LIVE_RPC_USER=btca-live
BTCA_LIVE_RPC_PASSWORD=BtcaLive-Demo-9333!
BTCA_LIVE_NODE1_DATADIR={root}/demo/live/node1
BTCA_LIVE_NODE2_DATADIR={root}/demo/live/node2
BTCA_LIVE_NODE1_RPC=http://127.0.0.1:8332
BTCA_LIVE_NODE2_RPC=http://127.0.0.1:8333
BTCA_LIVE_NODE1_WALLET=wallet_node1
BTCA_LIVE_NODE2_WALLET=wallet_node2
BTCA_LIVE_NODE1_ADDR=btca1qw508d6qejxtdg4y5r3zarvary0c5xw7kj7tmhx
BTCA_LIVE_NODE2_ADDR=btca1qq6hag67dl53wl99vzg42z8eyzfz2xlkvcq6awj
BTCA_LIVE_NODE1_PRIVKEY_WIF=KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
BTCA_LIVE_NODE2_PRIVKEY_WIF=KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4
BTCA_LIVE_PROPOSER_PUBKEY=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
BTCA_BITCOIND={root}/build/bin/bitcoind
BTCA_BITCOIN_CLI={root}/build/bin/bitcoin-cli
""")
print("height", h)
print("node1", b1)
print("node2", b2)
print("credentials written to demo/live/credentials.*")
PY

echo "LIVE wallet setup complete."
