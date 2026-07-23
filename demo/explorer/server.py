#!/usr/bin/env python3
"""BitcoinAll block explorer — reads two regtest nodes over RPC and serves a live UI."""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"

# Defaults = LIVE/main demo ports (8332/8333). Override with env or /api/config.
NODE1 = {
    "id": "node1",
    "name": "Nodo 1 · Proposer",
    "role": "proposer",
    "url": os.environ.get("BTCA_NODE1_RPC", "http://127.0.0.1:8332"),
    "user": os.environ.get("BTCA_RPC_USER", "btca-live"),
    "password": os.environ.get("BTCA_RPC_PASSWORD", "BtcaLive-Demo-9333!"),
    "reward_address": os.environ.get(
        "BTCA_NODE1_ADDR", "btca1qw508d6qejxtdg4y5r3zarvary0c5xw7kj7tmhx"
    ),
    "wallet": os.environ.get("BTCA_NODE1_WALLET")
    or os.environ.get("BTCA_LIVE_NODE1_WALLET")
    or "wallet_node1",
    "color": "#d97706",
}
NODE2 = {
    "id": "node2",
    "name": "Nodo 2 · Validador",
    "role": "validator",
    "url": os.environ.get("BTCA_NODE2_RPC", "http://127.0.0.1:8333"),
    "user": os.environ.get("BTCA_RPC_USER", "btca-live"),
    "password": os.environ.get("BTCA_RPC_PASSWORD", "BtcaLive-Demo-9333!"),
    "reward_address": os.environ.get(
        "BTCA_NODE2_ADDR", "btca1qq6hag67dl53wl99vzg42z8eyzfz2xlkvcq6awj"
    ),
    "wallet": os.environ.get("BTCA_NODE2_WALLET")
    or os.environ.get("BTCA_LIVE_NODE2_WALLET")
    or "wallet_node2",
    "color": "#0d9488",
}
NODES = {n["id"]: n for n in (NODE1, NODE2)}
ADDR_TO_NODE = {n["reward_address"]: n for n in NODES.values()}


def refresh_addr_map() -> None:
    ADDR_TO_NODE.clear()
    for n in NODES.values():
        if n.get("reward_address"):
            ADDR_TO_NODE[n["reward_address"]] = n

HOST = os.environ.get("BTCA_EXPLORER_HOST", "0.0.0.0")
PORT = int(os.environ.get("BTCA_EXPLORER_PORT", "8080"))

_subscribers: list[queue.Queue] = []
_sub_lock = threading.Lock()
_state_lock = threading.Lock()
_last_tip = ""
_block_cache: dict[int, dict[str, Any]] = {}
_auto_mine = {
    "enabled": False,
    "interval_sec": 8,
    "blocks": 1,
    "target": "rotate",  # node1 | node2 | rotate
    "next": "node1",
}


def rpc(node: dict[str, Any], method: str, params: list[Any] | None = None, *, wallet: str | None = None) -> Any:
    base = node["url"].rstrip("/")
    url = f"{base}/wallet/{wallet}" if wallet else base
    payload = json.dumps(
        {"jsonrpc": "1.0", "id": "btca-explorer", "method": method, "params": params or []}
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, node["user"], node["password"])
    password_mgr.add_password(None, base, node["user"], node["password"])
    opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(password_mgr))
    try:
        with opener.open(req, timeout=60) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="ignore")
        raise RuntimeError(f"RPC HTTP {exc.code}: {detail}") from exc
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"RPC {node['id']} {method}: {exc}") from exc
    if body.get("error"):
        raise RuntimeError(body["error"])
    return body["result"]


def broadcast(event: str, data: Any) -> None:
    msg = json.dumps({"event": event, "data": data}, default=str)
    with _sub_lock:
        dead: list[queue.Queue] = []
        for q in _subscribers:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)


def wallet_balances(node: dict[str, Any]) -> dict[str, Any] | None:
    wallet = (node.get("wallet") or "").strip()
    if not wallet:
        return None
    try:
        bal = rpc(node, "getbalances", wallet=wallet)
        return {
            "wallet": wallet,
            "trusted": float((bal.get("mine") or {}).get("trusted") or 0),
            "immature": float((bal.get("mine") or {}).get("immature") or 0),
            "untrusted_pending": float((bal.get("mine") or {}).get("untrusted_pending") or 0),
        }
    except Exception as exc:  # noqa: BLE001
        return {"wallet": wallet, "error": str(exc)}


def node_status(node: dict[str, Any]) -> dict[str, Any]:
    try:
        chain = rpc(node, "getblockchaininfo")
        net = rpc(node, "getnetworkinfo")
        mining = rpc(node, "getmininginfo")
        peers = rpc(node, "getpeerinfo")
        return {
            "id": node["id"],
            "name": node["name"],
            "role": node["role"],
            "color": node["color"],
            "reward_address": node["reward_address"],
            "rpc_url": node["url"],
            "wallet": node.get("wallet") or None,
            "wallet_balances": wallet_balances(node),
            "online": True,
            "chain": chain.get("chain"),
            "blocks": chain["blocks"],
            "headers": chain["headers"],
            "bestblockhash": chain["bestblockhash"],
            "verificationprogress": chain["verificationprogress"],
            "initialblockdownload": chain["initialblockdownload"],
            "connections": net["connections"],
            "subversion": net.get("subversion"),
            "mining": mining.get("mining"),
            "proof": mining.get("proof"),
            "generate_allowed": mining.get("generate_allowed"),
            "designated_proposer": mining.get("designated_proposer"),
            "peers": [
                {
                    "addr": p.get("addr"),
                    "inbound": p.get("inbound"),
                    "synced_headers": p.get("synced_headers"),
                    "synced_blocks": p.get("synced_blocks"),
                }
                for p in peers
            ],
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "id": node["id"],
            "name": node["name"],
            "role": node["role"],
            "color": node["color"],
            "reward_address": node["reward_address"],
            "rpc_url": node["url"],
            "wallet": node.get("wallet") or None,
            "wallet_balances": None,
            "online": False,
            "error": str(exc),
        }


def lookup_address(address: str) -> dict[str, Any]:
    address = (address or "").strip()
    if not address:
        raise ValueError("Indica una dirección BTCA")
    info = rpc(NODE1, "validateaddress", [address])
    if not info.get("isvalid"):
        raise ValueError("Dirección inválida para esta red")
    scan = rpc(NODE1, "scantxoutset", ["start", [f"addr({address})"]])
    unspents = scan.get("unspents") or []
    total = scan.get("total_amount")
    if total is None:
        total = sum(float(u.get("amount") or 0) for u in unspents)
    else:
        total = float(total)
    spendable = sum(float(u.get("amount") or 0) for u in unspents if not u.get("coinbase") or int(u.get("confirmations") or 0) >= 100)
    immature = round(total - spendable, 8)
    utxos = [
        {
            "txid": u.get("txid"),
            "vout": u.get("vout"),
            "amount": float(u.get("amount") or 0),
            "confirmations": u.get("confirmations"),
            "coinbase": bool(u.get("coinbase")),
            "height": u.get("height"),
        }
        for u in sorted(unspents, key=lambda x: (-int(x.get("confirmations") or 0), x.get("txid") or ""))
    ][:50]
    wallet_hits: list[dict[str, Any]] = []
    for node in (NODE1, NODE2):
        w = (node.get("wallet") or "").strip()
        if not w:
            continue
        try:
            received = float(rpc(node, "getreceivedbyaddress", [address, 0], wallet=w))
            ainfo = rpc(node, "getaddressinfo", [address], wallet=w)
            wallet_hits.append(
                {
                    "node": node["id"],
                    "wallet": w,
                    "ismine": bool(ainfo.get("ismine")),
                    "iswatchonly": bool(ainfo.get("iswatchonly")),
                    "received": received,
                }
            )
        except Exception as exc:  # noqa: BLE001
            wallet_hits.append({"node": node["id"], "wallet": w, "error": str(exc)})
    return {
        "address": address,
        "isvalid": True,
        "isscript": bool(info.get("isscript")),
        "iswitness": bool(info.get("iswitness")),
        "chain_height": scan.get("height"),
        "bestblock": scan.get("bestblock"),
        "total_btca": round(float(total), 8),
        "spendable_btca": round(float(spendable), 8),
        "immature_btca": round(float(immature), 8),
        "utxo_count": len(unspents),
        "utxos": utxos,
        "wallets": wallet_hits,
        "known_as": ADDR_TO_NODE[address]["name"] if address in ADDR_TO_NODE else None,
    }


def rpc_config() -> dict[str, Any]:
    return {
        "node1": {
            "url": NODE1["url"],
            "user": NODE1["user"],
            "reward_address": NODE1["reward_address"],
            "wallet": NODE1.get("wallet") or "",
        },
        "node2": {
            "url": NODE2["url"],
            "user": NODE2["user"],
            "reward_address": NODE2["reward_address"],
            "wallet": NODE2.get("wallet") or "",
        },
        "help": (
            "El explorador lee bitcoind por RPC en ESTA máquina. "
            "Si ves WinError 10061 / connection refused, arranca los nodos "
            "(demo/live/start-live.sh) o apunta las URLs RPC correctas."
        ),
    }


def apply_rpc_config(data: dict[str, Any]) -> dict[str, Any]:
    global _last_tip
    for key, node in (("node1", NODE1), ("node2", NODE2)):
        cfg = data.get(key) or {}
        if cfg.get("url"):
            node["url"] = str(cfg["url"]).rstrip("/")
        if cfg.get("user") is not None:
            node["user"] = str(cfg["user"])
        if cfg.get("password"):
            node["password"] = str(cfg["password"])
        if cfg.get("reward_address"):
            node["reward_address"] = str(cfg["reward_address"]).strip()
        if "wallet" in cfg:
            node["wallet"] = str(cfg.get("wallet") or "").strip()
    if data.get("password") and not (data.get("node1") or {}).get("password"):
        NODE1["password"] = str(data["password"])
        NODE2["password"] = str(data["password"])
    refresh_addr_map()
    _block_cache.clear()
    _last_tip = ""
    return rpc_config()


def enrich_block(height: int, verbosity: int = 2) -> dict[str, Any] | None:
    if height in _block_cache:
        return _block_cache[height]
    try:
        tip_hash = rpc(NODE1, "getblockhash", [height])
        block = rpc(NODE1, "getblock", [tip_hash, verbosity])
    except Exception:
        return None

    coinbase = None
    reward_total = 0.0
    recipients: list[dict[str, Any]] = []
    if block.get("tx"):
        cb = block["tx"][0]
        coinbase = {"txid": cb.get("txid"), "vout": []}
        for vout in cb.get("vout", []):
            value = float(vout.get("value", 0))
            reward_total += value
            spk = vout.get("scriptPubKey") or {}
            addr = spk.get("address") or (spk.get("addresses") or [None])[0]
            node = ADDR_TO_NODE.get(addr)
            entry = {
                "value": value,
                "address": addr,
                "node_id": node["id"] if node else None,
                "node_name": node["name"] if node else "Desconocido",
                "color": node["color"] if node else "#94a3b8",
            }
            recipients.append(entry)
            coinbase["vout"].append(entry)

    enriched = {
        "hash": block["hash"],
        "height": block["height"],
        "time": block["time"],
        "nTx": block["nTx"],
        "size": block.get("size"),
        "weight": block.get("weight"),
        "merkleroot": block.get("merkleroot"),
        "previousblockhash": block.get("previousblockhash"),
        "nextblockhash": block.get("nextblockhash"),
        "confirmations": block.get("confirmations"),
        "reward_total": reward_total,
        "recipients": recipients,
        "coinbase": coinbase,
        "miner_node": recipients[0]["node_id"] if recipients else None,
    }
    _block_cache[height] = enriched
    return enriched


def list_blocks(limit: int = 24) -> list[dict[str, Any]]:
    height = int(rpc(NODE1, "getblockcount"))
    start = max(0, height - limit + 1)
    blocks: list[dict[str, Any]] = []
    for h in range(height, start - 1, -1):
        b = enrich_block(h)
        if b:
            blocks.append(b)
    return blocks


def rewards_summary() -> dict[str, Any]:
    height = int(rpc(NODE1, "getblockcount"))
    by_node: dict[str, dict[str, Any]] = {
        n["id"]: {
            "id": n["id"],
            "name": n["name"],
            "role": n["role"],
            "color": n["color"],
            "address": n["reward_address"],
            "blocks_won": 0,
            "total_btca": 0.0,
            "share": 0.0,
        }
        for n in NODES.values()
    }
    unknown = {
        "id": "other",
        "name": "Otras direcciones",
        "role": "other",
        "color": "#94a3b8",
        "address": None,
        "blocks_won": 0,
        "total_btca": 0.0,
        "share": 0.0,
    }
    total = 0.0
    # skip genesis (height 0) — usually no spendable coinbase reward in the same way
    for h in range(1, height + 1):
        b = enrich_block(h)
        if not b:
            continue
        if not b["recipients"]:
            continue
        # attribute block prize to primary coinbase recipient
        primary = b["recipients"][0]
        nid = primary["node_id"] or "other"
        bucket = by_node.get(nid, unknown)
        bucket["blocks_won"] += 1
        bucket["total_btca"] += b["reward_total"]
        total += b["reward_total"]
        if nid == "other":
            unknown = bucket

    rows = list(by_node.values())
    if unknown["blocks_won"] or unknown["total_btca"]:
        rows.append(unknown)
    for row in rows:
        row["share"] = (row["total_btca"] / total) if total else 0.0
        row["total_btca"] = round(row["total_btca"], 8)
    return {
        "height": height,
        "total_btca": round(total, 8),
        "nodes": rows,
    }


def mine_blocks(count: int, target: str) -> dict[str, Any]:
    if count < 1 or count > 50:
        raise ValueError("count debe estar entre 1 y 50")
    if target == "rotate":
        with _state_lock:
            target = _auto_mine["next"]
            _auto_mine["next"] = "node2" if target == "node1" else "node1"
    if target not in NODES:
        raise ValueError("target debe ser node1, node2 o rotate")
    node = NODES[target]
    # Only node1 can generate (designated proposer / MineBlocksOnDemand on the mining node).
    hashes = rpc(NODE1, "generatetoaddress", [count, node["reward_address"]])
    # wait briefly for peer sync
    deadline = time.time() + 15
    tip = hashes[-1]
    while time.time() < deadline:
        try:
            if rpc(NODE2, "getbestblockhash") == tip:
                break
        except Exception:
            pass
        time.sleep(0.2)
    blocks = [enrich_block(rpc(NODE1, "getblock", [h, 1])["height"]) for h in hashes]
    payload = {
        "target": target,
        "address": node["reward_address"],
        "count": count,
        "hashes": hashes,
        "blocks": [b for b in blocks if b],
    }
    broadcast("mined", payload)
    broadcast("snapshot", build_snapshot())
    return payload


def build_snapshot() -> dict[str, Any]:
    nodes = [node_status(NODE1), node_status(NODE2)]
    online = all(n.get("online") for n in nodes)
    try:
        blocks = list_blocks(20)
        rewards = rewards_summary()
        tip = rpc(NODE1, "getbestblockhash")
        chain = nodes[0].get("chain")
    except Exception as exc:  # noqa: BLE001
        return {
            "nodes": nodes,
            "blocks": [],
            "rewards": {"height": 0, "total_btca": 0, "nodes": []},
            "tip": None,
            "auto_mine": dict(_auto_mine),
            "config": rpc_config(),
            "online": False,
            "error": str(exc),
            "help": rpc_config()["help"],
            "ts": int(time.time()),
        }
    return {
        "nodes": nodes,
        "blocks": blocks,
        "rewards": rewards,
        "tip": tip,
        "chain": chain,
        "auto_mine": dict(_auto_mine),
        "config": rpc_config(),
        "online": online,
        "error": None,
        "help": None,
        "ts": int(time.time()),
    }


def watcher() -> None:
    global _last_tip
    while True:
        try:
            tip = rpc(NODE1, "getbestblockhash")
            if tip != _last_tip:
                _last_tip = tip
                broadcast("snapshot", build_snapshot())
        except Exception:
            broadcast("status", {"nodes": [node_status(NODE1), node_status(NODE2)]})
        # auto mine
        with _state_lock:
            enabled = _auto_mine["enabled"]
            interval = _auto_mine["interval_sec"]
            blocks = _auto_mine["blocks"]
            target = _auto_mine["target"]
        if enabled:
            try:
                mine_blocks(blocks, target)
            except Exception as exc:  # noqa: BLE001
                broadcast("error", {"message": str(exc)})
            time.sleep(max(3, interval))
        else:
            time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    server_version = "BitcoinAllExplorer/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        # quieter logs
        if args and str(args[0]).startswith("GET /api/events"):
            return
        super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: Any) -> None:
        self._send(code, json.dumps(obj, default=str).encode(), "application/json; charset=utf-8")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode() or "{}")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            return self._send_file(STATIC / "index.html", "text/html; charset=utf-8")
        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            fp = (STATIC / rel).resolve()
            if not str(fp).startswith(str(STATIC.resolve())) or not fp.is_file():
                return self._json(404, {"error": "not found"})
            ctype = {
                ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".svg": "image/svg+xml",
                ".png": "image/png",
            }.get(fp.suffix, "application/octet-stream")
            return self._send_file(fp, ctype)

        if path == "/api/health":
            return self._json(200, {"ok": True, "service": "bitcoinall-explorer"})
        if path == "/api/config":
            return self._json(200, rpc_config())
        if path == "/api/snapshot":
            try:
                return self._json(200, build_snapshot())
            except Exception as exc:  # noqa: BLE001
                return self._json(500, {"error": str(exc)})
        if path == "/api/address":
            try:
                addr = (qs.get("address") or [""])[0]
                return self._json(200, lookup_address(addr))
            except Exception as exc:  # noqa: BLE001
                return self._json(400, {"error": str(exc)})
        if path == "/api/blocks":
            limit = int((qs.get("limit") or ["24"])[0])
            try:
                return self._json(200, {"blocks": list_blocks(min(max(limit, 1), 100))})
            except Exception as exc:  # noqa: BLE001
                return self._json(500, {"error": str(exc)})
        if path == "/api/block":
            try:
                if "hash" in qs:
                    h = qs["hash"][0]
                    height = rpc(NODE1, "getblock", [h, 1])["height"]
                else:
                    height = int(qs["height"][0])
                block = enrich_block(height)
                if not block:
                    return self._json(404, {"error": "block not found"})
                return self._json(200, block)
            except Exception as exc:  # noqa: BLE001
                return self._json(500, {"error": str(exc)})
        if path == "/api/rewards":
            try:
                return self._json(200, rewards_summary())
            except Exception as exc:  # noqa: BLE001
                return self._json(500, {"error": str(exc)})
        if path == "/api/events":
            return self._sse()

        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            data = self._read_json()
        except Exception:
            return self._json(400, {"error": "JSON inválido"})

        if path == "/api/mine":
            try:
                count = int(data.get("count", 1))
                target = str(data.get("target", "node1"))
                result = mine_blocks(count, target)
                return self._json(200, result)
            except Exception as exc:  # noqa: BLE001
                return self._json(400, {"error": str(exc)})

        if path == "/api/address":
            try:
                return self._json(200, lookup_address(str(data.get("address") or "")))
            except Exception as exc:  # noqa: BLE001
                return self._json(400, {"error": str(exc)})

        if path == "/api/config":
            try:
                cfg = apply_rpc_config(data)
                snap = build_snapshot()
                broadcast("snapshot", snap)
                return self._json(200, {"config": cfg, "snapshot": snap})
            except Exception as exc:  # noqa: BLE001
                return self._json(400, {"error": str(exc)})

        if path == "/api/automine":
            with _state_lock:
                if "enabled" in data:
                    _auto_mine["enabled"] = bool(data["enabled"])
                if "interval_sec" in data:
                    _auto_mine["interval_sec"] = max(3, min(120, int(data["interval_sec"])))
                if "blocks" in data:
                    _auto_mine["blocks"] = max(1, min(5, int(data["blocks"])))
                if "target" in data and data["target"] in ("node1", "node2", "rotate"):
                    _auto_mine["target"] = data["target"]
                state = dict(_auto_mine)
            broadcast("automine", state)
            return self._json(200, state)

        self._json(404, {"error": "not found"})

    def _send_file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            return self._json(404, {"error": "not found"})
        self._send(200, path.read_bytes(), content_type)

    def _sse(self) -> None:
        q: queue.Queue = queue.Queue(maxsize=64)
        with _sub_lock:
            _subscribers.append(q)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            # initial snapshot
            init = json.dumps({"event": "snapshot", "data": build_snapshot()}, default=str)
            self.wfile.write(f"data: {init}\n\n".encode())
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=15)
                    self.wfile.write(f"data: {msg}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _sub_lock:
                if q in _subscribers:
                    _subscribers.remove(q)


def main() -> None:
    threading.Thread(target=watcher, name="btca-watcher", daemon=True).start()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"BitcoinAll explorer en http://{HOST}:{PORT}", flush=True)
    print(f"  node1 RPC: {NODE1['url']}", flush=True)
    print(f"  node2 RPC: {NODE2['url']}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando explorer...", flush=True)
        httpd.server_close()


if __name__ == "__main__":
    main()
