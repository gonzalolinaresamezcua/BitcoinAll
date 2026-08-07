#!/usr/bin/env python3
"""BitcoinAll Explorer — explorador blockchain local via RPC."""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

APP_DIR = Path(__file__).resolve().parent
DATADIR = Path(os.environ.get("BITCOINALL_DATADIR", "/home/digitacode/BitcoinAll/data"))
RPC_HOST = os.environ.get("BITCOINALL_RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.environ.get("BITCOINALL_RPC_PORT", "8332"))
BIND_HOST = os.environ.get("BITCOINALL_EXPLORER_BIND", "127.0.0.1")
BIND_PORT = int(os.environ.get("BITCOINALL_EXPLORER_PORT", "9336"))

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
ADDR_RE = re.compile(r"^(btca1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$")

app = Flask(__name__, static_folder=str(APP_DIR / "static"), static_url_path="")


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def read_cookie() -> tuple[str, str]:
    cookie_path = DATADIR / ".cookie"
    if not cookie_path.exists():
        raise FileNotFoundError(
            f"No se encontró {cookie_path}. Arranca bitcoind con -datadir={DATADIR} -server"
        )
    user, password = cookie_path.read_text(encoding="utf-8").strip().split(":", 1)
    return user, password


def rpc_call(method: str, params: list | None = None, wallet: str | None = None) -> object:
    user, password = read_cookie()
    url = f"http://{RPC_HOST}:{RPC_PORT}/"
    if wallet:
        url = f"http://{RPC_HOST}:{RPC_PORT}/wallet/{wallet}"

    payload = json.dumps(
        {"jsonrpc": "1.0", "id": "btca-explorer", "method": method, "params": params or []}
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    req.add_header(
        "Authorization",
        "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode("ascii"),
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            err = json.loads(body).get("error", {})
            raise RpcError(err.get("code", exc.code), err.get("message", body)) from exc
        except json.JSONDecodeError:
            raise RpcError(exc.code, body) from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(f"No se pudo conectar al nodo en {RPC_HOST}:{RPC_PORT}") from exc

    if data.get("error"):
        err = data["error"]
        raise RpcError(err.get("code", -1), err.get("message", "RPC error"))
    return data.get("result")


def resolve_block(identifier: str) -> dict:
    if identifier.isdigit():
        height = int(identifier)
        blockhash = rpc_call("getblockhash", [height])
    elif HEX64.match(identifier):
        blockhash = identifier
    else:
        raise ValueError("Identificador de bloque inválido (altura o hash hex)")

    block = rpc_call("getblock", [blockhash, 2])
    stats = rpc_call("getblockstats", [blockhash])
    return {"hash": blockhash, "block": block, "stats": stats}


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/chain")
def chain_info():
    try:
        info = rpc_call("getblockchaininfo")
        mempool = rpc_call("getmempoolinfo")
        txstats = rpc_call("getchaintxstats")
        return jsonify(
            {
                "ok": True,
                "chain": info.get("chain"),
                "blocks": info.get("blocks"),
                "headers": info.get("headers"),
                "bestblockhash": info.get("bestblockhash"),
                "difficulty": info.get("difficulty"),
                "mediantime": info.get("mediantime"),
                "chainwork": info.get("chainwork"),
                "size_on_disk": info.get("size_on_disk"),
                "mempool": {
                    "size": mempool.get("size"),
                    "bytes": mempool.get("bytes"),
                    "total_fee": mempool.get("total_fee"),
                },
                "txstats": {
                    "txcount": txstats.get("txcount"),
                    "txrate": txstats.get("txrate"),
                },
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503


@app.get("/api/blocks")
def recent_blocks():
    try:
        limit = min(int(request.args.get("limit", 15)), 50)
        tip = rpc_call("getblockcount")
        blocks = []
        for h in range(tip, max(tip - limit, -1), -1):
            bh = rpc_call("getblockhash", [h])
            header = rpc_call("getblockheader", [bh, True])
            blocks.append(
                {
                    "height": header.get("height"),
                    "hash": header.get("hash"),
                    "time": header.get("time"),
                    "nTx": header.get("nTx"),
                    "size": header.get("size"),
                    "weight": header.get("weight"),
                }
            )
        return jsonify({"ok": True, "tip": tip, "blocks": blocks})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/api/block/<identifier>")
def block_detail(identifier: str):
    try:
        data = resolve_block(identifier)
        block = data["block"]
        txs = []
        for tx in block.get("tx", []):
            if isinstance(tx, dict):
                vin_count = len(tx.get("vin", []))
                vout_count = len(tx.get("vout", []))
                total_out = sum(float(o.get("value", 0)) for o in tx.get("vout", []))
                coinbase = bool(tx.get("vin") and tx["vin"][0].get("coinbase"))
                txs.append(
                    {
                        "txid": tx.get("txid"),
                        "size": tx.get("size"),
                        "vsize": tx.get("vsize"),
                        "total_out": total_out,
                        "vin_count": vin_count,
                        "vout_count": vout_count,
                        "coinbase": coinbase,
                    }
                )
        return jsonify(
            {
                "ok": True,
                "hash": data["hash"],
                "block": block,
                "stats": data["stats"],
                "txs_summary": txs,
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/api/tx/<txid>")
def tx_detail(txid: str):
    if not HEX64.match(txid):
        return jsonify({"ok": False, "error": "TXID inválido (64 hex)"}), 400
    try:
        tx = rpc_call("getrawtransaction", [txid, True])
        return jsonify({"ok": True, "tx": tx})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/api/address/<address>")
def address_detail(address: str):
    if not ADDR_RE.match(address):
        return jsonify({"ok": False, "error": "Dirección inválida"}), 400
    try:
        scan = rpc_call("scantxoutset", ["start", [f"addr({address})"]])
        utxos = []
        for u in scan.get("unspents", []):
            utxos.append(
                {
                    "txid": u.get("txid"),
                    "vout": u.get("vout"),
                    "amount": u.get("amount"),
                    "height": u.get("height"),
                    "confirmations": u.get("confirmations"),
                    "coinbase": u.get("coinbase"),
                    "blockhash": u.get("blockhash"),
                }
            )

        wallet_info = None
        try:
            wallet_info = rpc_call("getaddressinfo", [address], wallet="primera")
        except Exception:
            pass

        return jsonify(
            {
                "ok": True,
                "address": address,
                "balance": scan.get("total_amount", 0),
                "utxo_count": scan.get("txouts", 0),
                "utxos": utxos,
                "scan_height": scan.get("height"),
                "wallet_info": wallet_info,
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/api/mempool")
def mempool():
    try:
        entries = rpc_call("getrawmempool", [True])
        txs = []
        for txid, meta in (entries or {}).items():
            txs.append(
                {
                    "txid": txid,
                    "size": meta.get("size"),
                    "fee": meta.get("fee"),
                    "time": meta.get("time"),
                    "height": meta.get("height"),
                }
            )
        txs.sort(key=lambda x: x.get("time") or 0, reverse=True)
        return jsonify({"ok": True, "count": len(txs), "transactions": txs[:100]})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/api/search")
def search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"ok": False, "error": "Query vacía"}), 400

    try:
        if q.isdigit():
            data = resolve_block(q)
            return jsonify({"ok": True, "type": "block", "id": q, "result": data})
        if HEX64.match(q):
            try:
                tx = rpc_call("getrawtransaction", [q, True])
                return jsonify({"ok": True, "type": "tx", "id": q, "result": tx})
            except RpcError:
                data = resolve_block(q)
                return jsonify({"ok": True, "type": "block", "id": q, "result": data})
        if ADDR_RE.match(q):
            scan = rpc_call("scantxoutset", ["start", [f"addr({q})"]])
            return jsonify(
                {
                    "ok": True,
                    "type": "address",
                    "id": q,
                    "result": {
                        "address": q,
                        "balance": scan.get("total_amount", 0),
                        "utxo_count": scan.get("txouts", 0),
                        "utxos": scan.get("unspents", []),
                    },
                }
            )
        return jsonify({"ok": False, "error": "No reconocido: usa altura, hash, txid o dirección btca1…"}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


if __name__ == "__main__":
    print(f"BitcoinAll Explorer → http://{BIND_HOST}:{BIND_PORT}")
    print(f"Nodo: {RPC_HOST}:{RPC_PORT}  datadir={DATADIR}")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
