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
WALLET_NAME = os.environ.get("BITCOINALL_WALLET", "primera")

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
# btca1 bech32 + legacy AG/B prefixes used in BitcoinAll
ADDR_RE = re.compile(
    r"^(btca1[a-z0-9]{20,87}|[AG][a-km-zA-HJ-NP-Z1-9]{25,34}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$",
    re.IGNORECASE,
)

app = Flask(__name__, static_folder=str(APP_DIR / "static"), static_url_path="")


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def normalize_query(q: str) -> str:
    q = q.strip()
    if q.lower().startswith("btca1"):
        return q.lower()
    return q


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


def ensure_wallet_loaded(name: str) -> None:
    wallets = rpc_call("listwallets") or []
    if name not in wallets:
        try:
            rpc_call("loadwallet", [name])
        except RpcError as exc:
            if exc.code != -4:
                raise


def fetch_wallet_transactions(address: str, wallet: str) -> list[dict]:
    """Pagina listtransactions y filtra por dirección."""
    rows: list[dict] = []
    skip = 0
    batch = 500
    while True:
        chunk = rpc_call("listtransactions", ["*", batch, skip, True], wallet=wallet) or []
        if not chunk:
            break
        for tx in chunk:
            if tx.get("address") != address:
                continue
            rows.append(
                {
                    "txid": tx.get("txid"),
                    "amount": tx.get("amount"),
                    "category": tx.get("category"),
                    "confirmations": tx.get("confirmations"),
                    "blockheight": tx.get("blockheight"),
                    "blockhash": tx.get("blockhash"),
                    "time": tx.get("time"),
                    "timereceived": tx.get("timereceived"),
                    "label": tx.get("label"),
                    "abandoned": tx.get("abandoned", False),
                }
            )
        if len(chunk) < batch:
            break
        skip += batch
    rows.sort(key=lambda r: (r.get("blockheight") or 0, r.get("time") or 0), reverse=True)
    return rows


def wallet_address_data(canonical: str, wallet: str) -> dict:
    ensure_wallet_loaded(wallet)
    wallet_info = rpc_call("getaddressinfo", [canonical], wallet=wallet)

    unspent = rpc_call(
        "listunspent",
        [0, 9999999, [canonical], True, {"minimumAmount": 0}],
        wallet=wallet,
    ) or []
    utxos = []
    balance = 0.0
    for u in unspent:
        amount = float(u.get("amount", 0))
        balance += amount
        utxos.append(
            {
                "txid": u.get("txid"),
                "vout": u.get("vout"),
                "amount": amount,
                "height": u.get("height"),
                "confirmations": u.get("confirmations"),
                "coinbase": u.get("coinbase", False),
                "blockhash": None,
                "spendable": u.get("spendable", True),
                "safe": u.get("safe", True),
            }
        )

    received = rpc_call("getreceivedbyaddress", [canonical, 0], wallet=wallet)
    transactions = fetch_wallet_transactions(canonical, wallet)
    tip = rpc_call("getblockcount")

    return {
        "address": canonical,
        "balance": balance,
        "total_received": received,
        "utxo_count": len(utxos),
        "utxos": utxos,
        "transactions": transactions,
        "tx_count": len(transactions),
        "scan_height": tip,
        "wallet_info": wallet_info,
        "received_by_wallet": received,
        "source": "wallet",
        "wallet_name": wallet,
    }


def scan_address(address: str) -> dict:
    if not ADDR_RE.match(address):
        raise ValueError(
            "Dirección no válida. Comprueba que sea btca1… (SegWit) sin espacios ni caracteres erróneos."
        )

    validation = rpc_call("validateaddress", [address])
    if not validation.get("isvalid"):
        raise ValueError(
            f"Dirección rechazada por el nodo: «{address}». "
            "Revisa que esté copiada completa (btca1… suele tener ~42 caracteres)."
        )

    canonical = validation.get("address") or address

    wallet_info = None
    try:
        ensure_wallet_loaded(WALLET_NAME)
        wallet_info = rpc_call("getaddressinfo", [canonical], wallet=WALLET_NAME)
        if wallet_info.get("ismine"):
            return wallet_address_data(canonical, WALLET_NAME)
    except Exception:
        wallet_info = None

    try:
        scan = rpc_call("scantxoutset", ["start", [f"addr({canonical})"]])
    except RpcError as exc:
        raise ValueError(f"No se pudo escanear la dirección: {exc.message}") from exc

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

    return {
        "address": canonical,
        "balance": scan.get("total_amount", 0),
        "total_received": scan.get("total_amount", 0),
        "utxo_count": scan.get("txouts", 0),
        "utxos": utxos,
        "transactions": [],
        "tx_count": 0,
        "scan_height": scan.get("height"),
        "wallet_info": wallet_info,
        "received_by_wallet": None,
        "source": "chain",
        "wallet_name": None,
    }


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


@app.get("/api/address/<path:address>")
def address_detail(address: str):
    try:
        address = normalize_query(address)
        data = scan_address(address)
        return jsonify({"ok": True, **data})
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
    q = normalize_query(request.args.get("q", ""))
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
        if q.lower().startswith("btca1") or ADDR_RE.match(q):
            result = scan_address(q)
            return jsonify({"ok": True, "type": "address", "id": result["address"], "result": result})
        return jsonify(
            {
                "ok": False,
                "error": "No reconocido. Usa: altura, hash de bloque, txid (64 hex) o dirección btca1…",
            }
        ), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


if __name__ == "__main__":
    print(f"BitcoinAll Explorer → http://{BIND_HOST}:{BIND_PORT}")
    print(f"Nodo: {RPC_HOST}:{RPC_PORT}  datadir={DATADIR}  wallet={WALLET_NAME}")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
