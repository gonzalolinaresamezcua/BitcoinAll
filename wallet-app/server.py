#!/usr/bin/env python3
"""BitcoinAll Wallet — interfaz web local conectada al nodo via RPC."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

APP_DIR = Path(__file__).resolve().parent
DATADIR = Path(os.environ.get("BITCOINALL_DATADIR", "/home/digitacode/BitcoinAll/data"))
WALLET_NAME = os.environ.get("BITCOINALL_WALLET", "primera")
RPC_HOST = os.environ.get("BITCOINALL_RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.environ.get("BITCOINALL_RPC_PORT", "8332"))
BIND_HOST = os.environ.get("BITCOINALL_WALLET_BIND", "127.0.0.1")
BIND_PORT = int(os.environ.get("BITCOINALL_WALLET_PORT", "9335"))

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
            f"No se encontró {cookie_path}. ¿Está corriendo bitcoind con -datadir={DATADIR}?"
        )
    user, password = cookie_path.read_text(encoding="utf-8").strip().split(":", 1)
    return user, password


def rpc_call(method: str, params: list | None = None, wallet: str | None = None) -> object:
    user, password = read_cookie()
    url = f"http://{RPC_HOST}:{RPC_PORT}/"
    if wallet:
        url = f"http://{RPC_HOST}:{RPC_PORT}/wallet/{wallet}"

    payload = json.dumps(
        {"jsonrpc": "1.0", "id": "btca-wallet", "method": method, "params": params or []}
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    token = f"{user}:{password}".encode("utf-8")
    import base64

    req.add_header("Authorization", "Basic " + base64.b64encode(token).decode("ascii"))

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            err = json.loads(body).get("error", {})
            raise RpcError(err.get("code", exc.code), err.get("message", body)) from exc
        except json.JSONDecodeError:
            raise RpcError(exc.code, body) from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(
            f"No se pudo conectar al nodo en {RPC_HOST}:{RPC_PORT}. "
            "Arranca bitcoind con -server y -wallet=primera."
        ) from exc

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
            if exc.code != -4:  # already loaded race
                raise


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/status")
def status():
    try:
        chain = rpc_call("getblockchaininfo")
        wallets = rpc_call("listwallets") or []
        loaded = WALLET_NAME in wallets
        if not loaded:
            try:
                ensure_wallet_loaded(WALLET_NAME)
                loaded = True
            except Exception as exc:
                return jsonify(
                    {
                        "ok": False,
                        "error": str(exc),
                        "chain": chain,
                        "wallet": WALLET_NAME,
                        "wallet_loaded": False,
                    }
                )

        balance = rpc_call("getbalance", wallet=WALLET_NAME)
        unconfirmed = rpc_call("getunconfirmedbalance", wallet=WALLET_NAME)
        info = rpc_call("getwalletinfo", wallet=WALLET_NAME)

        return jsonify(
            {
                "ok": True,
                "chain": {
                    "chain": chain.get("chain"),
                    "blocks": chain.get("blocks"),
                    "headers": chain.get("headers"),
                    "bestblockhash": chain.get("bestblockhash"),
                    "verificationprogress": chain.get("verificationprogress"),
                },
                "wallet": WALLET_NAME,
                "wallet_loaded": loaded,
                "balance": balance,
                "unconfirmed_balance": unconfirmed,
                "wallet_info": {
                    "txcount": info.get("txcount"),
                    "keypoolsize": info.get("keypoolsize"),
                    "format": info.get("format"),
                },
                "datadir": str(DATADIR),
                "rpc": f"{RPC_HOST}:{RPC_PORT}",
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503


@app.get("/api/addresses")
def addresses():
    try:
        ensure_wallet_loaded(WALLET_NAME)
        addrs = rpc_call("listreceivedbyaddress", [0, True, True], wallet=WALLET_NAME)
        return jsonify({"ok": True, "addresses": addrs})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/address/new")
def new_address():
    try:
        ensure_wallet_loaded(WALLET_NAME)
        label = (request.json or {}).get("label", "")
        addr = rpc_call("getnewaddress", [label] if label else [], wallet=WALLET_NAME)
        return jsonify({"ok": True, "address": addr})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.get("/api/transactions")
def transactions():
    try:
        ensure_wallet_loaded(WALLET_NAME)
        count = int(request.args.get("count", 25))
        txs = rpc_call("listtransactions", ["*", count, 0, True], wallet=WALLET_NAME)
        return jsonify({"ok": True, "transactions": txs})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/send")
def send():
    body = request.json or {}
    address = body.get("address", "").strip()
    amount = body.get("amount")
    comment = body.get("comment", "")

    if not address or amount is None:
        return jsonify({"ok": False, "error": "Faltan address o amount"}), 400

    try:
        ensure_wallet_loaded(WALLET_NAME)
        amount = float(amount)
        if amount <= 0:
            raise ValueError("La cantidad debe ser mayor que 0")

        txid = rpc_call(
            "sendtoaddress",
            [address, amount, comment, "", False, True, 1, "unset", False],
            wallet=WALLET_NAME,
        )
        return jsonify({"ok": True, "txid": txid})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/sign")
def sign_message():
    body = request.json or {}
    message = body.get("message", "")
    address = body.get("address", "").strip()

    if not message or not address:
        return jsonify({"ok": False, "error": "Faltan message o address"}), 400

    try:
        ensure_wallet_loaded(WALLET_NAME)
        signature = rpc_call("signmessage", [address, message], wallet=WALLET_NAME)
        return jsonify({"ok": True, "signature": signature, "address": address, "message": message})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/verify")
def verify_message():
    body = request.json or {}
    address = body.get("address", "").strip()
    signature = body.get("signature", "").strip()
    message = body.get("message", "")

    if not address or not signature or not message:
        return jsonify({"ok": False, "error": "Faltan address, signature o message"}), 400

    try:
        valid = rpc_call("verifymessage", [address, signature, message])
        return jsonify({"ok": True, "valid": bool(valid)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


def _require_export_confirm(body: dict) -> None:
    if not body.get("confirm"):
        raise ValueError(
            "Debes confirmar la exportación (confirm: true). "
            "Nunca compartas tu clave privada con nadie."
        )


@app.post("/api/backup/master")
def backup_master():
    """Exporta la clave maestra extendida (xprv) — respaldo principal de la wallet."""
    body = request.json or {}
    try:
        _require_export_confirm(body)
        ensure_wallet_loaded(WALLET_NAME)
        keys = rpc_call("gethdkeys", [{"private": True, "active_only": True}], wallet=WALLET_NAME)
        if not keys:
            raise ValueError("No se encontraron claves HD en la wallet")

        master = keys[0]
        return jsonify(
            {
                "ok": True,
                "wallet": WALLET_NAME,
                "xprv": master.get("xprv"),
                "xpub": master.get("xpub"),
                "has_private": master.get("has_private"),
                "descriptors": master.get("descriptors", []),
                "warning": "Guarda esta xprv en un lugar seguro offline. Quien la tenga controla todos tus fondos.",
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/backup/descriptors")
def backup_descriptors():
    """Exporta todos los descriptores con claves privadas."""
    body = request.json or {}
    try:
        _require_export_confirm(body)
        ensure_wallet_loaded(WALLET_NAME)
        data = rpc_call("listdescriptors", [True], wallet=WALLET_NAME)
        return jsonify(
            {
                "ok": True,
                "wallet": data.get("wallet_name", WALLET_NAME),
                "descriptors": data.get("descriptors", []),
                "warning": "Respaldo completo en formato descriptor. Importable con importdescriptors.",
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/backup/address")
def backup_address():
    """Información de respaldo para una dirección concreta."""
    body = request.json or {}
    address = body.get("address", "").strip()
    try:
        _require_export_confirm(body)
        if not address:
            raise ValueError("Falta la dirección")

        ensure_wallet_loaded(WALLET_NAME)
        info = rpc_call("getaddressinfo", [address], wallet=WALLET_NAME)
        if not info.get("ismine"):
            raise ValueError("Esta dirección no pertenece a tu wallet")

        hdkeys = rpc_call("gethdkeys", [{"private": True, "active_only": True}], wallet=WALLET_NAME)
        master_xprv = hdkeys[0].get("xprv") if hdkeys else None

        return jsonify(
            {
                "ok": True,
                "address": info.get("address"),
                "pubkey": info.get("pubkey"),
                "hdkeypath": info.get("hdkeypath"),
                "hdmasterfingerprint": info.get("hdmasterfingerprint"),
                "descriptor": info.get("desc"),
                "parent_descriptor": info.get("parent_desc"),
                "master_xprv": master_xprv,
                "warning": (
                    "Para recuperar esta dirección guarda la xprv maestra y la ruta HD. "
                    "La clave privada de cada dirección se deriva de la xprv."
                ),
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.post("/api/backup/full")
def backup_full():
    """Respaldo JSON completo: xprv + descriptores + info de wallet."""
    body = request.json or {}
    try:
        _require_export_confirm(body)
        ensure_wallet_loaded(WALLET_NAME)
        hdkeys = rpc_call("gethdkeys", [{"private": True, "active_only": True}], wallet=WALLET_NAME)
        descriptors = rpc_call("listdescriptors", [True], wallet=WALLET_NAME)
        info = rpc_call("getwalletinfo", wallet=WALLET_NAME)

        backup = {
            "format": "bitcoinall-wallet-backup-v1",
            "wallet": WALLET_NAME,
            "chain": "main",
            "created_by": "BitcoinAll Wallet",
            "wallet_info": {
                "format": info.get("format"),
                "txcount": info.get("txcount"),
            },
            "master_keys": hdkeys,
            "descriptors": descriptors.get("descriptors", []),
        }
        return jsonify({"ok": True, "backup": backup})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


if __name__ == "__main__":
    print(f"BitcoinAll Wallet → http://{BIND_HOST}:{BIND_PORT}")
    print(f"Nodo: {RPC_HOST}:{RPC_PORT}  datadir={DATADIR}  wallet={WALLET_NAME}")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
