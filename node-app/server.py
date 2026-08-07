#!/usr/bin/env python3
"""BitcoinAll Node Monitor — peers P2P conectados y red local."""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from flask import Flask, jsonify, send_from_directory

APP_DIR = Path(__file__).resolve().parent
DATADIR = Path(os.environ.get("BITCOINALL_DATADIR", "/home/digitacode/BitcoinAll/data"))
RPC_HOST = os.environ.get("BITCOINALL_RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.environ.get("BITCOINALL_RPC_PORT", "8332"))
BIND_HOST = os.environ.get("BITCOINALL_NODE_BIND", "127.0.0.1")
BIND_PORT = int(os.environ.get("BITCOINALL_NODE_PORT", "9337"))

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
            f"No se encontró {cookie_path}. Arranca bitcoind con -datadir={DATADIR} -server -listen=1"
        )
    user, password = cookie_path.read_text(encoding="utf-8").strip().split(":", 1)
    return user, password


def rpc_call(method: str, params: list | None = None) -> object:
    user, password = read_cookie()
    url = f"http://{RPC_HOST}:{RPC_PORT}/"
    payload = json.dumps(
        {"jsonrpc": "1.0", "id": "btca-node", "method": method, "params": params or []}
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
        with urllib.request.urlopen(req, timeout=60) as resp:
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


def fmt_duration(seconds: float | int | None) -> str | None:
    if seconds is None:
        return None
    s = int(max(0, seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    h, rem = divmod(s, 3600)
    return f"{h}h {rem // 60}m"


def enrich_peer(peer: dict) -> dict:
    now = int(time.time())
    conntime = peer.get("conntime") or 0
    connected_for = now - conntime if conntime else None

    ping_ms = peer.get("pingtime")
    if ping_ms is not None:
        ping_ms = round(float(ping_ms) * 1000, 1)

    minping_ms = peer.get("minping")
    if minping_ms is not None:
        minping_ms = round(float(minping_ms) * 1000, 1)

    return {
        **peer,
        "connected_for_sec": connected_for,
        "connected_for": fmt_duration(connected_for),
        "ping_ms": ping_ms,
        "minping_ms": minping_ms,
        "direction": "Entrante" if peer.get("inbound") else "Saliente",
        "client": (peer.get("subver") or "desconocido").strip("/"),
        "services_list": peer.get("servicesnames") or [],
        "permissions_list": peer.get("permissions") or [],
        "traffic_sent_kb": round((peer.get("bytessent") or 0) / 1024, 1),
        "traffic_recv_kb": round((peer.get("bytesrecv") or 0) / 1024, 1),
        "fee_filter_btca_kvb": peer.get("minfeefilter"),
        "lastsend_ago": fmt_duration(now - peer["lastsend"]) if peer.get("lastsend") else None,
        "lastrecv_ago": fmt_duration(now - peer["lastrecv"]) if peer.get("lastrecv") else None,
    }


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/overview")
def overview():
    try:
        network = rpc_call("getnetworkinfo") or {}
        chain = rpc_call("getblockchaininfo") or {}
        totals = rpc_call("getnettotals") or {}
        count = rpc_call("getconnectioncount") or 0
        peers = rpc_call("getpeerinfo") or []

        inbound = sum(1 for p in peers if p.get("inbound"))
        outbound = len(peers) - inbound

        total_tx_bytes = totals.get("totalbytesrecv", 0) + totals.get("totalbytessent", 0)
        uptime = totals.get("uptime")

        return jsonify(
            {
                "ok": True,
                "connections": count,
                "connections_in": network.get("connections_in", inbound),
                "connections_out": network.get("connections_out", outbound),
                "networkactive": network.get("networkactive", False),
                "localrelay": network.get("localrelay", True),
                "version": network.get("version"),
                "subversion": (network.get("subversion") or "").strip("/"),
                "protocolversion": network.get("protocolversion"),
                "localservicesnames": network.get("localservicesnames") or [],
                "networks": network.get("networks") or [],
                "timeoffset": network.get("timeoffset"),
                "relayfee": network.get("relayfee"),
                "chain": chain.get("chain"),
                "blocks": chain.get("blocks"),
                "headers": chain.get("headers"),
                "verificationprogress": chain.get("verificationprogress"),
                "initialblockdownload": chain.get("initialblockdownload"),
                "net_totals": {
                    "totalbytesrecv": totals.get("totalbytesrecv", 0),
                    "totalbytessent": totals.get("totalbytessent", 0),
                    "total_mb": round(total_tx_bytes / (1024 * 1024), 2),
                    "uptime": uptime,
                    "uptime_human": fmt_duration(uptime),
                },
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503


@app.get("/api/peers")
def peers():
    try:
        raw = rpc_call("getpeerinfo") or []
        enriched = [enrich_peer(p) for p in raw]
        enriched.sort(key=lambda p: (not p.get("inbound"), p.get("addr") or ""))
        inbound = sum(1 for p in enriched if p.get("inbound"))
        return jsonify(
            {
                "ok": True,
                "count": len(enriched),
                "inbound": inbound,
                "outbound": len(enriched) - inbound,
                "peers": enriched,
            }
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503


@app.get("/api/peers/<int:peer_id>")
def peer_detail(peer_id: int):
    try:
        raw = rpc_call("getpeerinfo") or []
        match = next((p for p in raw if p.get("id") == peer_id), None)
        if not match:
            return jsonify({"ok": False, "error": f"Peer {peer_id} no encontrado"}), 404
        return jsonify({"ok": True, "peer": enrich_peer(match)})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503


@app.get("/api/banned")
def banned():
    try:
        rows = rpc_call("listbanned") or []
        return jsonify({"ok": True, "count": len(rows), "banned": rows})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503


if __name__ == "__main__":
    print(f"BitcoinAll Node Monitor → http://{BIND_HOST}:{BIND_PORT}")
    print(f"Nodo: {RPC_HOST}:{RPC_PORT}  datadir={DATADIR}")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
