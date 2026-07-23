# BitcoinAll Explorer (`demo/explorer`)

Web UI to view blocks, mine, and see reward distribution between nodes.

## Download from GitHub

Branch: `cursor/nodo-compatible-sin-minado-1b71`  
Folder: [`demo/explorer`](https://github.com/gonzalolinaresamezcua/BitcoinAll/tree/cursor/nodo-compatible-sin-minado-1b71/demo/explorer)

Or from the PR: https://github.com/gonzalolinaresamezcua/BitcoinAll/pull/1

## Open in Chrome

The UI needs the local Python server (it talks to `bitcoind` over RPC).  
**Do not** open `static/index.html` directly as `file://` — use the URL below.

```bash
# 1) Start your BitcoinAll nodes (LIVE or regtest)
#    LIVE:   demo/live/start-live.sh
#    regtest: your two local bitcoind processes

# 2) Start the explorer
cd demo/explorer
./run.sh

# 3) In Chrome open:
#    http://127.0.0.1:8080
```

`./run.sh` auto-loads `demo/live/credentials.env` if present, otherwise `demo/credentials.env`.

### Español

1. Descarga/clona la carpeta `demo/explorer` (y preferiblemente todo el repo).
2. Arranca los nodos BitcoinAll.
3. Ejecuta `./run.sh`.
4. Abre Chrome en **http://127.0.0.1:8080**.

### 中文

1. 从 GitHub 下载 `demo/explorer`。
2. 先启动 BitcoinAll 节点。
3. 运行 `./run.sh`。
4. 用 Chrome 打开 **http://127.0.0.1:8080**。

## Files

| Path | Role |
|------|------|
| `server.py` | RPC proxy + static server + live SSE |
| `static/index.html` | UI |
| `static/styles.css` | Styles |
| `static/app.js` | Front-end |
| `run.sh` | Start helper |
