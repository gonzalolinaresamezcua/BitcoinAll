const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

function toast(msg, type = "ok") {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast ${type}`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 3500);
}

async function api(path) {
  const res = await fetch(path);
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function switchTab(name) {
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $$(".panel").forEach((p) => p.classList.toggle("active", p.id === `panel-${name}`));
}

function short(s, n = 10) {
  if (!s || s.length <= n * 2 + 3) return s || "—";
  return `${s.slice(0, n)}…${s.slice(-n)}`;
}

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("es-ES");
}

function fmtBtca(n) {
  const v = Number(n);
  return v.toLocaleString("es-ES", { minimumFractionDigits: 2, maximumFractionDigits: 8 });
}

function blocksTable(blocks, container, onClick) {
  if (!blocks.length) {
    container.innerHTML = "<p class='hint'>Sin bloques.</p>";
    return;
  }
  container.innerHTML = `
    <table>
      <thead><tr>
        <th>Altura</th><th>Hash</th><th>Txs</th><th>Tamaño</th><th>Hora</th>
      </tr></thead>
      <tbody>
        ${blocks.map((b) => `
          <tr class="clickable" data-hash="${b.hash}" data-height="${b.height}">
            <td>${b.height}</td>
            <td class="mono">${short(b.hash, 12)}</td>
            <td>${b.nTx ?? "—"}</td>
            <td>${b.size ?? "—"} B</td>
            <td>${fmtTime(b.time)}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
  container.querySelectorAll("tr.clickable").forEach((row) => {
    row.onclick = () => onClick(row.dataset.height || row.dataset.hash);
  });
}

async function loadChain() {
  try {
    const data = await api("/api/chain");
    $("#chain-status").textContent = `main · bloque ${data.blocks}`;
    $("#header-stats").innerHTML = `
      <div class="stat-chip"><span class="label">Bloques</span><div class="value">${data.blocks}</div></div>
      <div class="stat-chip"><span class="label">Mempool</span><div class="value">${data.mempool?.size ?? 0}</div></div>
      <div class="stat-chip"><span class="label">Tx totales</span><div class="value">${data.txstats?.txcount ?? "—"}</div></div>
    `;
    $("#chain-info").innerHTML = `
      <dt>Cadena</dt><dd>${data.chain}</dd>
      <dt>Mejor bloque</dt><dd>${data.bestblockhash}</dd>
      <dt>Dificultad</dt><dd>${Number(data.difficulty).toExponential(3)}</dd>
      <dt>Tamaño en disco</dt><dd>${((data.size_on_disk || 0) / 1024).toFixed(1)} KB</dd>
      <dt>Mempool</dt><dd>${data.mempool?.size ?? 0} txs · ${((data.mempool?.bytes || 0) / 1024).toFixed(1)} KB</dd>
    `;
  } catch (err) {
    $("#chain-status").textContent = `Error: ${err.message}`;
    toast(err.message, "error");
  }
}

async function loadBlocks(limit = 15, container = "#home-blocks") {
  const box = $(container);
  box.innerHTML = "<p class='hint'>Cargando…</p>";
  try {
    const { blocks } = await api(`/api/blocks?limit=${limit}`);
    blocksTable(blocks, box, (id) => showBlock(id));
  } catch (err) {
    box.innerHTML = `<p class="hint">${err.message}</p>`;
  }
}

async function loadMempool() {
  const box = $("#mempool-table");
  box.innerHTML = "<p class='hint'>Cargando…</p>";
  try {
    const { transactions, count } = await api("/api/mempool");
    if (!count) {
      box.innerHTML = "<p class='hint'>Mempool vacío.</p>";
      return;
    }
    box.innerHTML = `
      <table>
        <thead><tr><th>TXID</th><th>Fee</th><th>Tamaño</th><th>Hora</th></tr></thead>
        <tbody>
          ${transactions.map((t) => `
            <tr class="clickable" data-txid="${t.txid}">
              <td class="mono">${short(t.txid, 14)}</td>
              <td>${t.fee != null ? fmtBtca(t.fee) : "—"}</td>
              <td>${t.size ?? "—"} B</td>
              <td>${fmtTime(t.time)}</td>
            </tr>`).join("")}
        </tbody>
      </table>`;
    box.querySelectorAll("tr.clickable").forEach((row) => {
      row.onclick = () => showTx(row.dataset.txid);
    });
  } catch (err) {
    box.innerHTML = `<p class="hint">${err.message}</p>`;
  }
}

function renderDetail(html) {
  switchTab("detail");
  $("#detail-content").innerHTML = html;
}

async function showBlock(id) {
  renderDetail("<p class='hint'>Cargando bloque…</p>");
  try {
    const { block, txs_summary, stats } = await api(`/api/block/${id}`);
    const coinbase = txs_summary.find((t) => t.coinbase);
    let coinbaseMsg = "";
    if (coinbase) {
      const tx = await api(`/api/tx/${coinbase.txid}`);
      const cb = tx.tx?.vin?.[0]?.coinbase;
      if (cb) {
        try {
          const bytes = cb.match(/.{1,2}/g).map((h) => parseInt(h, 16));
          coinbaseMsg = new TextDecoder().decode(new Uint8Array(bytes.slice(4))).replace(/\0/g, "").trim();
        } catch (_) { coinbaseMsg = cb; }
      }
    }
    renderDetail(`
      <div class="detail-card">
        <h3>Bloque #${block.height}</h3>
        <dl class="info-grid">
          <dt>Hash</dt><dd>${block.hash}</dd>
          <dt>Previo</dt><dd class="link" data-block="${block.previousblockhash}">${block.previousblockhash}</dd>
          <dt>Merkl root</dt><dd>${block.merkleroot}</dd>
          <dt>Time</dt><dd>${fmtTime(block.time)}</dd>
          <dt>Txs</dt><dd>${block.nTx}</dd>
          <dt>Tamaño</dt><dd>${block.size} B · weight ${block.weight}</dd>
          <dt>Nonce</dt><dd>${block.nonce}</dd>
          ${coinbaseMsg ? `<dt>Coinbase</dt><dd>${coinbaseMsg}</dd>` : ""}
        </dl>
      </div>
      <h2>Transacciones (${txs_summary.length})</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>TXID</th><th>Salida</th><th>In</th><th>Out</th><th>Tipo</th></tr></thead>
          <tbody>
            ${txs_summary.map((t) => `
              <tr class="clickable" data-txid="${t.txid}">
                <td class="mono">${short(t.txid, 12)}</td>
                <td>${fmtBtca(t.total_out)} BTCA</td>
                <td>${t.vin_count}</td>
                <td>${t.vout_count}</td>
                <td>${t.coinbase ? '<span class="tag">coinbase</span>' : "tx"}</td>
              </tr>`).join("")}
          </tbody>
        </table>
      </div>
    `);
    $("#detail-content").querySelectorAll("[data-block]").forEach((el) => {
      el.onclick = () => showBlock(el.dataset.block);
    });
    $("#detail-content").querySelectorAll("[data-txid]").forEach((row) => {
      row.closest("tr")?.addEventListener("click", () => showTx(row.dataset.txid));
    });
  } catch (err) {
    renderDetail(`<p class="hint">${err.message}</p>`);
    toast(err.message, "error");
  }
}

async function showTx(txid) {
  renderDetail("<p class='hint'>Cargando transacción…</p>");
  try {
    const { tx } = await api(`/api/tx/${txid}`);
    const totalOut = tx.vout.reduce((s, o) => s + o.value, 0);
    renderDetail(`
      <div class="detail-card">
        <h3>Transacción</h3>
        <dl class="info-grid">
          <dt>TXID</dt><dd>${tx.txid}</dd>
          <dt>Bloque</dt><dd class="link" data-block="${tx.blockhash}">${tx.blockhash} (#${tx.confirmations ? "confirmada" : "?"})</dd>
          <dt>Hora</dt><dd>${fmtTime(tx.time)}</dd>
          <dt>Confirmaciones</dt><dd>${tx.confirmations ?? 0}</dd>
          <dt>Total salida</dt><dd>${fmtBtca(totalOut)} BTCA</dd>
          <dt>Tamaño</dt><dd>${tx.size} B · vsize ${tx.vsize}</dd>
        </dl>
      </div>
      <h2>Entradas (${tx.vin.length})</h2>
      <div class="table-wrap"><table><thead><tr><th>#</th><th>Prevout</th><th>Valor</th></tr></thead><tbody>
        ${tx.vin.map((v, i) => `
          <tr>
            <td>${i}</td>
            <td class="mono">${v.coinbase ? `coinbase: ${short(v.coinbase, 20)}` : `${short(v.txid, 10)}:${v.vout}`}</td>
            <td>${v.coinbase ? "—" : ""}</td>
          </tr>`).join("")}
      </tbody></table></div>
      <h2>Salidas (${tx.vout.length})</h2>
      <div class="table-wrap"><table><thead><tr><th>#</th><th>Valor</th><th>Dirección</th></tr></thead><tbody>
        ${tx.vout.map((o) => `
          <tr>
            <td>${o.n}</td>
            <td>${fmtBtca(o.value)} BTCA</td>
            <td class="mono link" data-addr="${o.scriptPubKey?.address || ""}">${o.scriptPubKey?.address || o.scriptPubKey?.asm || "—"}</td>
          </tr>`).join("")}
      </tbody></table></div>
    `);
    $("#detail-content").querySelector("[data-block]")?.addEventListener("click", (e) => {
      showBlock(e.target.dataset.block);
    });
    $("#detail-content").querySelectorAll("[data-addr]").forEach((el) => {
      if (el.dataset.addr) el.onclick = () => showAddress(el.dataset.addr);
    });
  } catch (err) {
    renderDetail(`<p class="hint">${err.message}</p>`);
    toast(err.message, "error");
  }
}

async function showAddress(address) {
  renderDetail("<p class='hint'>Escaneando UTXOs…</p>");
  try {
    const data = await api(`/api/address/${encodeURIComponent(address)}`);
    renderDetail(`
      <div class="detail-card">
        <h3>Dirección</h3>
        <p class="mono">${data.address}</p>
        <p class="balance-big">${fmtBtca(data.balance)} BTCA</p>
        <dl class="info-grid">
          <dt>UTXOs</dt><dd>${data.utxo_count}</dd>
          <dt>Escaneado en bloque</dt><dd>${data.scan_height}</dd>
          ${data.wallet_info?.ismine ? "<dt>Wallet local</dt><dd>Sí (primera)</dd>" : ""}
        </dl>
      </div>
      <h2>UTXOs sin gastar</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>TXID</th><th>Vout</th><th>Cantidad</th><th>Altura</th><th>Conf</th></tr></thead>
          <tbody>
            ${(data.utxos || []).map((u) => `
              <tr class="clickable" data-txid="${u.txid}">
                <td class="mono">${short(u.txid, 12)}</td>
                <td>${u.vout}</td>
                <td>${fmtBtca(u.amount)} BTCA</td>
                <td>${u.height}</td>
                <td>${u.confirmations}${u.coinbase ? " · <span class='tag'>coinbase</span>" : ""}</td>
              </tr>`).join("") || "<tr><td colspan='5'>Sin UTXOs</td></tr>"}
          </tbody>
        </table>
      </div>
    `);
    $("#detail-content").querySelectorAll("[data-txid]").forEach((row) => {
      row.closest("tr")?.addEventListener("click", () => showTx(row.dataset.txid));
    });
  } catch (err) {
    renderDetail(`<p class="hint">${err.message}</p>`);
    toast(err.message, "error");
  }
}

async function doSearch(q) {
  q = q.trim();
  if (!q) return;
  $("#search-input").value = q;
  try {
    const data = await api(`/api/search?q=${encodeURIComponent(q)}`);
    if (data.type === "block") await showBlock(data.id);
    else if (data.type === "tx") await showTx(data.id);
    else if (data.type === "address") await showAddress(data.id);
  } catch (err) {
    toast(err.message, "error");
  }
}

$("#search-form").addEventListener("submit", (e) => {
  e.preventDefault();
  doSearch($("#search-input").value);
});

$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    switchTab(tab.dataset.tab);
    if (tab.dataset.tab === "blocks") loadBlocks(30, "#blocks-table");
    if (tab.dataset.tab === "mempool") loadMempool();
  });
});

$("#refresh-blocks").addEventListener("click", () => loadBlocks(30, "#blocks-table"));
$("#refresh-mempool").addEventListener("click", loadMempool);

loadChain();
loadBlocks(10, "#home-blocks");
setInterval(() => { loadChain(); loadBlocks(10, "#home-blocks"); }, 20000);
