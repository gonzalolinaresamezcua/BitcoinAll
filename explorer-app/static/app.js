const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

function toast(msg, type = "ok") {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast ${type}`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 3500);
}

function showSearchError(msg) {
  const el = $("#search-error");
  if (!msg) {
    el.textContent = "";
    el.classList.add("hidden");
    return;
  }
  el.textContent = msg;
  el.classList.remove("hidden");
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
  if (Number.isNaN(v)) return "0.00";
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
    $("#chain-status").textContent = `${data.chain} · bloque ${data.blocks}`;
    $("#stat-blocks").textContent = data.blocks ?? "—";
    $("#stat-mempool").textContent = data.mempool?.size ?? 0;
    $("#chain-info").innerHTML = `
      <dt>Cadena</dt><dd>${data.chain}</dd>
      <dt>Mejor bloque</dt><dd>${data.bestblockhash}</dd>
      <dt>Dificultad</dt><dd>${Number(data.difficulty).toExponential(3)}</dd>
      <dt>Tamaño en disco</dt><dd>${((data.size_on_disk || 0) / 1024).toFixed(1)} KB</dd>
      <dt>Tx totales</dt><dd>${data.txstats?.txcount ?? "—"}</dd>
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

function categoryLabel(cat) {
  const map = {
    generate: "minado",
    receive: "recibido",
    send: "enviado",
    immature: "inmaduro",
    move: "movimiento",
  };
  return map[cat] || cat || "—";
}

function renderAddressPanel(data) {
  const card = $("#address-result");
  card.classList.remove("hidden");
  const displayBalance = data.balance ?? data.total_received ?? 0;
  $("#addr-balance").textContent = fmtBtca(displayBalance);
  $("#addr-display").textContent = data.address;

  const parts = [];
  if (data.utxo_count != null) parts.push(`${data.utxo_count} UTXO${data.utxo_count === 1 ? "" : "s"}`);
  if (data.tx_count != null) parts.push(`${data.tx_count} transaccion${data.tx_count === 1 ? "" : "es"}`);
  if (data.scan_height != null) parts.push(`bloque ${data.scan_height}`);
  if (data.source === "wallet") parts.push(`wallet: ${data.wallet_name || "primera"}`);
  if (data.total_received != null && Number(data.total_received) !== Number(displayBalance)) {
    parts.push(`recibido total: ${fmtBtca(data.total_received)} BTCA`);
  }
  $("#addr-meta").textContent = parts.join(" · ");

  const txRows = (data.transactions || []).map((t) => {
    const amt = Number(t.amount);
    const sign = amt >= 0 ? "+" : "";
    const cls = amt >= 0 ? "amount-in" : "amount-out";
    return `
      <tr class="clickable" data-txid="${t.txid}">
        <td class="mono link">${short(t.txid, 14)}</td>
        <td><span class="tag">${categoryLabel(t.category)}</span></td>
        <td class="${cls}">${sign}${fmtBtca(amt)} BTCA</td>
        <td>${t.blockheight ?? "—"}</td>
        <td>${t.confirmations ?? 0}</td>
        <td>${fmtTime(t.time || t.timereceived)}</td>
      </tr>`;
  }).join("");

  const utxoRows = (data.utxos || []).map((u) => `
      <tr class="clickable" data-txid="${u.txid}">
        <td class="mono link">${short(u.txid, 12)}</td>
        <td>${u.vout}</td>
        <td>${fmtBtca(u.amount)} BTCA</td>
        <td>${u.height ?? "—"}</td>
        <td>${u.confirmations ?? 0}${u.coinbase ? " · <span class='tag'>coinbase</span>" : ""}</td>
      </tr>`).join("");

  $("#address-detail").innerHTML = `
    <div class="detail-card">
      <h3>Historial de transacciones (${data.tx_count || 0})</h3>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>TXID</th><th>Tipo</th><th>Cantidad</th><th>Altura</th><th>Conf</th><th>Fecha</th>
          </tr></thead>
          <tbody>
            ${txRows || "<tr><td colspan='6'>Sin transacciones (dirección no está en wallet local)</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>
    <div class="detail-card">
      <h3>UTXOs sin gastar (${data.utxo_count || 0})</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>TXID</th><th>Vout</th><th>Cantidad</th><th>Altura</th><th>Conf</th></tr></thead>
          <tbody>
            ${utxoRows || "<tr><td colspan='5'>Sin UTXOs en esta dirección</td></tr>"}
          </tbody>
        </table>
      </div>
    </div>`;

  $("#address-detail").querySelectorAll("[data-txid]").forEach((row) => {
    row.closest("tr")?.addEventListener("click", () => showTx(row.dataset.txid));
  });
}

async function showBlock(id) {
  showSearchError("");
  $("#address-result").classList.add("hidden");
  renderDetail("<p class='hint'>Cargando bloque…</p>");
  try {
    const { block, txs_summary } = await api(`/api/block/${id}`);
    const coinbase = txs_summary.find((t) => t.coinbase);
    let coinbaseMsg = "";
    if (coinbase) {
      const tx = await api(`/api/tx/${coinbase.txid}`);
      const cb = tx.tx?.vin?.[0]?.coinbase;
      if (cb) {
        try {
          const bytes = cb.match(/.{1,2}/g).map((h) => parseInt(h, 16));
          coinbaseMsg = new TextDecoder().decode(new Uint8Array(bytes.slice(4))).replace(/\0/g, "").trim();
        } catch (_) {
          coinbaseMsg = cb;
        }
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
    showSearchError(err.message);
    toast(err.message, "error");
  }
}

async function showTx(txid) {
  showSearchError("");
  $("#address-result").classList.add("hidden");
  renderDetail("<p class='hint'>Cargando transacción…</p>");
  try {
    const { tx } = await api(`/api/tx/${txid}`);
    const totalOut = tx.vout.reduce((s, o) => s + o.value, 0);
    renderDetail(`
      <div class="detail-card">
        <h3>Transacción</h3>
        <dl class="info-grid">
          <dt>TXID</dt><dd>${tx.txid}</dd>
          <dt>Bloque</dt><dd class="link" data-block="${tx.blockhash}">${tx.blockhash}</dd>
          <dt>Hora</dt><dd>${fmtTime(tx.time)}</dd>
          <dt>Confirmaciones</dt><dd>${tx.confirmations ?? 0}</dd>
          <dt>Total salida</dt><dd>${fmtBtca(totalOut)} BTCA</dd>
          <dt>Tamaño</dt><dd>${tx.size} B · vsize ${tx.vsize}</dd>
        </dl>
      </div>
      <h2>Entradas (${tx.vin.length})</h2>
      <div class="table-wrap"><table><thead><tr><th>#</th><th>Prevout</th></tr></thead><tbody>
        ${tx.vin.map((v, i) => `
          <tr>
            <td>${i}</td>
            <td class="mono">${v.coinbase ? `coinbase: ${short(v.coinbase, 20)}` : `${short(v.txid, 10)}:${v.vout}`}</td>
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
    showSearchError(err.message);
    toast(err.message, "error");
  }
}

async function showAddress(address, options = {}) {
  const { switchToAddressTab = true } = options;
  showSearchError("");
  $("#search-input").value = address;

  if (switchToAddressTab) switchTab("address");
  renderAddressPanel({ address, balance: 0, utxo_count: 0, utxos: [], scan_height: null });
  $("#addr-meta").textContent = "Escaneando UTXOs en la blockchain…";

  try {
    const data = await api(`/api/address/${encodeURIComponent(address)}`);
    renderAddressPanel(data);
    toast(`Saldo: ${fmtBtca(data.balance)} BTCA`, "ok");
  } catch (err) {
    $("#address-result").classList.add("hidden");
    $("#address-detail").innerHTML = `<p class="hint">${err.message}</p>`;
    showSearchError(err.message);
    toast(err.message, "error");
  }
}

async function doSearch(q) {
  q = q.trim();
  if (!q) return;
  $("#search-input").value = q;
  showSearchError("");

  try {
    const data = await api(`/api/search?q=${encodeURIComponent(q)}`);
    if (data.type === "block") await showBlock(data.id);
    else if (data.type === "tx") await showTx(data.id);
    else if (data.type === "address") await showAddress(data.result.address || data.id);
  } catch (err) {
    $("#address-result").classList.add("hidden");
    showSearchError(err.message);
    toast(err.message, "error");
  }
}

$("#search-form").addEventListener("submit", (e) => {
  e.preventDefault();
  doSearch($("#search-input").value);
});

$("#copy-addr").addEventListener("click", async () => {
  const addr = $("#addr-display").textContent;
  if (!addr || addr === "—") return;
  try {
    await navigator.clipboard.writeText(addr);
    toast("Dirección copiada", "ok");
  } catch {
    toast("No se pudo copiar", "error");
  }
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
setInterval(() => {
  loadChain();
  loadBlocks(10, "#home-blocks");
}, 20000);
