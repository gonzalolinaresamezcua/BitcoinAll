const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

let refreshTimer = null;
let selectedPeerId = null;
let lastPeers = [];

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

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("es-ES");
}

function fmtBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / (1024 * 1024)).toFixed(2)} MB`;
}

function pct(n) {
  if (n == null) return "—";
  return `${(Number(n) * 100).toFixed(1)} %`;
}

function renderSummary(ov) {
  const net = ov.net_totals || {};
  const cards = [
    { label: "Red activa", value: ov.networkactive ? "Sí" : "No", sub: ov.localrelay ? "Relay TX activo" : "Sin relay TX" },
    { label: "Bloques", value: ov.blocks ?? "—", sub: `${ov.chain || "main"} · headers ${ov.headers ?? "—"}` },
    { label: "Sincronización", value: ov.initialblockdownload ? "IBD" : "Listo", sub: pct(ov.verificationprogress) },
    { label: "Tráfico total", value: `${net.total_mb ?? 0} MB`, sub: `↑ ${fmtBytes(net.totalbytessent)} · ↓ ${fmtBytes(net.totalbytesrecv)}` },
    { label: "Uptime nodo", value: net.uptime_human || "—", sub: `Cliente ${ov.subversion || "—"}` },
    { label: "Fee relay", value: ov.relayfee != null ? `${ov.relayfee} BTCA/kvB` : "—", sub: `Offset ${ov.timeoffset ?? 0}s` },
  ];
  $("#summary-cards").innerHTML = cards.map((c) => `
    <div class="summary-card">
      <div class="label">${c.label}</div>
      <div class="value">${c.value}</div>
      <div class="sub">${c.sub}</div>
    </div>`).join("");
}

function renderLocal(ov) {
  const rows = [
    ["Versión cliente", ov.subversion || "—"],
    ["Protocolo P2P", ov.protocolversion ?? "—"],
    ["Servicios locales", (ov.localservicesnames || []).join(", ") || "—"],
    ["Conexiones totales", ov.connections ?? 0],
    ["Entrantes / Salientes", `${ov.connections_in ?? 0} / ${ov.connections_out ?? 0}`],
    ["Red activa", ov.networkactive ? "Sí" : "No"],
    ["Relay transacciones", ov.localrelay ? "Sí" : "No"],
    ["Cadena", `${ov.chain} · bloque ${ov.blocks}`],
    ["Tráfico enviado", fmtBytes(ov.net_totals?.totalbytessent)],
    ["Tráfico recibido", fmtBytes(ov.net_totals?.totalbytesrecv)],
    ["Desfase hora", `${ov.timeoffset ?? 0} s`],
  ];
  $("#local-info").innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");

  const nets = ov.networks || [];
  if (!nets.length) {
    $("#networks-table").innerHTML = "<p class='hint'>Sin datos de interfaces.</p>";
    return;
  }
  $("#networks-table").innerHTML = `
    <table>
      <thead><tr>
        <th>Red</th><th>Alcanzable</th><th>Limitada</th><th>Proxy</th>
      </tr></thead>
      <tbody>
        ${nets.map((n) => `
          <tr>
            <td>${n.name}</td>
            <td>${n.reachable ? '<span class="badge badge-on">Sí</span>' : '<span class="badge badge-off">No</span>'}</td>
            <td>${n.limited ? "Sí" : "No"}</td>
            <td class="mono">${n.proxy || "—"}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;
}

function renderPeersTable(peers) {
  lastPeers = peers;
  const empty = $("#peers-empty");
  const wrap = $("#peers-table");

  $("#stat-peers").textContent = peers.length;
  $("#stat-in").textContent = peers.filter((p) => p.inbound).length;
  $("#stat-out").textContent = peers.filter((p) => !p.inbound).length;

  if (!peers.length) {
    empty.classList.remove("hidden");
    wrap.innerHTML = "";
    return;
  }
  empty.classList.add("hidden");

  wrap.innerHTML = `
    <table>
      <thead><tr>
        <th>ID</th><th>Dirección</th><th>Tipo</th><th>Cliente</th>
        <th>Altura sync</th><th>Ping</th><th>Conectado</th><th>Tráfico</th>
      </tr></thead>
      <tbody>
        ${peers.map((p) => `
          <tr class="clickable${selectedPeerId === p.id ? " selected" : ""}" data-id="${p.id}">
            <td>${p.id}</td>
            <td class="mono">${p.addr || "—"}</td>
            <td><span class="badge ${p.inbound ? "badge-in" : "badge-out"}">${p.direction}</span></td>
            <td class="mono">${p.client || "—"}</td>
            <td>${p.synced_blocks ?? p.startingheight ?? "—"}</td>
            <td>${p.ping_ms != null ? `${p.ping_ms} ms` : "—"}</td>
            <td>${p.connected_for || "—"}</td>
            <td>↑${p.traffic_sent_kb}K ↓${p.traffic_recv_kb}K</td>
          </tr>`).join("")}
      </tbody>
    </table>`;

  wrap.querySelectorAll("tr.clickable").forEach((row) => {
    row.onclick = () => showPeerDetail(Number(row.dataset.id));
  });
}

function renderPeerDetail(peer) {
  const services = (peer.services_list || []).map((s) => `<span class="tag">${s}</span>`).join("") || "—";
  const perms = (peer.permissions_list || []).map((s) => `<span class="tag">${s}</span>`).join("") || "—";

  const sections = [
    {
      title: "Identidad",
      rows: [
        ["ID peer", peer.id],
        ["Dirección", peer.addr],
        ["Dirección bind", peer.addrbind || "—"],
        ["Dirección local", peer.addrlocal || "—"],
        ["Red", peer.network || "—"],
        ["Tipo conexión", peer.connection_type || "—"],
        ["Transporte", peer.transport_protocol_type || "—"],
        ["Dirección", peer.direction],
      ],
    },
    {
      title: "Cliente y protocolo",
      rows: [
        ["Subversión", peer.subver || "—"],
        ["Versión P2P", peer.version ?? "—"],
        ["Servicios", services],
        ["Permisos", perms],
        ["Relay TX", peer.relaytxes ? "Sí" : "No"],
        ["Relay direcciones", peer.addr_relay_enabled ? "Sí" : "No"],
      ],
    },
    {
      title: "Sincronización",
      rows: [
        ["Altura inicial peer", peer.startingheight ?? "—"],
        ["Headers en común", peer.synced_headers ?? "—"],
        ["Bloques en común", peer.synced_blocks ?? "—"],
        ["Headers presync", peer.presynced_headers ?? "—"],
        ["Bloques en vuelo", (peer.inflight || []).join(", ") || "—"],
      ],
    },
    {
      title: "Latencia y actividad",
      rows: [
        ["Ping", peer.ping_ms != null ? `${peer.ping_ms} ms` : "—"],
        ["Ping mínimo", peer.minping_ms != null ? `${peer.minping_ms} ms` : "—"],
        ["Espera ping", peer.pingwait != null ? `${Math.round(peer.pingwait * 1000)} ms` : "—"],
        ["Desfase hora", `${peer.timeoffset ?? 0} s`],
        ["Conectado desde", fmtTime(peer.conntime)],
        ["Tiempo conectado", peer.connected_for || "—"],
        ["Último envío", `${fmtTime(peer.lastsend)} (${peer.lastsend_ago || "—"} atrás)`],
        ["Último recv", `${fmtTime(peer.lastrecv)} (${peer.lastrecv_ago || "—"} atrás)`],
        ["Último bloque", fmtTime(peer.last_block)],
        ["Última TX", fmtTime(peer.last_transaction)],
      ],
    },
    {
      title: "Tráfico",
      rows: [
        ["Bytes enviados", fmtBytes(peer.bytessent)],
        ["Bytes recibidos", fmtBytes(peer.bytesrecv)],
        ["Fee filter mín.", peer.fee_filter_btca_kvb != null ? `${peer.fee_filter_btca_kvb} BTCA/kvB` : "—"],
        ["Direcciones procesadas", peer.addr_processed ?? "—"],
        ["Direcciones rate-limited", peer.addr_rate_limited ?? "—"],
        ["Compact blocks HB →", peer.bip152_hb_to ? "Sí" : "No"],
        ["Compact blocks HB ←", peer.bip152_hb_from ? "Sí" : "No"],
      ],
    },
  ];

  $("#peer-detail").innerHTML = `
    <div class="detail-card">
      <h3>Peer #${peer.id} · ${peer.addr || "sin dirección"}</h3>
      <p class="hint">${peer.client} · ${peer.direction} · ${peer.network || "—"}</p>
    </div>
    ${sections.map((sec) => `
      <div class="detail-card">
        <h3>${sec.title}</h3>
        <dl class="info-grid">
          ${sec.rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}
        </dl>
      </div>`).join("")}`;

  switchTab("detail");
}

function showPeerDetail(id) {
  selectedPeerId = id;
  const peer = lastPeers.find((p) => p.id === id);
  if (peer) {
    renderPeersTable(lastPeers);
    renderPeerDetail(peer);
  }
}

async function loadBanned() {
  try {
    const data = await api("/api/banned");
    const rows = data.banned || [];
    const wrap = $("#banned-table");
    if (!rows.length) {
      wrap.innerHTML = "<p class='hint'>No hay direcciones baneadas.</p>";
      return;
    }
    wrap.innerHTML = `
      <table>
        <thead><tr><th>Subnet</th><th>Hasta</th><th>Motivo</th><th>Tiempo ban (s)</th></tr></thead>
        <tbody>
          ${rows.map((b) => `
            <tr>
              <td class="mono">${b.address || "—"}</td>
              <td>${b.banned_until ? fmtTime(b.banned_until) : "Permanente"}</td>
              <td>${b.ban_reason || "—"}</td>
              <td>${b.ban_created != null ? Math.round(b.ban_created) : "—"}</td>
            </tr>`).join("")}
        </tbody>
      </table>`;
  } catch (e) {
    $("#banned-table").innerHTML = `<p class="hint">Error: ${e.message}</p>`;
  }
}

async function refreshAll() {
  try {
    const [ov, peersData] = await Promise.all([api("/api/overview"), api("/api/peers")]);
    const status = ov.networkactive
      ? `Red activa · ${ov.connections} peer${ov.connections === 1 ? "" : "s"} · bloque ${ov.blocks}`
      : `Red pausada · bloque ${ov.blocks}`;
    $("#node-status").textContent = status;
    renderSummary(ov);
    renderLocal(ov);
    renderPeersTable(peersData.peers || []);
    if (selectedPeerId != null) {
      const p = (peersData.peers || []).find((x) => x.id === selectedPeerId);
      if (p) renderPeerDetail(p);
    }
    await loadBanned();
  } catch (e) {
    $("#node-status").textContent = "Sin conexión al nodo local";
    toast(e.message, "error");
  }
}

function setupAutoRefresh() {
  clearInterval(refreshTimer);
  if ($("#auto-refresh").checked) {
    refreshTimer = setInterval(refreshAll, 10000);
  }
}

$$(".tab").forEach((tab) => {
  tab.onclick = () => switchTab(tab.dataset.tab);
});

$("#refresh-btn").onclick = () => refreshAll().then(() => toast("Actualizado"));
$("#auto-refresh").onchange = setupAutoRefresh;

refreshAll();
setupAutoRefresh();
