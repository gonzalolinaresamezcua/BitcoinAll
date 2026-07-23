(() => {
  const els = {
    nodes: document.getElementById("nodes"),
    blocks: document.getElementById("blocks"),
    rewardBars: document.getElementById("rewardBars"),
    rewardRows: document.getElementById("rewardRows"),
    rewardTotal: document.getElementById("rewardTotal"),
    feed: document.getElementById("feed"),
    livePill: document.getElementById("livePill"),
    liveLabel: document.getElementById("liveLabel"),
    mineBtn: document.getElementById("mineBtn"),
    autoBtn: document.getElementById("autoBtn"),
    mineTarget: document.getElementById("mineTarget"),
    mineCount: document.getElementById("mineCount"),
    mineStatus: document.getElementById("mineStatus"),
    tipMeta: document.getElementById("tipMeta"),
  };

  let lastTip = "";
  let autoMine = { enabled: false };

  function shortHash(h) {
    if (!h) return "—";
    return `${h.slice(0, 10)}…${h.slice(-8)}`;
  }

  function fmtTime(ts) {
    try {
      return new Date(ts * 1000).toLocaleString();
    } catch {
      return String(ts);
    }
  }

  function fmtBtca(n) {
    return `${Number(n || 0).toLocaleString(undefined, {
      minimumFractionDigits: 0,
      maximumFractionDigits: 8,
    })} BTCA`;
  }

  function pushFeed(text, color) {
    const li = document.createElement("li");
    li.style.setProperty("--accent", color || "#e0a15a");
    const t = document.createElement("time");
    t.textContent = new Date().toLocaleTimeString();
    li.appendChild(t);
    li.appendChild(document.createTextNode(text));
    els.feed.prepend(li);
    while (els.feed.children.length > 40) {
      els.feed.lastChild.remove();
    }
  }

  function renderNodes(nodes) {
    els.nodes.innerHTML = (nodes || [])
      .map((n) => {
        const online = n.online
          ? `<span class="tag ok">online</span>`
          : `<span class="tag off">offline</span>`;
        const role = `<span class="tag">${n.role || "node"}</span>`;
        return `
        <article class="node-card" style="--accent:${n.color || "#e0a15a"}">
          <h3>${n.name || n.id}</h3>
          <div class="node-meta">${online}${role}<span class="tag">${n.proof || "sync"}</span></div>
          <div class="stats">
            <div class="stat"><span>Altura</span><strong>${n.blocks ?? "—"}</strong></div>
            <div class="stat"><span>Peers</span><strong>${n.connections ?? "—"}</strong></div>
            <div class="stat"><span>Progreso</span><strong>${
              n.verificationprogress != null
                ? (n.verificationprogress * 100).toFixed(1) + "%"
                : "—"
            }</strong></div>
          </div>
          <div class="addr">premio → ${n.reward_address || "—"}</div>
          ${n.error ? `<div class="addr" style="color:#e8715a">${n.error}</div>` : ""}
        </article>`;
      })
      .join("");
  }

  function renderRewards(rewards) {
    const rows = rewards?.nodes || [];
    const total = rewards?.total_btca || 0;
    els.rewardTotal.textContent = fmtBtca(total);
    els.rewardBars.innerHTML = rows
      .map((r) => {
        const pct = Math.round((r.share || 0) * 1000) / 10;
        return `
        <div class="reward-row">
          <header>
            <span>${r.name}</span>
            <span>${fmtBtca(r.total_btca)} · ${pct}%</span>
          </header>
          <div class="bar"><i style="--accent:${r.color};background:${r.color};width:${pct}%"></i></div>
        </div>`;
      })
      .join("");
    els.rewardRows.innerHTML = rows
      .map(
        (r) => `
      <tr>
        <td style="color:${r.color}">${r.name}</td>
        <td>${r.blocks_won}</td>
        <td>${fmtBtca(r.total_btca)}</td>
        <td>${(Math.round((r.share || 0) * 1000) / 10).toFixed(1)}%</td>
      </tr>`
      )
      .join("");
  }

  function renderBlocks(blocks, tip) {
    const freshTip = tip && tip !== lastTip;
    els.blocks.innerHTML = (blocks || [])
      .map((b, idx) => {
        const recipient = b.recipients?.[0];
        const fresh = freshTip && idx === 0 ? "fresh" : "";
        return `
        <article class="block ${fresh}">
          <div class="height">#${b.height}</div>
          <div>
            <div class="hash">${b.hash}</div>
            <div class="meta">${b.nTx} tx · ${fmtTime(b.time)} · ${shortHash(b.previousblockhash)}</div>
          </div>
          <div class="prize" style="color:${recipient?.color || "#e0a15a"}">
            ${fmtBtca(b.reward_total)}
            <small>${recipient?.node_name || "sin premio"} · ${shortHash(recipient?.address || "")}</small>
          </div>
        </article>`;
      })
      .join("");
    if (tip) {
      els.tipMeta.textContent = `tip ${shortHash(tip)} · altura ${blocks?.[0]?.height ?? "—"}`;
      if (freshTip && lastTip) {
        pushFeed(`Nuevo bloque #${blocks?.[0]?.height} · ${shortHash(tip)}`, blocks?.[0]?.recipients?.[0]?.color);
      }
      lastTip = tip;
    }
  }

  function applySnapshot(snap) {
    if (!snap) return;
    renderNodes(snap.nodes);
    renderRewards(snap.rewards);
    renderBlocks(snap.blocks, snap.tip);
    autoMine = snap.auto_mine || autoMine;
    els.autoBtn.textContent = `Auto-minado: ${autoMine.enabled ? "ON" : "OFF"}`;
    els.autoBtn.classList.toggle("on", !!autoMine.enabled);
    if (snap.error) {
      els.mineStatus.textContent = `Aviso: ${snap.error}`;
    }
  }

  async function post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  els.mineBtn.addEventListener("click", async () => {
    els.mineBtn.disabled = true;
    els.mineStatus.textContent = "Firmando y propagando bloque…";
    try {
      const count = Number(els.mineCount.value || 1);
      const target = els.mineTarget.value;
      const result = await post("/api/mine", { count, target });
      const first = result.blocks?.[0];
      els.mineStatus.textContent = `OK · ${result.count} bloque(s) → ${result.target} · ${fmtBtca(
        first?.reward_total || 0
      )}`;
      pushFeed(
        `Minado manual: ${result.count} bloque(s) premiando a ${result.target}`,
        first?.recipients?.[0]?.color
      );
    } catch (err) {
      els.mineStatus.textContent = `Error: ${err.message}`;
      pushFeed(`Error al minar: ${err.message}`, "#e8715a");
    } finally {
      els.mineBtn.disabled = false;
    }
  });

  els.autoBtn.addEventListener("click", async () => {
    try {
      const next = !autoMine.enabled;
      const state = await post("/api/automine", {
        enabled: next,
        target: els.mineTarget.value,
        interval_sec: 8,
        blocks: 1,
      });
      autoMine = state;
      els.autoBtn.textContent = `Auto-minado: ${state.enabled ? "ON" : "OFF"}`;
      els.autoBtn.classList.toggle("on", !!state.enabled);
      pushFeed(`Auto-minado ${state.enabled ? "activado" : "desactivado"}`, "#2bb5a0");
    } catch (err) {
      pushFeed(`No se pudo cambiar auto-minado: ${err.message}`, "#e8715a");
    }
  });

  function connectEvents() {
    const es = new EventSource("/api/events");
    es.onopen = () => {
      els.livePill.classList.add("on");
      els.liveLabel.textContent = "En vivo";
    };
    es.onerror = () => {
      els.livePill.classList.remove("on");
      els.liveLabel.textContent = "Reconectando…";
    };
    es.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.event === "snapshot") applySnapshot(msg.data);
        if (msg.event === "mined") {
          const b = msg.data.blocks?.[0];
          pushFeed(
            `Premio repartido a ${msg.data.target}: ${fmtBtca(b?.reward_total || 0)}`,
            b?.recipients?.[0]?.color
          );
        }
        if (msg.event === "automine") {
          autoMine = msg.data;
          els.autoBtn.textContent = `Auto-minado: ${autoMine.enabled ? "ON" : "OFF"}`;
          els.autoBtn.classList.toggle("on", !!autoMine.enabled);
        }
        if (msg.event === "error") {
          pushFeed(msg.data.message || "error", "#e8715a");
        }
      } catch {
        /* ignore parse errors */
      }
    };
  }

  async function bootstrap() {
    try {
      const res = await fetch("/api/snapshot");
      const snap = await res.json();
      applySnapshot(snap);
      pushFeed("Explorador conectado a BitcoinAll", "#e0a15a");
    } catch (err) {
      els.mineStatus.textContent = `No hay snapshot: ${err.message}`;
    }
    connectEvents();
  }

  bootstrap();
})();
