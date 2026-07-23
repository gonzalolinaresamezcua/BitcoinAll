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
    offlineBanner: document.getElementById("offlineBanner"),
    offlineHelp: document.getElementById("offlineHelp"),
    ledeText: document.getElementById("ledeText"),
    lookupForm: document.getElementById("lookupForm"),
    lookupAddress: document.getElementById("lookupAddress"),
    lookupBtn: document.getElementById("lookupBtn"),
    lookupResult: document.getElementById("lookupResult"),
    quickAddrs: document.getElementById("quickAddrs"),
    configForm: document.getElementById("configForm"),
    cfg1Url: document.getElementById("cfg1Url"),
    cfg2Url: document.getElementById("cfg2Url"),
    cfgUser: document.getElementById("cfgUser"),
    cfgPass: document.getElementById("cfgPass"),
    cfg1Wallet: document.getElementById("cfg1Wallet"),
    cfg2Wallet: document.getElementById("cfg2Wallet"),
    configStatus: document.getElementById("configStatus"),
  };

  let lastTip = "";
  let autoMine = { enabled: false };
  let lastNodes = [];

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
    lastNodes = nodes || [];
    els.nodes.innerHTML = lastNodes
      .map((n) => {
        const online = n.online
          ? `<span class="tag ok">online</span>`
          : `<span class="tag off">offline</span>`;
        const role = `<span class="tag">${n.role || "node"}</span>`;
        const chain = n.chain ? `<span class="tag">${n.chain}</span>` : "";
        const wb = n.wallet_balances;
        let walletHtml = "";
        if (wb && !wb.error) {
          walletHtml = `<div class="wallet-bal">wallet <code>${wb.wallet}</code>: <strong>${fmtBtca(
            wb.trusted
          )}</strong> gastable · ${fmtBtca(wb.immature)} inmaduro</div>`;
        } else if (wb && wb.error) {
          walletHtml = `<div class="wallet-bal warn">wallet ${wb.wallet}: ${wb.error}</div>`;
        }
        return `
        <article class="node-card" style="--accent:${n.color || "#e0a15a"}">
          <h3>${n.name || n.id}</h3>
          <div class="node-meta">${online}${role}${chain}<span class="tag">${n.proof || "sync"}</span></div>
          <div class="stats">
            <div class="stat"><span>Altura</span><strong>${n.blocks ?? "—"}</strong></div>
            <div class="stat"><span>Peers</span><strong>${n.connections ?? "—"}</strong></div>
            <div class="stat"><span>Progreso</span><strong>${
              n.verificationprogress != null
                ? (n.verificationprogress * 100).toFixed(1) + "%"
                : "—"
            }</strong></div>
          </div>
          ${walletHtml}
          <div class="addr">premio → <button type="button" class="linkish" data-addr="${
            n.reward_address || ""
          }">${n.reward_address || "—"}</button></div>
          <div class="addr">rpc → ${n.rpc_url || "—"}</div>
          ${n.error ? `<div class="addr err">${n.error}</div>` : ""}
        </article>`;
      })
      .join("");

    els.quickAddrs.innerHTML = lastNodes
      .filter((n) => n.reward_address)
      .map(
        (n) =>
          `<button type="button" class="chip" data-addr="${n.reward_address}">${n.name}: ${shortHash(
            n.reward_address
          )}</button>`
      )
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
            <small>${recipient?.node_name || "sin premio"} ·
              <button type="button" class="linkish" data-addr="${recipient?.address || ""}">${shortHash(
          recipient?.address || ""
        )}</button>
            </small>
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
    } else if (!(blocks || []).length) {
      els.blocks.innerHTML = `<p class="muted">Sin bloques: los nodos no responden por RPC.</p>`;
    }
  }

  function fillConfig(cfg) {
    if (!cfg) return;
    els.cfg1Url.value = cfg.node1?.url || "";
    els.cfg2Url.value = cfg.node2?.url || "";
    els.cfgUser.value = cfg.node1?.user || cfg.node2?.user || "";
    els.cfg1Wallet.value = cfg.node1?.wallet || "";
    els.cfg2Wallet.value = cfg.node2?.wallet || "";
  }

  function applySnapshot(snap) {
    if (!snap) return;
    renderNodes(snap.nodes);
    renderRewards(snap.rewards);
    renderBlocks(snap.blocks, snap.tip);
    fillConfig(snap.config);
    autoMine = snap.auto_mine || autoMine;
    els.autoBtn.textContent = `Auto-minado: ${autoMine.enabled ? "ON" : "OFF"}`;
    els.autoBtn.classList.toggle("on", !!autoMine.enabled);

    const online = !!snap.online && (snap.nodes || []).every((n) => n.online);
    els.offlineBanner.classList.toggle("hidden", online);
    if (!online) {
      const err = snap.error || (snap.nodes || []).map((n) => n.error).filter(Boolean)[0] || "";
      els.offlineHelp.textContent =
        (snap.help ||
          "Arranca bitcoind (demo/live/start-live.sh) en esta máquina o corrige la conexión RPC.") +
        (err ? ` Detalle: ${err}` : "");
      els.livePill.classList.remove("on");
      els.liveLabel.textContent = "Nodos offline";
    } else {
      els.livePill.classList.add("on");
      els.liveLabel.textContent = `En vivo · ${snap.chain || "chain"}`;
      els.ledeText.textContent = `Cadena ${snap.chain || ""} en vivo: validación, saldos y generación firmada.`;
    }
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

  async function lookup(address) {
    const addr = (address || "").trim();
    if (!addr) return;
    els.lookupAddress.value = addr;
    els.lookupBtn.disabled = true;
    els.lookupResult.innerHTML = `<p class="muted">Consultando ${addr}…</p>`;
    try {
      const data = await post("/api/address", { address: addr });
      const utxoRows = (data.utxos || [])
        .slice(0, 8)
        .map(
          (u) =>
            `<tr><td>${shortHash(u.txid)}</td><td>${fmtBtca(u.amount)}</td><td>${
              u.confirmations ?? "—"
            }</td><td>${u.coinbase ? "coinbase" : "tx"}</td></tr>`
        )
        .join("");
      const walletRows = (data.wallets || [])
        .map((w) => {
          if (w.error) return `<li>${w.node}/${w.wallet}: ${w.error}</li>`;
          return `<li>${w.node}/${w.wallet}: ${w.ismine ? "propia" : "externa"} · recibido ${fmtBtca(
            w.received
          )}</li>`;
        })
        .join("");
      els.lookupResult.innerHTML = `
        <div class="lookup-card">
          <div class="lookup-addr">${data.address}</div>
          ${data.known_as ? `<div class="tag ok">${data.known_as}</div>` : ""}
          <div class="stats lookup-stats">
            <div class="stat"><span>Total</span><strong>${fmtBtca(data.total_btca)}</strong></div>
            <div class="stat"><span>Gastable</span><strong>${fmtBtca(data.spendable_btca)}</strong></div>
            <div class="stat"><span>Inmaduro</span><strong>${fmtBtca(data.immature_btca)}</strong></div>
            <div class="stat"><span>UTXOs</span><strong>${data.utxo_count}</strong></div>
          </div>
          ${walletRows ? `<ul class="wallet-hits">${walletRows}</ul>` : ""}
          <table class="reward-table">
            <thead><tr><th>Tx</th><th>Monto</th><th>Conf</th><th>Tipo</th></tr></thead>
            <tbody>${utxoRows || `<tr><td colspan="4">Sin UTXOs</td></tr>`}</tbody>
          </table>
        </div>`;
      pushFeed(`Saldo ${shortHash(addr)}: ${fmtBtca(data.total_btca)}`, "#2bb5a0");
    } catch (err) {
      els.lookupResult.innerHTML = `<p class="err">Error: ${err.message}</p>`;
      pushFeed(`Consulta fallida: ${err.message}`, "#e8715a");
    } finally {
      els.lookupBtn.disabled = false;
    }
  }

  els.lookupForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    lookup(els.lookupAddress.value);
  });

  document.body.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-addr]");
    if (!btn) return;
    const addr = btn.getAttribute("data-addr");
    if (addr) lookup(addr);
  });

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

  els.configForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    els.configStatus.textContent = "Reconectando…";
    try {
      const body = {
        password: els.cfgPass.value || undefined,
        node1: {
          url: els.cfg1Url.value.trim(),
          user: els.cfgUser.value.trim(),
          password: els.cfgPass.value || undefined,
          wallet: els.cfg1Wallet.value.trim(),
        },
        node2: {
          url: els.cfg2Url.value.trim(),
          user: els.cfgUser.value.trim(),
          password: els.cfgPass.value || undefined,
          wallet: els.cfg2Wallet.value.trim(),
        },
      };
      const res = await post("/api/config", body);
      if (res.snapshot) applySnapshot(res.snapshot);
      els.configStatus.textContent = "RPC actualizado.";
      pushFeed("Configuración RPC actualizada", "#e0a15a");
      els.cfgPass.value = "";
    } catch (err) {
      els.configStatus.textContent = `Error: ${err.message}`;
    }
  });

  function connectEvents() {
    const es = new EventSource("/api/events");
    es.onopen = () => {
      /* pill updated from snapshot online state */
    };
    es.onerror = () => {
      els.livePill.classList.remove("on");
      els.liveLabel.textContent = "Reconectando…";
    };
    es.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.event === "snapshot") applySnapshot(msg.data);
        if (msg.event === "status" && msg.data?.nodes) renderNodes(msg.data.nodes);
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
        /* ignore */
      }
    };
  }

  async function bootstrap() {
    try {
      const res = await fetch("/api/snapshot");
      const snap = await res.json();
      applySnapshot(snap);
      pushFeed("Explorador listo", "#e0a15a");
    } catch (err) {
      els.mineStatus.textContent = `No hay snapshot: ${err.message}`;
      els.offlineBanner.classList.remove("hidden");
    }
    connectEvents();
  }

  bootstrap();
})();
