const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function toast(msg, type = "ok") {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast ${type}`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 3500);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

function fmtBtca(n) {
  const v = Number(n);
  if (Number.isNaN(v)) return "0.00";
  return v.toLocaleString("es-ES", { minimumFractionDigits: 2, maximumFractionDigits: 8 });
}

function switchTab(name) {
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  $$(".panel").forEach((p) => p.classList.toggle("active", p.id === `panel-${name}`));
}

function setDisplayedAddress(address) {
  if (!address) return;
  $("#hero-address").textContent = address;
  $("#receive-address").value = address;
  if (!$("#sign-address").value) $("#sign-address").value = address;
  if (!$("#backup-address").value) $("#backup-address").value = address;
}

async function loadPrimaryAddress() {
  try {
    const { addresses } = await api("/api/addresses");
    const sorted = (addresses || [])
      .filter((a) => a.address)
      .sort((a, b) => Number(b.amount) - Number(a.amount));
    if (sorted.length) {
      setDisplayedAddress(sorted[0].address);
      return sorted[0].address;
    }
  } catch (_) {
    /* fall through */
  }

  try {
    const { address } = await api("/api/address/new", { method: "POST", body: "{}" });
    setDisplayedAddress(address);
    return address;
  } catch (err) {
    toast(err.message, "error");
    return null;
  }
}

async function loadStatus() {
  try {
    const data = await api("/api/status");
    $("#node-status").textContent = data.ok
      ? `Nodo conectado · ${data.rpc}`
      : `Error: ${data.error}`;

    $("#blocks").textContent = data.chain?.blocks ?? "—";
    $("#wallet-name").textContent = data.wallet ?? "—";
    $("#balance").textContent = fmtBtca(data.balance);

    const pending = Number(data.unconfirmed_balance || 0);
    $("#pending").textContent =
      pending !== 0
        ? `Pendiente: ${fmtBtca(pending)} BTCA`
        : "";

    const info = $("#chain-info");
    info.innerHTML = `
      <dt>Cadena</dt><dd>${data.chain?.chain ?? "—"}</dd>
      <dt>Mejor bloque</dt><dd>${data.chain?.bestblockhash ?? "—"}</dd>
      <dt>Transacciones</dt><dd>${data.wallet_info?.txcount ?? "—"}</dd>
      <dt>Datadir</dt><dd>${data.datadir ?? "—"}</dd>
    `;

    if (data.ok && $("#hero-address").textContent === "—") {
      await loadPrimaryAddress();
      await loadAddresses();
    }
  } catch (err) {
    $("#node-status").textContent = `Sin conexión: ${err.message}`;
    toast(err.message, "error");
  }
}

async function refreshReceive() {
  try {
    const { address } = await api("/api/address/new", { method: "POST", body: "{}" });
    setDisplayedAddress(address);
    await loadAddresses();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function loadAddresses() {
  try {
    const { addresses } = await api("/api/addresses");
    const list = $("#address-list");
    list.innerHTML = "";
    (addresses || [])
      .filter((a) => a.amount > 0 || a.label)
      .slice(0, 20)
      .forEach((a) => {
        const li = document.createElement("li");
        li.textContent = `${a.address} · ${fmtBtca(a.amount)} BTCA`;
        li.title = "Clic para usar esta dirección";
        li.onclick = () => {
          setDisplayedAddress(a.address);
        };
        list.appendChild(li);
      });
    if (!list.children.length) {
      list.innerHTML = "<li style='color:var(--muted)'>Sin direcciones con saldo aún</li>";
    }
  } catch (_) {
    /* optional */
  }
}

async function loadTransactions() {
  const box = $("#tx-list");
  box.innerHTML = "<p class='hint'>Cargando…</p>";
  try {
    const { transactions } = await api("/api/transactions?count=30");
    if (!transactions.length) {
      box.innerHTML = "<p class='hint'>Sin transacciones todavía.</p>";
      return;
    }
    box.innerHTML = transactions
      .map((tx) => {
        const incoming = Number(tx.amount) >= 0;
        const cls = incoming ? "in" : "out";
        const sign = incoming ? "+" : "";
        return `
          <div class="tx-item">
            <div>${tx.label || tx.category || "transferencia"}</div>
            <div class="amount ${cls}">${sign}${fmtBtca(tx.amount)} BTCA</div>
            <div class="meta">${tx.address || ""} · ${tx.confirmations ?? 0} conf · ${tx.txid?.slice(0, 16)}…</div>
          </div>`;
      })
      .join("");
  } catch (err) {
    box.innerHTML = `<p class="hint">${err.message}</p>`;
  }
}

$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    switchTab(tab.dataset.tab);
    if (tab.dataset.tab === "history") loadTransactions();
    if (tab.dataset.tab === "receive") loadAddresses();
    if (tab.dataset.tab === "backup") {
      const addr = $("#receive-address").value || $("#sign-address").value;
      if (addr && !$("#backup-address").value) $("#backup-address").value = addr;
    }
  });
});

$$("[data-tab]").forEach((btn) => {
  if (btn.classList.contains("tab")) return;
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

$("#send-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const result = $("#send-result");
  result.classList.add("hidden");
  try {
    const body = {
      address: $("#send-address").value.trim(),
      amount: $("#send-amount").value,
      comment: $("#send-comment").value.trim(),
    };
    const { txid } = await api("/api/send", { method: "POST", body: JSON.stringify(body) });
    result.textContent = `Transacción enviada\nTXID: ${txid}`;
    result.classList.remove("hidden");
    toast("Envío realizado");
    $("#send-form").reset();
    loadStatus();
  } catch (err) {
    toast(err.message, "error");
    result.textContent = err.message;
    result.classList.remove("hidden");
  }
});

$("#new-address").addEventListener("click", refreshReceive);

$("#copy-address").addEventListener("click", async () => {
  const addr = $("#receive-address").value || $("#hero-address").textContent;
  if (!addr || addr === "—") return;
  await navigator.clipboard.writeText(addr);
  toast("Dirección copiada");
});

$("#copy-hero-address").addEventListener("click", async () => {
  const addr = $("#hero-address").textContent;
  if (!addr || addr === "—") return;
  await navigator.clipboard.writeText(addr);
  toast("Dirección copiada");
});

$("#sign-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#sign-output");
  out.value = "Firmando…";
  try {
    const body = {
      address: $("#sign-address").value.trim(),
      message: $("#sign-message").value,
    };
    const { signature } = await api("/api/sign", { method: "POST", body: JSON.stringify(body) });
    out.value = signature;
    toast("Mensaje firmado");
  } catch (err) {
    out.value = "";
    toast(err.message, "error");
  }
});

$("#verify-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#verify-result");
  try {
    const body = {
      address: $("#verify-address").value.trim(),
      message: $("#verify-message").value,
      signature: $("#verify-signature").value.trim(),
    };
    const { valid } = await api("/api/verify", { method: "POST", body: JSON.stringify(body) });
    out.textContent = valid ? "✓ Firma válida" : "✗ Firma inválida";
    out.className = `verify-result ${valid ? "valid" : "invalid"}`;
  } catch (err) {
    out.textContent = err.message;
    out.className = "verify-result invalid";
  }
});

$("#refresh-txs").addEventListener("click", loadTransactions);

async function exportWithConfirm(path, confirmId, bodyExtra = {}) {
  if (!$(confirmId).checked) {
    toast("Marca la casilla de confirmación primero", "error");
    return null;
  }
  return api(path, {
    method: "POST",
    body: JSON.stringify({ confirm: true, ...bodyExtra }),
  });
}

$("#export-master").addEventListener("click", async () => {
  try {
    const data = await exportWithConfirm("/api/backup/master", "#backup-confirm-master");
    if (!data) return;
    const lines = [
      `# BitcoinAll — clave maestra wallet "${data.wallet}"`,
      `# ${data.warning}`,
      "",
      data.xprv,
      "",
      `# xpub (solo lectura): ${data.xpub}`,
    ];
    $("#master-key-output").value = lines.join("\n");
    toast("Clave maestra exportada — guárdala ya");
  } catch (err) {
    toast(err.message, "error");
  }
});

$("#copy-master").addEventListener("click", async () => {
  const text = $("#master-key-output").value;
  if (!text) return toast("Exporta la clave primero", "error");
  await navigator.clipboard.writeText(text);
  toast("Copiado al portapapeles");
});

$("#backup-address-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const address = $("#backup-address").value.trim();
    const data = await exportWithConfirm("/api/backup/address", "#backup-confirm-address", { address });
    if (!data) return;
    const out = [
      `# Dirección: ${data.address}`,
      `# ${data.warning}`,
      "",
      `Ruta HD: ${data.hdkeypath}`,
      `Pubkey:  ${data.pubkey}`,
      `Fingerprint: ${data.hdmasterfingerprint}`,
      "",
      `Descriptor:`,
      data.descriptor,
      "",
      `Descriptor padre (con xprv):`,
      data.parent_descriptor,
      "",
      `Clave maestra (xprv):`,
      data.master_xprv,
    ];
    $("#address-key-output").value = out.join("\n");
    toast("Info de dirección exportada");
  } catch (err) {
    toast(err.message, "error");
  }
});

$("#copy-address-backup").addEventListener("click", async () => {
  const text = $("#address-key-output").value;
  if (!text) return toast("Exporta primero", "error");
  await navigator.clipboard.writeText(text);
  toast("Copiado");
});

$("#export-full").addEventListener("click", async () => {
  try {
    const data = await exportWithConfirm("/api/backup/full", "#backup-confirm-full");
    if (!data) return;
    const blob = new Blob([JSON.stringify(data.backup, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bitcoinall-backup-${data.backup.wallet}-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast("Backup descargado");
  } catch (err) {
    toast(err.message, "error");
  }
});

loadStatus();
setInterval(loadStatus, 15000);
