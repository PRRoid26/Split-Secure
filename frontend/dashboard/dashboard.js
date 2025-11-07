// frontend/dashboard/dashboard.js
const CRYPTO_BRAIN = "https://nonnephritic-amiyah-calvus.ngrok-free.dev";

async function fetchMe() {
  const res = await fetch("/api/me", {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" }
  });
  if (res.status === 401) { window.location.href = "/"; return null; }
  const data = await res.json();
  document.getElementById("profileName").textContent = data.name || "";
  document.getElementById("profileAcct").textContent = data.account || "";
  document.getElementById("profileUsername").textContent = data.username || "";
  document.getElementById("profilePhone").textContent = data.phone || "";
  document.getElementById("profileBank").textContent = data.bank || "";
  return data;
}

async function fetchTransactions() {
  const res = await fetch("/api/transactions", { credentials: "same-origin" });
  if (res.status === 401) { window.location.href = "/"; return []; }
  return res.json();
}

async function fetchPolicy(senderBank, receiverBank) {
  try {
    const url = `${CRYPTO_BRAIN}/select?from_bank=${encodeURIComponent(senderBank)}&to_bank=${encodeURIComponent(receiverBank)}`;
    const res = await fetch(url, { method: "GET", headers: { "Accept": "application/json" } });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

async function enrichWithCrypto(rows) {
  for (let tx of rows) {
    const pol = await fetchPolicy(tx.senderBank, tx.receiverBank);
    if (pol) {
      tx.mode = pol.suggested_sw_algo;
      tx.hw_class = pol.suggested_hw_class;
      tx.tx_type = pol.transaction_type;
    } else {
      tx.mode = tx.mode || "Unknown";
      tx.hw_class = tx.hw_class || "Unknown";
      tx.tx_type = tx.tx_type || "Unknown";
    }
  }
  return rows;
}

function renderTxList(rows) {
  const c = document.getElementById("txContainer");
  c.innerHTML = "";
  if (!rows.length) {
    c.innerHTML = `<p class="text-muted">No transaction history.</p>`;
    return;
  }

  rows.forEach(r => {
    const incoming = r.direction === "IN";
    const title = incoming ? `Received from ${r.senderName}` : `Paid to ${r.receiverName}`;
    const amt = (incoming ? "+ " : "- ") + "₹" + Number(Math.abs(r.amount)).toLocaleString("en-IN");
    const amtClass = incoming ? "text-success" : "text-danger";
    const dateStr = new Date(r.ts).toLocaleString();
    const mode = r.mode || "Unknown";
    const hw = r.hw_class || "Unknown";
    const route = `${r.senderBank} → ${r.receiverBank}`;
    const type = r.tx_type || "Unknown";

    const card = document.createElement("div");
    card.className = "card mb-2 tx-item";
    card.innerHTML = `
      <div class="card-body py-2 px-3">
        <div class="d-flex justify-content-between align-items-center">
          <div>
            <div class="fw-semibold">${title}</div>
            <small class="text-muted">${dateStr}</small><br>
            <small class="text-primary">🔐 ${mode}</small><br>
            <small class="text-secondary">💻 ${hw} | 🧭 ${type}</small><br>
            <small class="text-secondary">🏦 ${route}</small>
          </div>
          <div class="${amtClass} fw-semibold">${amt}</div>
        </div>
      </div>
    `;
    c.appendChild(card);
  });
}

let txCache = [];

function connectSSE() {
  const src = new EventSource("/api/tx/stream");
  src.addEventListener("tx", async () => {
    txCache = await fetchTransactions();
    txCache = await enrichWithCrypto(txCache);
    renderTxList(txCache);
  });
  src.onerror = () => { try { src.close(); } catch {}; setTimeout(connectSSE, 3000); };
}

document.addEventListener("DOMContentLoaded", async () => {
  await fetchMe();
  txCache = await fetchTransactions();
  txCache = await enrichWithCrypto(txCache);
  renderTxList(txCache);
  connectSSE();
});

async function logout() {
  await fetch("/logout", { method: "POST", credentials: "same-origin" });
  window.location.href = "/";
}
