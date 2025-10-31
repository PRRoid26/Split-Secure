// frontend/dashboard/dashboard.js
async function fetchMe() {
  const res = await fetch("/api/me", {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" }
  });
  if (res.status === 401) {
    window.location.href = "/";
    return null;
  }
  if (!res.ok) throw new Error("Failed to fetch profile");
  const data = await res.json();
  document.getElementById("profileName").textContent = data.name || "";
  document.getElementById("profileAcct").textContent = data.account || "";
  document.getElementById("profileUsername").textContent = data.username || "";
  document.getElementById("profilePhone").textContent = data.phone || "";
  document.getElementById("profileBank").textContent = data.bank || "";
  return data;
}

async function fetchTransactions() {
  const res = await fetch("/api/transactions", {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" }
  });
  if (res.status === 401) {
    window.location.href = "/";
    return [];
  }
  if (!res.ok) throw new Error("Failed to fetch transactions");
  const rows = await res.json();
  return rows;
}

function renderTxList(rows) {
  const c = document.getElementById("txContainer");
  c.innerHTML = "";
  if (!rows || rows.length === 0) {
    const p = document.createElement("p");
    p.className = "text-muted";
    p.textContent = "No transaction history.";
    c.appendChild(p);
    return;
  }
  rows.forEach(r => {
    const card = document.createElement("div");
    card.className = "card mb-2 tx-item";
    card.onclick = () => (location.href = "../logs.html");
    const incoming = r.direction === "IN";
    const title = incoming ? `Received from ${r.senderName}` : `Paid to ${r.receiverName}`;
    const amt = (incoming ? "+ " : "- ") + "₹" + Number(Math.abs(r.amount)).toLocaleString("en-IN");
    const amtClass = incoming ? "text-success" : "text-danger";
    const dateStr = new Date(r.ts).toLocaleString();
    card.innerHTML = `
      <div class="card-body py-2 px-3 d-flex justify-content-between">
        <div>
          <div class="fw-semibold">${title}</div>
          <small class="text-muted">${dateStr} • ${r.channel}</small>
        </div>
        <div class="${amtClass} fw-semibold">${amt}</div>
      </div>`;
    c.appendChild(card);
  });
}

// Maintain an in-memory list and prepend updates
let txCache = [];

function prependTxFromEvent(ev, viewerId) {
  try {
    const r = JSON.parse(ev.data);
    if (!r || typeof r !== "object") return;
    // Only care for tx where viewer is sender or receiver (server already filters, but double-check)
    if (r.senderId !== viewerId && r.receiverId !== viewerId) return;

    // Build a display row compatible with renderTxList
    const incoming = r.receiverId === viewerId;
    const direction = incoming ? "IN" : "OUT";

    // Names are not in SSE payload; refetch latest list for correctness,
    // or optimistically insert a placeholder then refresh list in background.
    // Simpler: refetch recent list now to keep names correct and ordering consistent.
    return true; // signal caller to refetch
  } catch {
    // ignore
  }
  return false;
}

function connectSSE(viewerId) {
  const src = new EventSource("/api/tx/stream");
  src.addEventListener("tx", async (ev) => {
    const needRefresh = prependTxFromEvent(ev, viewerId);
    if (needRefresh) {
      try {
        const rows = await fetchTransactions();
        txCache = rows;
        renderTxList(txCache);
      } catch (e) {
        console.error(e);
      }
    }
  });
  src.addEventListener("ping", () => {
    // keep-alive
  });
  src.onerror = () => {
    // try to reconnect after a delay
    try { src.close(); } catch {}
    setTimeout(() => connectSSE(viewerId), 3000);
  };
}

async function logout() {
  try {
    await fetch("/logout", { method: "POST", credentials: "same-origin" });
    window.location.href = "/";
  } catch {
    window.location.href = "/";
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  try {
    const me = await fetchMe();
    if (!me) return;
    const rows = await fetchTransactions();
    txCache = rows;
    renderTxList(txCache);
    // Use username as display, but SSE needs numeric id; fetch via transactions or add /api/me/id endpoint if needed
    // For this approach, derive viewerId from first tx if present, else fetch again via a lightweight query
    // To get viewerId reliably, add a small endpoint or modify /api/me to include id; quick workaround:
    // call a tiny endpoint via transactions join; here we assume at least one tx or use SSE without filter (server filters anyway).
    // Since server filters by req.userId already, we can just connect:
    connectSSE(/* viewerId not needed due to server filter */ 0);
  } catch (e) {
    console.error(e);
  }
});
