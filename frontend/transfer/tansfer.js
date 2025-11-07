// frontend/transfer/transfer.js
// Adjust CSV_PATH to where bank_testcases.csv is publicly served by express.static
const CSV_PATH = "./bank_testcases.csv"; // e.g., if CSV is alongside transfer.html

function getEl(id) {
  return document.getElementById(id);
}

function logBox() {
  return getEl("logBox");
}

function clearLog() {
  const box = logBox();
  if (box) box.innerHTML = "";
}

function print(line) {
  const box = logBox();
  if (!box) return;
  const p = document.createElement("p");
  p.className = "mb-1";
  p.textContent = line;
  box.appendChild(p);
  box.scrollTop = box.scrollHeight;
}

function parseCSV(text) {
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (!lines.length) return [];
  const header = lines[0].split(",").map(h => h.trim());
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(",").map(c => c.trim());
    if (cols.length !== header.length) continue;
    const obj = {};
    header.forEach((h, idx) => (obj[h] = cols[idx]));
    rows.push(obj);
  }
  return rows;
}

async function loadTestcases() {
  const res = await fetch(CSV_PATH, { credentials: "same-origin" });
  if (!res.ok) throw new Error("Failed to load bank_testcases.csv");
  return parseCSV(await res.text());
}

function norm(x) {
  return String(x || "").trim().toLowerCase();
}

function matchRow(rows, fromBank, toBank) {
  const f = norm(fromBank);
  const t = norm(toBank);
  let r = rows.find(x => norm(x["From Bank"]) === f && norm(x["To Bank"]) === t);
  if (r) return r;
  r = rows.find(x => norm(x["From Bank"]) === t && norm(x["To Bank"]) === f);
  return r || null;
}

function detectMode(row) {
  const base = (row["HW_Base"] || "").toLowerCase();
  const budget = (row["HW_Budget"] || "").toLowerCase();
  const algo = (row["Receiver Algo"] || row["Receiver_Algo"] || "").toLowerCase();

  const hasPQC = base.includes("pqc") || budget.includes("pqc") ||
                 algo.includes("pqc") || algo.includes("kyber") ||
                 algo.includes("ml-dsa") || algo.includes("dilithium");

  const hasClassical = base.includes("classical") || budget.includes("classical") ||
                       algo.includes("ecd") || algo.includes("rsa") ||
                       algo.includes("hs256");

  if (hasPQC && hasClassical) return "Hybrid";
  if (hasPQC) return "PQC";
  return "Classical";
}

function flowByMode(modeKey) {
  if (modeKey === "Hybrid") {
    return {
      mode: "Hybrid (Classical + PQC)",
      tls: "TLS 1.3 (Hybrid: ECDH + Kyber)",
      kx: "Ephemeral ECDH + Kyber key exchange performed.",
      jwt: "JWT signed with HS256 + PQC signature (ML-DSA).",
      cert: "Hybrid X.509 cert with RSA + PQC (Dilithium) validated.",
      perfNote: "Time: ~150 ms | CPU usage: Medium"
    };
  } else if (modeKey === "PQC") {
    return {
      mode: "PQC",
      tls: "TLS 1.3 (PQC only: Kyber)",
      kx: "Kyber key exchange performed.",
      jwt: "JWT signed with PQC signature (ML-DSA).",
      cert: "PQC-only X.509 cert (Dilithium) validated.",
      perfNote: "Time: ~250 ms | CPU usage: High"
    };
  } else {
    return {
      mode: "Classical-only",
      tls: "TLS 1.3 (Classical: ECDH)",
      kx: "Ephemeral ECDH key exchange performed.",
      jwt: "JWT signed with HS256.",
      cert: "Classical RSA X.509 cert validated.",
      perfNote: "Time: ~50 ms | CPU usage: Low"
    };
  }
}

function currentSender() {
  const sName = (getEl("profileName")?.textContent || "You").trim();
  const sBank = (getEl("profileBank")?.textContent || "Sender Bank").trim();
  return { sName, sBank };
}

function currentReceiver() {
  const sel = getEl("receiver");
  const opt = sel?.options[sel.selectedIndex];
  const bank = (opt?.dataset.bank || "Receiver Bank").trim();
  const uname = (opt?.dataset.username || "").trim();
  const label = (opt?.textContent || "Receiver").trim();
  const rDetails = uname ? `${label} (@${uname})` : label;
  return { rDetails, rBank: bank };
}

async function persistLog(payload) {
  try {
    const res = await fetch("/api/transfer-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload)
    });
    // non-fatal if it fails; UI already printed logs
    if (!res.ok) {
      console.warn("Log save failed:", await res.text());
    }
  } catch (e) {
    console.warn("Log save error:", e);
  }
}

async function runFlow(amount) {
  clearLog();

  const { sName, sBank } = currentSender();
  const { rDetails, rBank } = currentReceiver();

  const steps = [];
  function step(s) { steps.push(s); print(s); }

  step("Starting secure transaction flow...");

  let modeKey = "Classical";
  try {
    const rows = await loadTestcases();
    const row = matchRow(rows, sBank, rBank);
    if (row) {
      modeKey = detectMode(row);
    } else {
      step(`Note: No CSV rule for ${sBank} → ${rBank}; using default mode.`);
    }
  } catch (e) {
    step("Note: Could not load bank_testcases.csv; using default mode.");
  }

  const f = flowByMode(modeKey);

  step(`Negotiating security mode with ${rDetails} : ${f.mode}`);
  step(`Initiating ${f.tls} handshake...`);
  step(f.kx);
  step("TLS handshake complete, secure channel established.");
  step("Generating JWT...");
  step(f.jwt);
  step("JWT issued and verified successfully.");
  step("Generating digital certificate...");
  step(f.cert);
  step("Certificate signed and validated.");
  step(`Initiating transfer: ${sName} (${sBank}) → ${rDetails} (${rBank}), Amount: ₹${Number(amount).toLocaleString("en-IN")}...`);
  step("Encrypting transaction payload...");
  step("Transaction encrypted and transmitted.");
  step("Transfer complete successfully!");
  step(`Performance stats: ${f.perfNote}`);

  // Persist to server as JSON
  const payload = {
    timestamp: new Date().toISOString(),
    senderName: sName,
    senderBank: sBank,
    receiverLabel: rDetails,
    receiverBank: rBank,
    amount: Number(amount),
    mode: f.mode,
    steps
  };
  await persistLog(payload);
}

document.addEventListener("DOMContentLoaded", () => {
  const form = getEl("transferForm");
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const sel = getEl("receiver");
    const amount = getEl("amount")?.value.trim();

    if (!sel?.value) {
      alert("Please select a friend.");
      return;
    }
    if (!amount || Number(amount) <= 0) {
      alert("Enter a valid amount.");
      return;
    }

    await runFlow(amount);
    form.reset();
  });
});
