document.addEventListener("DOMContentLoaded", loadBanks);

async function loadBanks() {
  try {
    const res = await fetch("/api/banks-csv");
    const text = await res.text();
    const rows = text.trim().split("\n");

    const select = document.getElementById("bank");
    select.innerHTML = `<option value="">--Choose Bank--</option>`;

    rows.forEach(line => {
      const [bankId, bankName] = line.split(",");
      const opt = document.createElement("option");
      opt.value = bankId.trim();
      opt.textContent = bankName.trim();
      select.appendChild(opt);
    });
  } catch (e) {
    console.error("Failed to load banks:", e);
    document.getElementById("bank").innerHTML =
      `<option value="">(Pi Offline)</option>`;
  }
}

document.getElementById("registerForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  const name = document.querySelector('input[name="name"]').value.trim();
  const surname = document.querySelector('input[name="surname"]').value.trim();
  const username = document.querySelector('input[name="username"]').value.trim();
  const password = document.querySelector('input[name="password"]').value.trim();
  const account = document.querySelector('input[name="account"]').value.trim();
  const phone = document.querySelector('input[name="phone"]').value.trim();
  const bank = document.querySelector('select[name="bank"]').value;

  if (!name || !surname || !username || !password || !account || !phone || !bank) {
    alert("All fields are required.");
    return;
  }

  if (!/^\d{10}$/.test(phone)) {
    alert("Phone number must be exactly 10 digits.");
    return;
  }

  if (!/^\d{8,16}$/.test(account)) {
    alert("Account number must be 8-16 digits.");
    return;
  }

  const payload = {
    name,
    surname,
    username,
    password,
    account,
    phone,
    bank,
    encryptionVersion: "auto",
    hardwareVersion: "auto",
  };

  try {
    const res = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (res.ok) {
      alert("Account created successfully!");
      window.location.href = "../login/login.html";
    } else {
      alert("Error: " + data.message);
    }
  } catch (err) {
    console.error("Request failed", err);
    alert("Something went wrong. Try again.");
  }
});
