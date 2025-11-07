const CRYPTO_BRAIN = "https://nonnephritic-amiyah-calvus.ngrok-free.dev";

async function fetchPolicy(senderBank, receiverBank) {
  try {
    const res = await fetch(`${CRYPTO_BRAIN}/select?from_bank=${encodeURIComponent(senderBank)}&to_bank=${encodeURIComponent(receiverBank)}`, {
      method: "GET",
      headers: { "Accept": "application/json" }
    });
    return await res.json();
  } catch (err) {
    return null;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const user = JSON.parse(localStorage.getItem("user"));
  if (!user) {
    alert("Login required.");
    window.location.href = "../login/login.html";
    return;
  }

  document.getElementById("fromUserLabel").innerText = user.username;
  document.getElementById("fromBankLabel").innerText = user.bank;
});

document.getElementById("transferForm").addEventListener("submit", async function(e) {
  e.preventDefault();

  const user = JSON.parse(localStorage.getItem("user"));
  const fromUser = user.username;
  const senderBank = user.bank;

  const toUser = document.querySelector('input[name="toUser"]').value.trim();
  const amount = parseFloat(document.querySelector('input[name="amount"]').value.trim());
  const receiverBank = document.querySelector('select[name="toBank"]').value;

  if (!toUser || !amount || !receiverBank) {
    alert("All fields required.");
    return;
  }

  const policy = await fetchPolicy(senderBank, receiverBank);
  if (!policy || !policy.suggested_sw_algo) {
    alert("Crypto Brain unreachable. Try again.");
    return;
  }

  document.getElementById("encryption-info").innerHTML =
    "Encryption: " + policy.suggested_sw_algo + "<br>" +
    "Hardware: " + policy.suggested_hw_class + "<br>" +
    "Type: " + policy.transaction_type;

  const payload = {
    fromUser: fromUser,
    toUser: toUser,
    amount: amount,
    toBank: receiverBank,
    mode: policy.suggested_sw_algo,
    hw_class: policy.suggested_hw_class,
    tx_type: policy.transaction_type
  };

  try {
    const res = await fetch("/transfer", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok) {
      alert("Transfer Successful");
      window.location.reload();
    } else {
      alert(data.error || "Transfer Failed");
    }
  } catch (err) {
    alert("Network Error");
  }
});
