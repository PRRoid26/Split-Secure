document.getElementById("registerForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  // Get form values
  const name = document.querySelector('input[name="name"]').value.trim();
  const surname = document.querySelector('input[name="surname"]').value.trim();
  const username = document.querySelector('input[name="username"]').value.trim();
  const password = document.querySelector('input[name="password"]').value.trim();
  const account = document.querySelector('input[name="account"]').value.trim();
  const phone = document.querySelector('input[name="phone"]').value.trim();
  const bank = document.querySelector('select[name="bank"]').value;

  // Basic Validation
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

  // Set encryption & hardware version based on bank
  let encryptionVersion = "";
  let hardwareVersion = "";

  switch (bank) {
    case "ICICI":
      encryptionVersion = "pqc";
      hardwareVersion = "latest";
      break;
    case "HDFC":
      encryptionVersion = "hybrid";
      hardwareVersion = "medium";
      break;
    case "SBI":
      encryptionVersion = "classic";
      hardwareVersion = "old";
      break;
    case "Saraswat Bank":
      encryptionVersion = "classic";
      hardwareVersion = "latest";
      break;
    default:
      alert("Invalid bank selected.");
      return;
  }

  // Create payload
  const payload = {
    name,
    surname,
    username,
    password,
    account,
    phone,
    bank,
    encryptionVersion,
    hardwareVersion,
  };

  try {
    const res = await fetch("/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
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
