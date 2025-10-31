document.addEventListener("DOMContentLoaded", () => {
  // Utility: show error below input
  function showError(input, message) {
    if (!input) return;
    let errorEl = input.parentElement.querySelector(".error");
    if (!errorEl) {
      errorEl = document.createElement("div");
      errorEl.className = "error";
      input.parentElement.appendChild(errorEl);
    }
    errorEl.textContent = message;
  }

  // Utility: clear error
  function clearError(input) {
    if (!input) return;
    const errorEl = input.parentElement.querySelector(".error");
    if (errorEl) errorEl.textContent = "";
  }

  // ========== REGISTER ==========
  const registerForm = document.getElementById("registerForm");
  if (registerForm) {
    registerForm.addEventListener("submit", (e) => {
      e.preventDefault();
      let valid = true;

      // elements accessed by name attribute on the form
      const { name, surname, username, password, account, phone, bank, upi } = registerForm;

      if (name.value.trim().length < 2) {
        showError(name, "First name must be at least 2 characters.");
        valid = false;
      } else clearError(name);

      if (surname.value.trim().length < 2) {
        showError(surname, "Last name must be at least 2 characters.");
        valid = false;
      } else clearError(surname);

      if (username.value.trim().length < 4) {
        showError(username, "Username must be at least 4 characters.");
        valid = false;
      } else clearError(username);

      if (password.value.trim().length < 6) {
        showError(password, "Password must be at least 6 characters.");
        valid = false;
      } else clearError(password);

      if (!/^\d{10,16}$/.test(account.value.trim())) {
        showError(account, "Account number must be 10–16 digits.");
        valid = false;
      } else clearError(account);

      if (!/^\d{10}$/.test(phone.value.trim())) {
        showError(phone, "Phone number must be exactly 10 digits.");
        valid = false;
      } else clearError(phone);

      if (!bank || bank.value === "") {
        showError(bank, "Please select a bank.");
        valid = false;
      } else clearError(bank);

      if (!upi || upi.value === "") {
        showError(upi, "Please select a UPI provider.");
        valid = false;
      } else clearError(upi);

      if (valid) {
        // Save user in localStorage
        const user = {
          name: name.value.trim(),
          surname: surname.value.trim(),
          username: username.value.trim(),
          password: password.value.trim(),
          account: account.value.trim(),
          phone: phone.value.trim(),
          bank: bank.value,
          upi: upi.value
        };

        localStorage.setItem("user", JSON.stringify(user));
        console.log("Registration successful → redirecting to login.html");
        alert("Registration successful! Please login.");
        window.location.href = "login.html";
      }
    });
  }

  // ========== LOGIN ==========
  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", (e) => {
      e.preventDefault();
      let valid = true;

      const username = loginForm.username;
      const password = loginForm.password;

      if (username.value.trim().length < 4) {
        showError(username, "Username must be at least 4 characters.");
        valid = false;
      } else clearError(username);

      if (password.value.trim().length < 6) {
        showError(password, "Password must be at least 6 characters.");
        valid = false;
      } else clearError(password);

      if (valid) {
        const storedUser = JSON.parse(localStorage.getItem("user"));
        if (
          storedUser &&
          storedUser.username === username.value.trim() &&
          storedUser.password === password.value.trim()
        ) {
          console.log("Login successful → redirecting to dashboard.html");
          localStorage.setItem("loggedIn", "true");
          window.location.href = "dashboard.html";
        } else {
          showError(password, "Invalid username or password.");
        }
      }
    });
  }

  // ========== DASHBOARD ==========
  if (window.location.pathname.includes("dashboard.html")) {
    const loggedIn = localStorage.getItem("loggedIn");
    const storedUser = JSON.parse(localStorage.getItem("user"));

    if (!loggedIn || !storedUser) {
      alert("Please login first.");
      window.location.href = "login.html";
    } else {
      const nameField = document.getElementById("profileName");
      const acctField = document.getElementById("profileAcct");
      const userField = document.getElementById("profileUsername");
      const phoneField = document.getElementById("profilePhone");

      if (nameField && acctField && userField && phoneField) {
        nameField.textContent = storedUser.name + " " + storedUser.surname;
        acctField.textContent = "XXXX-XXXX-" + storedUser.account.slice(-4);
        userField.textContent = storedUser.username;
        phoneField.textContent = storedUser.phone;

        const bankField = document.getElementById("profileBank");
        const upiField = document.getElementById("profileUpi");
        if (bankField) bankField.textContent = storedUser.bank;
        if (upiField) upiField.textContent = storedUser.upi;
      }

      function showRecentLogs() {
        const recentLogsDiv = document.getElementById("recentLogs");
        if (!recentLogsDiv) return;

        let logs = JSON.parse(localStorage.getItem("transactionLogs")) || [];

        if (logs.length === 0) {
          recentLogsDiv.innerHTML = "<p>No transaction history.</p>";
          return;
        }

        let html = "";
        logs.slice(0, 3).forEach(log => {
          html += `
            <div class="subcard">
              <p>Paid ₹${log.amount} to ${log.recipient}</p>
              <small>${log.timestamp}</small>
            </div>`;
        });

        recentLogsDiv.innerHTML = html;
      }

      // Run immediately (important)
      showRecentLogs();
    }
  }

  // ========== LOGS PAGE ==========
  function showAllLogs() {
    const allLogsDiv = document.getElementById("allLogs");
    if (!allLogsDiv) return;

    let logs = JSON.parse(localStorage.getItem("transactionLogs")) || [];

    if (logs.length === 0) {
      allLogsDiv.innerHTML = "<p>No transaction history.</p>";
      return;
    }

    let html = "";
    logs.forEach((log, index) => {
      html += `
        <div class="log-card" onclick="toggleLogDetails(${index})">
          <p><strong>Paid ₹${log.amount}</strong> to ${log.recipient}</p>
          <small>${log.timestamp}</small>
          <div id="details-${index}" class="log-details" style="display:none;">
            <p><strong>From:</strong> ${log.from}</p>
            <p><strong>To:</strong> ${log.recipient}</p>
            <p><strong>Provider:</strong> ${log.provider}</p>
            <p><strong>Protocol:</strong> ${log.details.protocol}</p>
            <p><strong>Keys Exchanged:</strong> ${log.details.keysExchanged}</p>
            <p><strong>Encryption:</strong> ${log.details.encryption}</p>
            <p><strong>Decryption:</strong> ${log.details.decryption}</p>
            <p><strong>Perf:</strong> ${log.details.perf || ""}</p>
          </div>
        </div>`;
    });

    allLogsDiv.innerHTML = html;
  }

  // If on logs.html, render logs immediately
  if (window.location.pathname.includes("logs.html")) {
    showAllLogs();
  }

  // expose toggleLogDetails globally (used by onclick in generated HTML)
  window.toggleLogDetails = function(index) {
    const detailsDiv = document.getElementById(`details-${index}`);
    if (!detailsDiv) return;
    detailsDiv.style.display = (detailsDiv.style.display === "none" || detailsDiv.style.display === "") ? "block" : "none";
  };

  // Transfer simulation function — expose globally so onclick works
  window.simulateTransfer = function() {
    const logBox = document.getElementById("logBox");
    if (!logBox) return;
    logBox.innerHTML = "";

    const receiverEl = document.getElementById("receiver");
    const amountEl = document.getElementById("amount");
    const receiver = receiverEl ? receiverEl.value : "";
    const amount = amountEl ? amountEl.value || "0" : "0";

    const user = JSON.parse(localStorage.getItem("user")) || { username: "unknown", bank: "UnknownBank", upi: "UnknownUPI" };
    const senderDetails = `${user.username} [${user.bank}, ${user.upi}]`;

    let receiverDetails = "";
    let mode = "";
    let tls = "";
    let kx = "";
    let jwt = "";
    let cert = "";
    let perfNote = "";

    if (receiver === "shruti") {
      receiverDetails = "Shruti [HDFC, Paytm]";
      mode = "Hybrid (Classical + PQC)";
      tls = "TLS 1.3 (Hybrid: ECDH + Kyber)";
      kx = "Ephemeral ECDH + Kyber key exchange performed.";
      jwt = "JWT signed with HS256 + PQC signature (ML-DSA).";
      cert = "Hybrid X.509 cert with RSA + PQC (Dilithium) validated.";
      perfNote = "Time: ~150 ms | CPU usage: Medium";
    } else if (receiver === "prathamesh") {
      receiverDetails = "Prathamesh [SBI, GPay]";
      mode = "PQC-only";
      tls = "TLS 1.3 (PQC only: Kyber)";
      kx = "Kyber key exchange performed.";
      jwt = "JWT signed with PQC signature (ML-DSA).";
      cert = "PQC-only X.509 cert (Dilithium) validated.";
      perfNote = "Time: ~250 ms | CPU usage: High";
    } else if (receiver === "arnav") {
      receiverDetails = "Arnav [Saraswat Bank, BHIM UPI]";
      mode = "Classical-only";
      tls = "TLS 1.3 (Classical: ECDH)";
      kx = "Ephemeral ECDH key exchange performed.";
      jwt = "JWT signed with HS256.";
      cert = "Classical RSA X.509 cert validated.";
      perfNote = "Time: ~50 ms | CPU usage: Low";
    }

    const steps = [
      "Starting secure transaction flow...",
      `Negotiating security mode with ${receiverDetails} : ${mode}`,
      `Initiating ${tls} handshake...`,
      `${kx}`,
      "TLS handshake complete, secure channel established.",
      "Generating JWT...",
      `${jwt}`,
      "JWT issued and verified successfully.",
      "Generating digital certificate...",
      `${cert}`,
      "Certificate signed and validated.",
      `Initiating transfer: ${senderDetails} → ${receiverDetails}, Amount: ₹${amount}...`,
      "Encrypting transaction payload...",
      "Transaction encrypted and transmitted.",
      "Transfer complete successfully!",
      `Performance stats: ${perfNote}`
    ];

    // animate logs
    let i = 0;
    function nextStep() {
      if (i < steps.length) {
        logBox.innerHTML += steps[i] + "<br>";
        logBox.scrollTop = logBox.scrollHeight;
        i++;
        setTimeout(nextStep, 1200); // 1.2s delay
      }
    }
    nextStep();

    // Save transaction log to localStorage (latest first)
    const logs = JSON.parse(localStorage.getItem("transactionLogs")) || [];
    logs.unshift({
      amount,
      recipient: receiver.charAt(0).toUpperCase() + receiver.slice(1),
      timestamp: new Date().toLocaleString(),
      from: senderDetails,
      provider: receiverDetails,
      details: {
        protocol: tls,
        keysExchanged: kx,
        encryption: jwt,
        decryption: cert,
        perf: perfNote
      }
    });
    localStorage.setItem("transactionLogs", JSON.stringify(logs));
  };
}); // end DOMContentLoaded wrapper

// ========== LOGOUT ==========
function logout() {
  localStorage.removeItem("loggedIn");
  console.log("User logged out");
  window.location.href = "login.html";
}
