// frontend/login/login.js
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("loginForm");
  if (!form) {
    console.error("Login form not found");
    return;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const formData = new FormData(form);
    const username = (formData.get("username") || "").trim();
    const password = (formData.get("password") || "").trim();

    if (!username || !password) {
      alert("Please enter both username and password.");
      return;
    }
    if (username.length < 3 || password.length < 6) {
      alert("Username or password is too short.");
      return;
    }

    try {
      const res = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ username, password })
      });

      const data = await res.json().catch(() => ({}));

      if (res.ok) {
        window.location.href = "/dashboard";
        return;
      } else if (res.status === 401) {
        alert(data.message || "Invalid username or password.");
      } else if (res.status === 400) {
        alert(data.message || "Missing or invalid input.");
      } else {
        alert(data.message || "Login failed. Please try again.");
      }
    } catch (err) {
      console.error("Login error:", err);
      alert("Network error. Please check the connection and try again.");
    }
  });
});
