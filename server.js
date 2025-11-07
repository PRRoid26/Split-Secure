// server.js
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const os = require("os");
const fetch = require("node-fetch");          // ✅ REQUIRED
const cors = require("cors");                // ✅ REQUIRED

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: "*", credentials: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser("dev-secret-change-me"));

// DB
const dbPath = path.resolve(__dirname, "users.db");
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("Error opening database:", err.message);
  else console.log("Connected to SQLite database.");
});

// Create tables if not exists
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      surname TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      account TEXT NOT NULL,
      phone TEXT NOT NULL,
      bank TEXT NOT NULL,
      encryptionVersion TEXT NOT NULL,
      hardwareVersion TEXT NOT NULL
    )`);

  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      senderId INTEGER NOT NULL,
      receiverId INTEGER NOT NULL,
      amount REAL NOT NULL,
      mode TEXT NOT NULL,
      hw_class TEXT NOT NULL,
      tx_type TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'UPI',
      FOREIGN KEY(senderId) REFERENCES users(id),
      FOREIGN KEY(receiverId) REFERENCES users(id)
    )`);
});

// Auth middleware
function requireAuth(req, res, next) {
  const uid = req.signedCookies?.uid;
  if (!uid) return res.status(401).json({ message: "Not authenticated" });
  req.userId = parseInt(uid, 10);
  next();
}

// REGISTER
app.post("/register", (req, res) => {
  const { name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion } = req.body;
  if (!name || !surname || !username || !password || !account || !phone || !bank) {
    return res.status(400).json({ message: "Missing required fields" });
  }
  db.run(
    `INSERT INTO users (name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion],
    function (err) {
      if (err) return res.status(400).json({ message: "Username already exists" });
      return res.status(201).json({ message: "User registered", id: this.lastID });
    }
  );
});

// LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT id, password FROM users WHERE username = ?", [username], (err, row) => {
    if (!row || row.password !== password) return res.status(401).json({ message: "Invalid credentials" });
    res.cookie("uid", String(row.id), { httpOnly: true, signed: true, sameSite: "lax", maxAge: 7*24*60*60*1000 });
    return res.json({ message: "Login OK" });
  });
});

app.post("/logout", (req, res) => {
  res.clearCookie("uid");
  res.json({ message: "Logged out" });
});

// PROFILE
app.get("/api/me", requireAuth, (req, res) => {
  db.get("SELECT name, account, username, phone, bank FROM users WHERE id = ?", [req.userId], (err, row) => {
    if (!row) return res.status(404).json({ message: "User not found" });
    res.json(row);
  });
});

// USERS LIST
app.get("/api/users", requireAuth, (req, res) => {
  db.all("SELECT id, name, username, bank, account FROM users WHERE id != ?", [req.userId], (err, rows) => {
    res.json(rows || []);
  });
});

// ✅ TRANSACTION (WITH CRYPTO BRAIN DECISION)
app.post("/api/transfer", requireAuth, (req, res) => {
  const { toUser, amount } = req.body;
  
  db.get("SELECT * FROM users WHERE id = ?", [req.userId], (err, sender) => {
    db.get("SELECT * FROM users WHERE username = ?", [toUser], async (err2, receiver) => {
      const CRYPTO_BRAIN = "https://nonnephritic-amiyah-calvus.ngrok-free.dev";

      const r = await fetch(`${CRYPTO_BRAIN}/select?from_bank=${sender.bank}&to_bank=${receiver.bank}`);
      const p = await r.json();

      db.run(
        `INSERT INTO transactions (ts, senderId, receiverId, amount, mode, hw_class, tx_type)
         VALUES (datetime('now'), ?, ?, ?, ?, ?, ?)`,
        [sender.id, receiver.id, amount, p.suggested_sw_algo, p.suggested_hw_class, p.transaction_type],
        () => res.json({ success: true, encryption_used: p.suggested_sw_algo })
      );
    });
  });
});

// GET USER TX
app.get("/api/transactions", requireAuth, (req, res) => {
  db.all(`
    SELECT t.*, us.name AS senderName, ur.name AS receiverName
    FROM transactions t
    JOIN users us ON us.id = t.senderId
    JOIN users ur ON ur.id = t.receiverId
    WHERE t.senderId = ? OR t.receiverId = ?
    ORDER BY t.id DESC
  `, [req.userId, req.userId], (err, rows) => res.json(rows));
});

// Static
app.use(express.static(path.join(__dirname, "frontend")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "frontend", "login", "login.html")));

app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
