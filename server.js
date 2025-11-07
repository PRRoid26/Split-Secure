// server.js
import fetch from "node-fetch"; // <--- IMPORTANT
import express from "express";
import sqlite3 from "sqlite3";
import path from "path";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import fs from "fs";
import os from "os";

const dbPath = path.resolve("users.db");
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser("dev-secret-change-me"));
app.use(express.static(path.join(process.cwd(), "frontend")));

// Connect DB
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("DB Error:", err.message);
  else console.log("✅ Connected to SQLite database.");
});

// Create tables if missing
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
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      senderId INTEGER NOT NULL,
      receiverId INTEGER NOT NULL,
      amount REAL NOT NULL,
      title TEXT NOT NULL,
      channel TEXT NOT NULL,
      FOREIGN KEY(senderId) REFERENCES users(id),
      FOREIGN KEY(receiverId) REFERENCES users(id)
    )
  `);
});

// Auth
function requireAuth(req, res, next) {
  const uid = req.signedCookies?.uid;
  if (!uid) return res.status(401).json({ message: "Not authenticated" });
  req.userId = Number(uid);
  next();
}

// Register
app.post("/register", (req, res) => {
  const { name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion } = req.body;
  if (!name || !surname || !username || !password || !account || !phone || !bank)
    return res.status(400).json({ message: "Missing fields" });

  db.run(
    `INSERT INTO users (name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) return res.status(400).json({ message: "Username already exists" });
        return res.status(500).json({ message: "DB error" });
      }
      res.status(201).json({ message: "User registered", id: this.lastID });
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT id, password FROM users WHERE username = ?", [username], (err, row) => {
    if (!row || row.password !== password) return res.status(401).json({ message: "Invalid login" });
    res.cookie("uid", String(row.id), { httpOnly: true, signed: true, sameSite: "lax", maxAge: 604800000 });
    res.json({ message: "OK" });
  });
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("uid");
  res.json({ message: "Logged out" });
});

// Profile
app.get("/api/me", requireAuth, (req, res) => {
  db.get("SELECT name, account, username, phone, bank FROM users WHERE id = ?", [req.userId], (err, row) => {
    if (!row) return res.status(404).json({ message: "User not found" });
    res.json(row);
  });
});

// List others for transfer dropdown
app.get("/api/users", requireAuth, (req, res) => {
  db.all("SELECT id, name, username, bank FROM users WHERE id != ? ORDER BY name", [req.userId], (err, rows) => {
    res.json(rows || []);
  });
});

// 🔥 TRANSFER — FIXED & CORRECT
app.post("/api/transfer", requireAuth, (req, res) => {
  const { toUser, amount } = req.body;
  const fromUserId = req.userId;

  db.get("SELECT * FROM users WHERE id = ?", [fromUserId], (err, sender) => {
    if (!sender) return res.status(500).json({ error: "Sender missing" });

    db.get("SELECT * FROM users WHERE username = ?", [toUser], async (err2, receiver) => {
      if (!receiver) return res.status(404).json({ error: "Receiver not found" });

      const CRYPTO = "https://nonnephritic-amiyah-calvus.ngrok-free.dev";
      let policy;

      try {
        const r = await fetch(`${CRYPTO}/select?from_bank=${sender.bank}&to_bank=${receiver.bank}`);
        policy = await r.json();
      } catch {
        return res.status(500).json({ error: "Crypto Brain unreachable — check Raspberry + ngrok." });
      }

      const mode = policy.suggested_sw_algo || "Unknown";
      const hw = policy.suggested_hw_class || "Unknown";
      const txType = policy.transaction_type || "External";
      const now = new Date().toISOString();

      db.run(
        `INSERT INTO transactions (ts, senderId, receiverId, amount, title, channel)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [now, sender.id, receiver.id, amount, `Transfer (${txType})`, `${mode} / ${hw}`],
        function (err3) {
          if (err3) return res.status(500).json({ error: "DB insert failed" });

          broadcastTx({
            id: this.lastID,
            ts: now,
            senderId: sender.id,
            receiverId: receiver.id,
            senderName: sender.name,
            receiverName: receiver.name,
            amount,
            direction: "OUT",
            channel: `${mode} / ${hw}`
          });

          res.json({ success: true, encryption_used: mode, hardware_class: hw, transaction_type: txType });
        }
      );
    });
  });
});

// 🔥 DASHBOARD TX LIST — FIXED
app.get("/api/transactions", requireAuth, (req, res) => {
  const sql = `
    SELECT t.id, t.ts, t.senderId, t.receiverId, t.amount,
           CASE WHEN senderId = ? THEN 'OUT' ELSE 'IN' END AS direction,
           us.name AS senderName, ur.name AS receiverName,
           t.channel
    FROM transactions t
    JOIN users us ON us.id = t.senderId
    JOIN users ur ON ur.id = t.receiverId
    WHERE senderId = ? OR receiverId = ?
    ORDER BY datetime(ts) DESC
  `;
  db.all(sql, [req.userId, req.userId, req.userId], (err, rows) => res.json(rows || []));
});

// 🔥 LIVE UPDATES (SSE)
const clients = new Set();
app.get("/api/tx/stream", requireAuth, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.flushHeaders();
  const client = { res, uid: req.userId };
  clients.add(client);
  req.on("close", () => clients.delete(client));
});

function broadcastTx(tx) {
  for (const c of clients) {
    if (c.uid === tx.senderId || c.uid === tx.receiverId) {
      c.res.write(`event: tx\ndata:${JSON.stringify(tx)}\n\n`);
    }
  }
}

// Routes
app.get("/", (req, res) => res.sendFile(path.join(process.cwd(), "frontend/login/login.html")));
app.get("/dashboard", requireAuth, (req, res) =>
  res.sendFile(path.join(process.cwd(), "frontend/dashboard/dashboard.html"))
);

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
