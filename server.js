// server.js
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const os = require("os");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser("dev-secret-change-me")); // signed cookies

// DB
const dbPath = path.resolve(__dirname, "users.db");
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("Error opening database:", err.message);
  else console.log("Connected to SQLite database.");
});

// Create tables if not exists
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
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
    )`,
    (err) => {
      if (err) console.error("Table creation error (users):", err.message);
    }
  );

  db.run(
    `CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      senderId INTEGER NOT NULL,
      receiverId INTEGER NOT NULL,
      amount REAL NOT NULL,
      direction TEXT NOT NULL,      -- 'IN' or 'OUT' relative to the viewer, computed per query
      title TEXT NOT NULL,
      channel TEXT NOT NULL,        -- e.g., 'UPI','IMPS','NEFT'
      FOREIGN KEY(senderId) REFERENCES users(id),
      FOREIGN KEY(receiverId) REFERENCES users(id)
    )`,
    (err) => {
      if (err) console.error("Table creation error (transactions):", err.message);
    }
  );
});

// Auth middleware
function requireAuth(req, res, next) {
  const uid = req.signedCookies?.uid;
  if (!uid) return res.status(401).json({ message: "Not authenticated" });
  const val = parseInt(uid, 10);
  if (Number.isNaN(val)) {
    res.clearCookie("uid");
    return res.status(401).json({ message: "Not authenticated" });
  }
  req.userId = val;
  next();
}

// Simple login/register/profile
app.post("/register", (req, res) => {
  const {
    name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion,
  } = req.body;

  if (!name || !surname || !username || !password || !account || !phone || !bank || !encryptionVersion || !hardwareVersion) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const sql = `INSERT INTO users
    (name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  db.run(sql,
    [name, surname, username, password, account, phone, bank, encryptionVersion, hardwareVersion],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE constraint failed")) {
          return res.status(400).json({ message: "Username already exists" });
        }
        console.error("Insert error:", err.message);
        return res.status(500).json({ message: "Database error" });
      }
      return res.status(201).json({ message: "User registered successfully", id: this.lastID });
    });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Missing username or password" });

  const sql = "SELECT id, username, password FROM users WHERE username = ?";
  db.get(sql, [username], (err, row) => {
    if (err) {
      console.error("Query error:", err.message);
      return res.status(500).json({ message: "Database error" });
    }
    if (!row) return res.status(401).json({ message: "Invalid credentials" });

    const ok = password === row.password; // NOTE: replace with bcrypt soon
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    res.cookie("uid", String(row.id), {
      httpOnly: true,
      signed: true,
      sameSite: "lax",
      // secure: true, // on HTTPS
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    return res.status(200).json({ message: "Login successful", id: row.id });
  });
});

app.post("/logout", (req, res) => {
  res.clearCookie("uid");
  res.status(200).json({ message: "Logged out" });
});

app.get("/api/me", requireAuth, (req, res) => {
  const sql = "SELECT name, account, username, phone, bank FROM users WHERE id = ?";
  db.get(sql, [req.userId], (err, row) => {
    if (err) {
      console.error("Profile query error:", err.message);
      return res.status(500).json({ message: "Database error" });
    }
    if (!row) {
      res.clearCookie("uid");
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json(row);
  });
});

app.get("/api/users", requireAuth, (req, res) => {
  const sql = "SELECT id, name, username, bank, account, phone FROM users WHERE id != ? ORDER BY name ASC";
  db.all(sql, [req.userId], (err, rows) => {
    if (err) {
      console.error("Users list query error:", err.message);
      return res.status(500).json({ message: "Database error" });
    }
    return res.status(200).json(rows || []);
  });
});

// Save transaction log JSONL (existing)
app.post("/api/transfer-log", requireAuth, (req, res) => {
  try {
    const {
      timestamp, senderName, senderBank, receiverLabel, receiverBank,
      amount, mode, steps
    } = req.body || {};
    if (!timestamp || !senderName || !senderBank || !receiverLabel || !receiverBank ||
        typeof amount !== "number" || !mode || !Array.isArray(steps)) {
      return res.status(400).json({ message: "Missing or invalid fields" });
    }
    const dir = path.join(__dirname, "logs");
    const file = path.join(dir, "transactions.jsonl");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const record = {
      userId: req.userId, timestamp, senderName, senderBank, receiverLabel,
      receiverBank, amount, mode, steps
    };
    fs.appendFile(file, JSON.stringify(record) + os.EOL, (err) => {
      if (err) {
        console.error("Log write error:", err.message);
        return res.status(500).json({ message: "Failed to write log" });
      }
      return res.status(200).json({ message: "Log saved" });
    });
  } catch (e) {
    console.error("Log save exception:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

// Minimal transaction API: create + list
// Create a transaction (simulate transfer) and notify via SSE
app.post("/api/transfer", requireAuth, (req, res) => {
  const { receiverId, amount, channel } = req.body || {};
  const amt = Number(amount);
  if (!receiverId || !amt || amt <= 0) {
    return res.status(400).json({ message: "Missing or invalid fields" });
  }

  const ts = new Date().toISOString();
  const chan = channel || "UPI";
  const title = "Peer transfer";

  // Insert one row referencing sender and receiver
  const sql = `INSERT INTO transactions (ts, senderId, receiverId, amount, direction, title, channel)
               VALUES (?, ?, ?, ?, ?, ?, ?)`;
  // direction stored as 'OUT' (relative to sender); will be computed per viewer in queries
  db.run(sql, [ts, req.userId, receiverId, amt, 'OUT', title, chan], function (err) {
    if (err) {
      console.error("Insert tx error:", err.message);
      return res.status(500).json({ message: "Database error" });
    }

    // Notify all SSE clients
    broadcastTx({
      id: this.lastID,
      ts, senderId: req.userId, receiverId, amount: amt, title, channel: chan
    });

    return res.status(201).json({ message: "Transfer recorded", id: this.lastID });
  });
});

// List recent transactions for the logged-in user (merged IN/OUT)
app.get("/api/transactions", requireAuth, (req, res) => {
  // Compose list where viewer is either sender or receiver; compute direction and label
  const sql = `
    SELECT
      t.id, t.ts, t.senderId, t.receiverId, t.amount, t.title, t.channel,
      CASE WHEN t.senderId = ? THEN 'OUT' ELSE 'IN' END as direction,
      us.name as senderName, ur.name as receiverName
    FROM transactions t
    JOIN users us ON us.id = t.senderId
    JOIN users ur ON ur.id = t.receiverId
    WHERE t.senderId = ? OR t.receiverId = ?
    ORDER BY datetime(t.ts) DESC
    LIMIT 20
  `;
  db.all(sql, [req.userId, req.userId, req.userId], (err, rows) => {
    if (err) {
      console.error("Fetch tx error:", err.message);
      return res.status(500).json({ message: "Database error" });
    }
    res.status(200).json(rows || []);
  });
});

// Server-Sent Events (SSE) for realtime tx updates
const clients = new Set();
app.get("/api/tx/stream", requireAuth, (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive"
  });
  res.flushHeaders();

  const client = { res, userId: req.userId };
  clients.add(client);

  // Send a ping every 25s to keep connection open (some proxies time out otherwise)
  const interval = setInterval(() => {
    try {
      res.write(`event: ping\ndata: ${Date.now()}\n\n`);
    } catch {
      // ignore
    }
  }, 25000);

  req.on("close", () => {
    clearInterval(interval);
    clients.delete(client);
  });
});

// Broadcast a tx event to all connected users that are party to the tx
function broadcastTx(tx) {
  for (const client of clients) {
    if (client.userId === tx.senderId || client.userId === tx.receiverId) {
      const payload = JSON.stringify(tx);
      try {
        client.res.write(`event: tx\ndata: ${payload}\n\n`);
      } catch {
        // ignore broken client
      }
    }
  }
}

// Static
app.use(express.static(path.join(__dirname, "frontend")));

// Routes to pages
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "login", "login.html"));
});

app.get(["/dashboard", "/dashboard/"], (req, res) => {
  res.sendFile(path.join(__dirname, "frontend", "dashboard", "dashboard.html"));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

const RPI = "https://nonnephritic-amiyah-calvus.ngrok-free.dev"; // <--- Hardcode here

app.get("/api/banks-csv", async (req, res) => {
  try {
    const fetch = (await import("node-fetch")).default;
    const r = await fetch(`${RPI}/banks`);
    const text = await r.text();
    res.set("Content-Type", "text/csv");
    res.send(text);
  } catch {
    res.status(500).send("RPI offline");
  }
});

app.get("/api/policies-csv", async (req, res) => {
  try {
    const fetch = (await import("node-fetch")).default;
    const r = await fetch(`${RPI}/policies`);
    const text = await r.text();
    res.set("Content-Type", "text/csv");
    res.send(text);
  } catch {
    res.status(500).send("RPI offline");
  }
});

const logsFile = path.join(__dirname, "logs", "transactions.jsonl");

app.get("/api/security-logs", requireAuth, (req, res) => {
  try {
    if (!fs.existsSync(logsFile)) return res.json([]);

    const text = fs.readFileSync(logsFile, "utf8").trim();
    if (!text) return res.json([]);

    const rows = text.split(/\r?\n/).map(line => JSON.parse(line));

    // Return newest first
    return res.json(rows.reverse());
  } catch (err) {
    console.error("Log read error:", err);
    return res.status(500).json({ message: "Log read error" });
  }
});
