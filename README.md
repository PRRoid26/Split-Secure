
# 🚀 Split-Secure  
### *Adaptive, Post-Quantum Secure Transaction Tunnel for Inter-Bank Communications*

Split-Secure is a **crypto-agile payment security layer** that allows banks with **different cryptographic capabilities** to securely transact with each other — *without requiring upgrades on both sides*.

At the center of the system is a **Raspberry Pi acting as a smart quantum-secure tunnel**.  
Even if one bank uses **legacy encryption**, the Pi ensures the **data in transit is always protected using the strongest PQC and hybrid cryptography**.

---

## 🔥 Why Split-Secure?
Most banks today still rely on RSA/ECC — both of which are **breakable by quantum computers**.  
Upgrading entire banking infrastructure is expensive and slow.

**Split-Secure solves this by adapting encryption in real time**, per transaction.

| Bank A | Bank B | What Split-Secure Does |
|-------|--------|------------------------|
| Legacy Bank | Modern Bank | Uses classical on one side, hybrid/PQC inside the tunnel |
| Modern Bank | PQC-Ready Bank | Enables full PQC handshake end-to-end |
| Legacy ↔ Legacy | Tunnel still remains PQC-secured while banks stay unchanged |

---

## 🧠 Core Idea
> **Banks negotiate encryption based on their capabilities.  
> The Raspberry Pi ensures the *path in-between* is always maximally secure.**

```

Bank A                Raspberry Pi Tunnel            Bank B
(Classical TLS)    =>   PQC / Hybrid Encryption   =>  (PQC / Classical)
___________________ Protected ___________________/

```

---

## ⚙️ Key Features
- **AI-based algorithm selection** per transaction  
- Supports **Classical → Hybrid → PQC** switching  
- Ensures **in-transit data is always quantum-safe**  
- **No infrastructure overhaul** needed by banks  
- Works with **UPI-like instant payment flows**  
- Raspberry Pi acts as **secure crypto router + policy engine**

---

## 🧱 System Architecture

```

+------------------+         +----------------------+         +------------------+
|    Sender Bank   | <-----> |   Split-Secure Pi    | <-----> |  Receiver Bank   |
| (Any Crypto Tier)|         | (AI + PQC Tunnel)    |         | (Any Crypto Tier)|
+------------------+         +----------------------+         +------------------+

Decision Engine:

* Detects capabilities of both banks
* Selects: Classical / Hybrid / PQC
* Applies strongest cipher *inside* the tunnel

````

---

## 🚦 Modes of Operation
| Mode | When Used | Encryption Used |
|------|----------|-----------------|
| **Classical** | Legacy hardware | RSA + AES-GCM |
| **Hybrid** | Mid-tier infra | ECDH + Kyber + AES-GCM |
| **PQC-First** | Modern or dedicated HSM banks | ML-KEM (Kyber) + Dilithium |

---

## 🛠️ Setup & Run

### 1. Clone Repository
```bash
git clone https://github.com/<your-username>/Split-Secure.git
cd Split-Secure
````

### 2. Setup Python Environment (recommended: Raspberry Pi 5)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Start Server

```bash
uvicorn crypto_brain_server:app --host 0.0.0.0 --port 8080
```

### 4. Add a Bank to the Registry

```bash
curl -X POST http://localhost:8080/banks/subscribe \
-H "Content-Type: application/json" \
-d @banks/HDFC.json
```

---

## 🌐 Example Transaction Flow

```bash
curl "http://localhost:8080/select?from_bank=ICICI&to_bank=HDFC"
```

**Output includes selected mode:**
`Hybrid (ECDH + ML-KEM + AES-GCM)`

---

## 🔭 Future Scope

* Hardware Security Module (HSM) integration
* Multi-tunnel routing for high-load bank clusters
* Real-time anomaly detection on encrypted traffic

---

## 🧑‍💻 Authors

**Prathamesh Shetty** — Researcher, AUV & PQC Systems Design

---

## 🛡️ License

MIT License — free to use & modify ✅

```

---

### Want to make your README look **premium**?
I can now add:
✅ Shields.io badges  
✅ Dark mode diagrams  
✅ Animated architecture flow  
✅ Paper-style technical abstract  

Just tell me: **Do you want a clean white theme or black cyber theme?** 😎
```
