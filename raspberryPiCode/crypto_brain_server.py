# crypto_brain_server.py (Two-CSV architecture)
import os, time, base64, hmac, hashlib, json
from typing import Dict, Any, Optional, List, Tuple

import numpy as np
import pandas as pd
import joblib
import onnxruntime as ort
import portalocker

from fastapi import FastAPI, HTTPException, Path, Query, Header
from pydantic import BaseModel, Field, validator

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import oqs  # PQC KEM (Kyber/ML-KEM)
from dotenv import load_dotenv
load_dotenv()

# =====================================================================================
# CONFIG
# =====================================================================================

# Artifacts search order:
ART_SEARCH_PATHS = [
    os.environ.get("CRYPTO_ARTIFACTS"),
    "/mnt/data",
    "./artifacts",
]
ART_SEARCH_PATHS = [p for p in ART_SEARCH_PATHS if p]

# New two-CSV file paths (start fresh as per user choice "B")
BANKS_CSV = os.environ.get("BANKS_CSV", "/home/capstone/capstone/banks.csv")
POLICIES_CSV = os.environ.get("POLICIES_CSV", "/home/capstone/capstone/policies.csv")


# =====================================================================================
# UTILS: artifact loading
# =====================================================================================

def _first_existing(*candidates: str) -> str:
    for p in candidates:
        if p and os.path.exists(p):
            return p
    raise FileNotFoundError(f"None of these paths exist: {candidates}")

def _find_artifact(filename: str) -> str:
    tries = [os.path.join(base, filename) for base in ART_SEARCH_PATHS]
    return _first_existing(*tries)

def _load_scaler(path):
    obj = joblib.load(path)
    if isinstance(obj, dict) and "scaler" in obj:
        return obj["scaler"]
    return obj

def _load_encoder(path):
    obj = joblib.load(path)
    if isinstance(obj, dict):
        for v in obj.values():
            try:
                _ = v.classes_
                return v
            except Exception:
                continue
    return obj

def _onnx_input_name(sess: ort.InferenceSession) -> str:
    return sess.get_inputs()[0].name


# =====================================================================================
# LOAD AI (ONNX + scalers/encoders)
# =====================================================================================

def _load_ai():
    sw_model = _find_artifact("sw_model.onnx")
    hw_model = _find_artifact("hw_model.onnx")
    scaler_sw_p = _find_artifact("scaler_sw.joblib")
    scaler_hw_p = _find_artifact("scaler_hw.joblib")
    le_sw_p = _find_artifact("le_sw.joblib")
    le_hw_p = _find_artifact("le_hw.joblib")

    providers = ["CPUExecutionProvider"]
    sw_sess = ort.InferenceSession(sw_model, providers=providers)
    hw_sess = ort.InferenceSession(hw_model, providers=providers)

    sw_in_name = _onnx_input_name(sw_sess)
    hw_in_name = _onnx_input_name(hw_sess)

    scaler_sw = _load_scaler(scaler_sw_p)
    scaler_hw = _load_scaler(scaler_hw_p)
    le_sw = _load_encoder(le_sw_p)
    le_hw = _load_encoder(le_hw_p)
    return sw_sess, hw_sess, sw_in_name, hw_in_name, scaler_sw, scaler_hw, le_sw, le_hw

sw_sess, hw_sess, sw_in_name, hw_in_name, scaler_sw, scaler_hw, le_sw, le_hw = _load_ai()


# =====================================================================================
# AI DECISION
# =====================================================================================

def _onnx_predict_label(sess, in_name, X: np.ndarray, enc) -> str:
    out = sess.run(None, {in_name: X.astype(np.float32)})[0]
    arr = np.asarray(out).squeeze()
    if arr.ndim == 0:
        idx = int(arr)
    else:
        idx = int(np.argmax(arr))
    return enc.inverse_transform([idx])[0]

def ai_decide(sw_latency, ct_bytes, keysize, security, lut, bram, dsp, freq, lat) -> Tuple[str, str]:
    """
    Return (software_algo_label, hardware_class_label) via ONNX models.
    SW features: [sw_latency, ct_bytes, keysize, security]
    HW features: [lut, bram, dsp, freq, lat, penalty]
    """
    penalty = (lut + dsp * 10 + bram * 50) / 10000.0

    X_sw = scaler_sw.transform([[sw_latency, ct_bytes, keysize, security]])
    sw_label = _onnx_predict_label(sw_sess, sw_in_name, X_sw, le_sw)

    X_hw = scaler_hw.transform([[lut, bram, dsp, freq, lat, penalty]])
    hw_label = _onnx_predict_label(hw_sess, hw_in_name, X_hw, le_hw)

    return sw_label, hw_label


# =====================================================================================
# RUNTIME SESSIONS (for hybrid channel)
# =====================================================================================
SESSIONS: Dict[str, Dict[str, Any]] = {}


# =====================================================================================
# Pydantic models
# =====================================================================================

class DecideIn(BaseModel):
    sw_latency: float = Field(..., gt=0)
    ct_bytes: int = Field(..., gt=0)
    keysize: int = Field(..., gt=0)
    security: int = Field(..., gt=0)
    lut: int = Field(..., ge=0)
    bram: int = Field(..., ge=0)
    dsp: int = Field(..., ge=0)
    freq: int = Field(..., gt=0)
    lat: float = Field(..., ge=0)

class DecideOut(BaseModel):
    chosen_sw_algo: str
    chosen_hw_class: str

class BankConfig(BaseModel):
    bank_id: str = Field(..., min_length=2, max_length=64)
    bank_name: str = Field(..., min_length=2, max_length=128)

    sw_latency: float = Field(..., gt=0, description="SLA threshold (sec)")
    avg_ct_bytes: int = Field(..., gt=0)
    pref_keysize: int = Field(..., gt=0)
    security_level: int = Field(..., gt=0)

    lut: int = Field(..., ge=0)
    bram: int = Field(..., ge=0)
    dsp: int = Field(..., ge=0)
    freq: int = Field(..., gt=0)
    base_latency: float = Field(..., ge=0)

    region: Optional[str] = None
    hw_base: Optional[str] = None
    hw_budget: Optional[str] = None
    hw_infra: Optional[str] = None

    enterprise: Optional[str] = None
    infra: Optional[str] = None
    budget: Optional[str] = None
    legacy: Optional[str] = None
    deployment: Optional[str] = None

    crypto_pref: Optional[str] = "auto"

    @validator("bank_id")
    def no_commas(cls, v):
        if "," in v:
            raise ValueError("bank_id must not contain commas")
        return v

class BankRegisterOut(BaseModel):
    bank_id: str
    bank_name: str
    suggested_sw_algo: str
    suggested_hw_class: str
    pairwise_rows_added: int

class HSStartOut(BaseModel):
    session_hint: str
    kem_name: str
    server_x25519_pub_b64: str
    server_kem_pub_b64: str

class HSFinishIn(BaseModel):
    session_hint: str
    client_x25519_pub_b64: str
    kem_ciphertext_b64: str

class HSFinishOut(BaseModel):
    session_id: str
    confirm_tag_b64: str

class EncIn(BaseModel):
    session_id: str
    plaintext_b64: str
    aad_b64: Optional[str] = None

class EncOut(BaseModel):
    nonce_b64: str
    ciphertext_b64: str

class DecIn(BaseModel):
    session_id: str
    nonce_b64: str
    ciphertext_b64: str
    aad_b64: Optional[str] = None

class DecOut(BaseModel):
    plaintext_b64: str


# =====================================================================================
# CSV HELPERS — Two-CSV design
# =====================================================================================

BANKS_COLUMNS = [
    "BankID","BankName","Region","LatencySLA","AvgCTBytes","PrefKeySize","SecurityLevel",
    "LUT","BRAM","DSP","FREQ","BaseLatency",
    "HW_Base","HW_Budget","HW_Infra",
    "Enterprise","Infra","Budget","Legacy","Deployment",
    "CryptoPref","UpdatedAt"
]

POLICY_COLUMNS = [
    "From_Bank","To_Bank","Transaction_Type",
    "Policy_SW_Algo","Policy_HW_Class","PolicyUpdatedAt"
]

def _ensure_parent(path: str):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)

def _lock_write_csv(df: pd.DataFrame, path: str):
    _ensure_parent(path)
    if not os.path.exists(path):
        open(path, "a").close()
    with portalocker.Lock(path, timeout=10):
        df.to_csv(path, index=False)

def load_banks() -> pd.DataFrame:
    if not os.path.exists(BANKS_CSV) or os.path.getsize(BANKS_CSV) == 0:
        return pd.DataFrame(columns=BANKS_COLUMNS)
    try:
        df = pd.read_csv(BANKS_CSV)
    except Exception:
        return pd.DataFrame(columns=BANKS_COLUMNS)
    # Basic normalization
    for c in BANKS_COLUMNS:
        if c not in df.columns:
            df[c] = np.nan
    df = df.dropna(how="all")
    # keep only non-empty BankID
    if "BankID" in df.columns:
        df = df[df["BankID"].astype(str).str.strip() != ""]
    return df[BANKS_COLUMNS]

def save_banks(df: pd.DataFrame):
    if df.empty:
        _lock_write_csv(pd.DataFrame(columns=BANKS_COLUMNS), BANKS_CSV)
        return
    # ensure cols
    for c in BANKS_COLUMNS:
        if c not in df.columns:
            df[c] = np.nan
    # dedup & sanitize
    df = df[df["BankID"].astype(str).str.strip() != ""]
    df = df.drop_duplicates(subset=["BankID"], keep="last")
    _lock_write_csv(df[BANKS_COLUMNS], BANKS_CSV)

def load_policies() -> pd.DataFrame:
    if not os.path.exists(POLICIES_CSV) or os.path.getsize(POLICIES_CSV) == 0:
        return pd.DataFrame(columns=POLICY_COLUMNS)
    try:
        df = pd.read_csv(POLICIES_CSV)
    except Exception:
        return pd.DataFrame(columns=POLICY_COLUMNS)
    for c in POLICY_COLUMNS:
        if c not in df.columns:
            df[c] = np.nan
    df = df.dropna(how="all")
    # basic sanity: drop rows without From/To
    df = df.dropna(subset=["From_Bank","To_Bank"])
    return df[POLICY_COLUMNS]

def save_policies(df: pd.DataFrame):
    if df.empty:
        _lock_write_csv(pd.DataFrame(columns=POLICY_COLUMNS), POLICIES_CSV)
        return
    for c in POLICY_COLUMNS:
        if c not in df.columns:
            df[c] = np.nan
    df = df.dropna(subset=["From_Bank","To_Bank"])
    df = df.drop_duplicates(subset=["From_Bank","To_Bank","Transaction_Type"], keep="last")
    _lock_write_csv(df[POLICY_COLUMNS], POLICIES_CSV)


# =====================================================================================
# Policy helpers and overrides
# =====================================================================================

def _maybe_force_classical(sw_label: str, hw_label: str,
                           *, lut: int, dsp: int, freq: int,
                           hw_base: Optional[str] = None,
                           hw_budget: Optional[str] = None,
                           hw_infra: Optional[str] = None) -> Tuple[str, str]:
    weak_numeric = (lut is not None and lut < 10000) or \
                   (dsp is not None and dsp < 96) or \
                   (freq is not None and freq < 140)

    hb = (hw_base or "").lower()
    bud = (hw_budget or "").lower()
    inf = (hw_infra or "").lower()

    legacy_hint = any(s in hb for s in ["legacy", "cpu"]) or \
                  ("low" in bud) or \
                  any(s in inf for s in ["old", "branch", "edge"])

    if weak_numeric or legacy_hint:
        return "RSA-2048/ECDSA", "legacy_hw"
    return sw_label, hw_label

def _apply_overrides(sw_algo: str, hw_class: str, crypto_pref: Optional[str]) -> Tuple[str, str]:
    if not crypto_pref:
        return sw_algo, hw_class

    pref = crypto_pref.lower().strip()

    # Force classical
    if pref == "classical_only":
        return "RSA-2048/ECDSA", "legacy_hw"

    # Force PQC only (no classical fallback)
    if pref == "pqc_only":
        if "RSA" in sw_algo or "ECDSA" in sw_algo:
            sw_algo = "Kyber768/Falcon"
        if "legacy" in hw_class:
            hw_class = "pqc_hw"
        return sw_algo, hw_class

    # Force HYBRID mode (X25519 + PQC KEM)
    if pref == "hybrid":
        sw_algo = "HYBRID(X25519 + ML-KEM-768)"
        hw_class = "hybrid_hw"
        return sw_algo, hw_class

    return sw_algo, hw_class


# =====================================================================================
# Metadata accessors (now from banks.csv)
# =====================================================================================

def get_bank_profile(bank_id: str) -> Optional[dict]:
    df = load_banks()
    row = df[df["BankID"] == bank_id]
    if row.empty:
        return None
    r = row.iloc[0]

    def _ival(x, default):
        try: return int(x)
        except Exception: return default

    def _fval(x, default):
        try: return float(x)
        except Exception: return default

    return {
        "lat": _fval(r.get("LatencySLA", 0.003), 0.003),
        "ct":  _ival(r.get("AvgCTBytes", 1184), 1184),
        "key": _ival(r.get("PrefKeySize", 1568), 1568),
        "sec": _ival(r.get("SecurityLevel", 1568), 1568),
        "lut": _ival(r.get("LUT", 12000), 12000),
        "bram": _ival(r.get("BRAM", 24), 24),
        "dsp": _ival(r.get("DSP", 128), 128),
        "freq": _ival(r.get("FREQ", 160), 160),
        "hw_lat": _fval(r.get("BaseLatency", 4e-5), 4e-5),
        "crypto_pref": str(r.get("CryptoPref", "") or "").strip().lower(),
        "hw_base": str(r.get("HW_Base", "") or ""),
        "hw_budget": str(r.get("HW_Budget", "") or ""),
        "hw_infra": str(r.get("HW_Infra", "") or ""),
    }


# =====================================================================================
# Rebuild ALL policies (banks.csv -> policies.csv)
# =====================================================================================

def rebuild_all_policies() -> int:
    banks = load_banks()
    if banks.empty:
        save_policies(pd.DataFrame(columns=POLICY_COLUMNS))
        return 0

    rows = []
    timestamp = int(time.time())

    # make a reusable cache of bank profiles
    profiles: Dict[str, dict] = {}
    for _, brow in banks.iterrows():
        profiles[brow["BankID"]] = get_bank_profile(brow["BankID"])

    for _, srow in banks.iterrows():
        s_id = srow["BankID"]
        s = profiles.get(s_id)
        if not s:
            continue
        for _, rrow in banks.iterrows():
            r_id = rrow["BankID"]
            r = profiles.get(r_id)
            if not r:
                continue

            tx_type = "Internal" if s_id == r_id else "External"

            # negotiation rules
            sec = max(s["sec"], r["sec"])
            key = max(s["key"], r["key"])
            lat = max(s["lat"], r["lat"])
            ct  = s["ct"]  # sender payload size governs

            eff_lut   = min(s["lut"], r["lut"])
            eff_bram  = min(s["bram"], r["bram"])
            eff_dsp   = min(s["dsp"], r["dsp"])
            eff_freq  = min(s["freq"], r["freq"])
            eff_hwlat = max(s["hw_lat"], r["hw_lat"])

            sw, hw = ai_decide(lat, ct, key, sec, eff_lut, eff_bram, eff_dsp, eff_freq, eff_hwlat)

            # fallback on effective hardware
            sw, hw = _maybe_force_classical(
                sw, hw,
                lut=eff_lut, dsp=eff_dsp, freq=eff_freq,
                hw_base=s.get("hw_base"), hw_budget=s.get("hw_budget"), hw_infra=s.get("hw_infra")
            )
            # sender override (policy owner)
            sw, hw = _apply_overrides(sw, hw, s["crypto_pref"])

            rows.append({
                "From_Bank": s_id,
                "To_Bank": r_id,
                "Transaction_Type": tx_type,
                "Policy_SW_Algo": sw,
                "Policy_HW_Class": hw,
                "PolicyUpdatedAt": timestamp
            })

    save_policies(pd.DataFrame(rows, columns=POLICY_COLUMNS))
    return len(rows)


# =====================================================================================
# FastAPI app
# =====================================================================================

app = FastAPI(title="Crypto Brain: Bank Registry + Policy Router (Two-CSV) + Hybrid Channel")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # you can replace "*" with your real frontend domain later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"ok": True, "time": int(time.time())}

# --- Debug: raw AI decision (direct ONNX) ---
@app.post("/decide_crypto", response_model=DecideOut)
def decide_endpoint(inp: DecideIn):
    sw, hw = ai_decide(
        inp.sw_latency, inp.ct_bytes, inp.keysize, inp.security,
        inp.lut, inp.bram, inp.dsp, inp.freq, inp.lat
    )
    return DecideOut(chosen_sw_algo=sw, chosen_hw_class=hw)

# --- Subscribe/update a bank: ONLY banks.csv, then rebuild all policies into policies.csv ---
@app.post("/banks/subscribe", response_model=BankRegisterOut)
def bank_subscribe(cfg: BankConfig, admin_key: str = Header(None)):
    if admin_key != os.environ.get("ADMIN_KEY"):
        raise HTTPException(status_code=403, detail="Invalid or missing admin key")
    # Compute a suggestion for THIS bank (internal policy preview)
    sw, hw = ai_decide(
        cfg.sw_latency, cfg.avg_ct_bytes, cfg.pref_keysize, cfg.security_level,
        cfg.lut, cfg.bram, cfg.dsp, cfg.freq, cfg.base_latency
    )
    sw, hw = _maybe_force_classical(
        sw, hw, lut=cfg.lut, dsp=cfg.dsp, freq=cfg.freq,
        hw_base=cfg.hw_base, hw_budget=cfg.hw_budget, hw_infra=cfg.hw_infra
    )
    sw, hw = _apply_overrides(sw, hw, cfg.crypto_pref)

    # Upsert into banks.csv
    df = load_banks()
    row = {
        "BankID": cfg.bank_id,
        "BankName": cfg.bank_name,
        "Region": cfg.region or "",
        "LatencySLA": cfg.sw_latency,
        "AvgCTBytes": cfg.avg_ct_bytes,
        "PrefKeySize": cfg.pref_keysize,
        "SecurityLevel": cfg.security_level,
        "LUT": cfg.lut,
        "BRAM": cfg.bram,
        "DSP": cfg.dsp,
        "FREQ": cfg.freq,
        "BaseLatency": cfg.base_latency,
        "HW_Base": cfg.hw_base or "",
        "HW_Budget": cfg.hw_budget or "",
        "HW_Infra": cfg.hw_infra or "",
        "Enterprise": cfg.enterprise or "",
        "Infra": cfg.infra or "",
        "Budget": cfg.budget or "",
        "Legacy": cfg.legacy or "",
        "Deployment": cfg.deployment or "",
        "CryptoPref": cfg.crypto_pref or "",
        "UpdatedAt": int(time.time()),
    }
    df = df[df["BankID"] != cfg.bank_id]
    df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    save_banks(df)

    # Rebuild all pairwise policies into policies.csv
    added = rebuild_all_policies()

    return BankRegisterOut(
        bank_id=cfg.bank_id,
        bank_name=cfg.bank_name,
        suggested_sw_algo=sw,
        suggested_hw_class=hw,
        pairwise_rows_added=added
    )

# --- Bank listings ---
@app.get("/banks")
def banks_list():
    df = load_banks()
    if df.empty:
        return []
    meta = df.drop_duplicates(subset=["BankID"]).fillna("")
    return json.loads(meta[BANKS_COLUMNS].to_json(orient="records"))

@app.get("/banks/{bank_id}")
def bank_get(bank_id: str = Path(..., min_length=2)):
    df = load_banks()
    m = df[df["BankID"] == bank_id]
    if m.empty:
        raise HTTPException(status_code=404, detail="Bank not found")
    meta = m.drop_duplicates(subset=["BankID"]).fillna("")
    return json.loads(meta.to_json(orient="records"))[0]

# --- Policies list (reads policies.csv only) ---
@app.get("/policies")
def policies(from_bank: Optional[str] = None, to_bank: Optional[str] = None):
    df = load_policies()
    if from_bank:
        df = df[df["From_Bank"] == from_bank]
    if to_bank:
        df = df[df["To_Bank"] == to_bank]
    df = df.sort_values(["From_Bank","To_Bank","Transaction_Type","PolicyUpdatedAt"])
    return json.loads(df.to_json(orient="records"))

from fastapi import Header

@app.post("/policies/rebuild")
def rebuild_policies(admin_key: str = Header(None)):
    if admin_key != os.environ.get("ADMIN_KEY"):
        raise HTTPException(status_code=403, detail="Invalid or missing admin key")
    count = rebuild_all_policies()
    return {"status": "ok", "policies_recomputed": count}



# --- Runtime selection: reads policies.csv; if missing pair, compute+append once ---
@app.get("/select")
def select_algo(
    from_bank: str = Query(..., min_length=2),
    to_bank: str = Query(..., min_length=2)
):
    pol = load_policies()
    tx_type = "Internal" if from_bank == to_bank else "External"

    row = pol[(pol["From_Bank"] == from_bank) &
              (pol["To_Bank"] == to_bank) &
              (pol["Transaction_Type"] == tx_type)]
    if not row.empty:
        best = row.sort_values("PolicyUpdatedAt").iloc[-1]
        return {
            "from_bank": from_bank,
            "to_bank": to_bank,
            "transaction_type": tx_type,
            "suggested_sw_algo": best["Policy_SW_Algo"],
            "suggested_hw_class": best["Policy_HW_Class"],
            "updated_at": int(best["PolicyUpdatedAt"]) if not pd.isna(best["PolicyUpdatedAt"]) else None
        }

    # Fallback: compute on-the-fly if pair is missing (and persist for next time)
    fb_sender = get_bank_profile(from_bank)
    fb_rcvr = get_bank_profile(to_bank)
    if not fb_sender or not fb_rcvr:
        raise HTTPException(status_code=404, detail="No policy and missing bank metadata")

    sec = max(fb_sender["sec"], fb_rcvr["sec"])
    key = max(fb_sender["key"], fb_rcvr["key"])
    lat = max(fb_sender["lat"], fb_rcvr["lat"])
    ct  = fb_sender["ct"]
    eff_lut  = min(fb_sender["lut"], fb_rcvr["lut"])
    eff_bram = min(fb_sender["bram"], fb_rcvr["bram"])
    eff_dsp  = min(fb_sender["dsp"], fb_rcvr["dsp"])
    eff_freq = min(fb_sender["freq"], fb_rcvr["freq"])
    eff_hw_lat = max(fb_sender["hw_lat"], fb_rcvr["hw_lat"])

    sw, hw = ai_decide(lat, ct, key, sec, eff_lut, eff_bram, eff_dsp, eff_freq, eff_hw_lat)
    sw, hw = _maybe_force_classical(
        sw, hw,
        lut=eff_lut, dsp=eff_dsp, freq=eff_freq,
        hw_base=fb_sender.get("hw_base"), hw_budget=fb_sender.get("hw_budget"), hw_infra=fb_sender.get("hw_infra")
    )
    sw, hw = _apply_overrides(sw, hw, fb_sender["crypto_pref"])

    now = int(time.time())
    add = pd.DataFrame([{
        "From_Bank": from_bank,
        "To_Bank": to_bank,
        "Transaction_Type": tx_type,
        "Policy_SW_Algo": sw,
        "Policy_HW_Class": hw,
        "PolicyUpdatedAt": now
    }], columns=POLICY_COLUMNS)
    merged = pd.concat([pol, add], ignore_index=True)
    save_policies(merged)

    return {
        "from_bank": from_bank, "to_bank": to_bank, "transaction_type": tx_type,
        "suggested_sw_algo": sw, "suggested_hw_class": hw, "updated_at": now
    }


# =====================================================================================
# Hybrid handshake (unchanged)
# =====================================================================================

def new_session_id(n: int = 24) -> str:
    return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")

def hkdf32(input_key_material: bytes, *, salt: bytes = b"", info: bytes = b"") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    return hkdf.derive(input_key_material)

@app.get("/handshake/start", response_model=HSStartOut)
def handshake_start():
    srv_x_priv = x25519.X25519PrivateKey.generate()
    srv_x_pub = srv_x_priv.public_key().public_bytes_raw()
    kem_name = "ML-KEM-768"
    kem = oqs.KeyEncapsulation(kem_name)
    kem_pub = kem.generate_keypair()
    session_hint = new_session_id()
    SESSIONS[session_hint] = {
        "created": time.time(),
        "x25519_priv": srv_x_priv,
        "kem": kem,
        "kem_name": kem_name,
        "key": None
    }
    return HSStartOut(
        session_hint=session_hint,
        kem_name=kem_name,
        server_x25519_pub_b64=base64.b64encode(srv_x_pub).decode(),
        server_kem_pub_b64=base64.b64encode(kem_pub).decode(),
    )

@app.post("/handshake/finish", response_model=HSFinishOut)
def handshake_finish(data: HSFinishIn):
    s = SESSIONS.get(data.session_hint)
    if not s:
        raise HTTPException(status_code=400, detail="Invalid session hint")
    srv_x_priv = s["x25519_priv"]
    cli_x_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(data.client_x25519_pub_b64))
    s_classical = srv_x_priv.exchange(cli_x_pub)
    kem: oqs.KeyEncapsulation = s["kem"]
    kem_ct = base64.b64decode(data.kem_ciphertext_b64)
    try:
        s_pqc = kem.decap_secret(kem_ct)
    except Exception:
        del SESSIONS[data.session_hint]
        raise HTTPException(status_code=400, detail="KEM decapsulation failed")
    hybrid_input = s_classical + s_pqc
    hybrid_key = hkdf32(hybrid_input, salt=b"hybrid", info=s["kem_name"].encode())
    session_id = new_session_id()
    SESSIONS[session_id] = {
        "created": time.time(),
        "key": hybrid_key,
        "kem_name": s["kem_name"],
        "algo": {"classical": "X25519", "pqc": s["kem_name"], "aead": "AES-256-GCM"},
    }
    try:
        kem.free()
    except Exception:
        pass
    del SESSIONS[data.session_hint]
    tag = hmac.new(hybrid_key, b"OK", hashlib.sha256).digest()
    return HSFinishOut(session_id=session_id, confirm_tag_b64=base64.b64encode(tag).decode())

# --- AEAD endpoints ---
@app.post("/enc", response_model=EncOut)
def enc_endpoint(inp: EncIn):
    s = SESSIONS.get(inp.session_id)
    if not s or not s.get("key"):
        raise HTTPException(status_code=400, detail="Invalid or expired session")
    key = s["key"]
    aead = AESGCM(key)
    nonce = os.urandom(12)
    aad = b"" if inp.aad_b64 is None else base64.b64decode(inp.aad_b64)
    ct = aead.encrypt(nonce, base64.b64decode(inp.plaintext_b64), aad)
    return EncOut(nonce_b64=base64.b64encode(nonce).decode(), ciphertext_b64=base64.b64encode(ct).decode())

@app.post("/dec", response_model=DecOut)
def dec_endpoint(inp: DecIn):
    s = SESSIONS.get(inp.session_id)
    if not s or not s.get("key"):
        raise HTTPException(status_code=400, detail="Invalid or expired session")
    key = s["key"]
    aead = AESGCM(key)
    aad = b"" if inp.aad_b64 is None else base64.b64decode(inp.aad_b64)
    pt = aead.decrypt(base64.b64decode(inp.nonce_b64), base64.b64decode(inp.ciphertext_b64), aad)
    return DecOut(plaintext_b64=base64.b64encode(pt).decode())
