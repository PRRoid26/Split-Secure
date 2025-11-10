import numpy as np
import joblib
import onnxruntime as ort

ART = "/home/capstone/capstone/artifacts/"

# ---- Load ONNX Models ----
sw_sess = ort.InferenceSession(ART + "sw_model.onnx", providers=["CPUExecutionProvider"])
hw_sess = ort.InferenceSession(ART + "hw_model.onnx", providers=["CPUExecutionProvider"])

# ---- Load Scalers and Encoders ----
scaler_sw = joblib.load(ART + "scaler_sw.joblib")["scaler"]
scaler_hw = joblib.load(ART + "scaler_hw.joblib")["scaler"]
le_sw = joblib.load(ART + "le_sw.joblib")
le_hw = joblib.load(ART + "le_hw.joblib")

# ========= INPUTS (these will be dynamic later) ========= #

# Example: Bank SW crypto choice factors
sw_latency = 0.003       # seconds
ct_bytes   = 1184        # ciphertext length
keysize    = 1568        # security param
security   = keysize     # same feature duplicated as training

# Prepare SW feature vector
X_sw = scaler_sw.transform([[sw_latency, ct_bytes, keysize, security]]).astype(np.float32)

# ONNX runtime prediction
sw_pred = sw_sess.run(None, {"input": X_sw})[0][0]
chosen_sw = le_sw.inverse_transform([int(sw_pred)])[0]

# Example: Hardware resource usage (change these later for FPGA/HSM sensors)
lut = 12000
bram = 24
dsp = 128
freq = 160
lat = 0.00004
penalty = (lut + dsp*10 + bram*50) / 10000.0

# Prepare HW feature vector
X_hw = scaler_hw.transform([[lut, bram, dsp, freq, lat, penalty]]).astype(np.float32)

# ONNX runtime prediction
hw_pred = hw_sess.run(None, {"input": X_hw})[0][0]
chosen_hw = le_hw.inverse_transform([int(hw_pred)])[0]

# ========= OUTPUT ========= #

print("\n=== CRYPTO DECISION OUTPUT (ONNX) ===")
print("Chosen Software Algorithm  →", chosen_sw.upper())
print("Chosen Hardware Class      →", chosen_hw)
print("=====================================\n")
