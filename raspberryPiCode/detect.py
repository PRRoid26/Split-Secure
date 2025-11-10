import onnx
import onnxruntime as ort

ART = "/home/capstone/capstone/artifacts/"

def check_model(name):
    path = ART + name
    print(f"\nChecking {name} ...")

    # Check structure
    try:
        model = onnx.load(path)
        onnx.checker.check_model(model)
        print("  ✅ ONNX model structure is valid.")
    except Exception as e:
        print("  ❌ Structure error:", e)
        return

    # Check runtime load
    try:
        sess = ort.InferenceSession(path)
        print("  ✅ ONNX Runtime session loaded successfully.")
    except Exception as e:
        print("  ❌ Runtime load error:", e)

check_model("sw_model.onnx")
check_model("hw_model.onnx")
