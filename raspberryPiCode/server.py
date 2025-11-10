from flask import Flask, send_file

app = Flask(__name__)

BANKS = "/home/capstone/capstone/banks.csv"
POLICIES = "/home/capstone/capstone/policies.csv"

@app.get("/banks")
def banks():
    return send_file(BANKS, mimetype="text/csv")

@app.get("/policies")
def policies():
    return send_file(POLICIES, mimetype="text/csv")

app.run(host="0.0.0.0", port=5050)
