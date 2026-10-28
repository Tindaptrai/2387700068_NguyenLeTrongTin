from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def health():
    return jsonify({"service": "devsecops-demo", "status": "ok"})


@app.get("/api/health")
def api_health():
    return jsonify({"status": "ok", "security": "gates-enabled"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)