import os

from flask import Flask, jsonify, request

from memory_analyzer import MemoryAnalyzer
from network_traffic_analyzer import NetworkTrafficAnalyzer
from runtime_monitor import RuntimeMonitor
from security_behavior_checker import SecurityBehaviorChecker
from virtual_sandbox import VirtualSandbox


app = Flask(__name__)
PID = os.getpid()


@app.get("/api/monitor")
def monitor():
    runtime = RuntimeMonitor(PID)
    return jsonify({
        "cpu_usage": runtime.get_cpu_usage(),
        "memory_usage": runtime.get_memory_usage(),
        "open_files": runtime.get_open_files(),
    })


@app.get("/api/memory")
def memory():
    analyzer = MemoryAnalyzer()
    return jsonify({
        "memory_check": analyzer.check_memory_leaks(),
        "overflow_test": analyzer.check_overflow(2**64),
    })


@app.get("/api/network")
def network():
    return jsonify({"network_stats": NetworkTrafficAnalyzer().get_network_stats()})


@app.get("/api/security")
def security():
    return jsonify({
        "suspicious_calls": SecurityBehaviorChecker().suspicious_calls(__file__)
    })


@app.post("/api/sandbox")
def sandbox():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON body must be an object."}), 400
    try:
        stdout, stderr = VirtualSandbox().run_isolated(data.get("command"))
    except (PermissionError, ValueError) as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({"stdout": stdout, "stderr": stderr})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
