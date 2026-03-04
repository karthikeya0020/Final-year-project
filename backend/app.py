"""
WAF Pipeline — Flask REST API Server

Serves the frontend dashboard and provides API endpoints for
real-time attack detection, traffic simulation, and statistics.
"""

import os
import sys
import torch
import time
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from model import load_model, get_model, CLASSES, FEATURE_DIM
from feature_extractor import extract_features, extract_features_simple, reset_tracker
from traffic_simulator import TrafficSimulator
from domain_scanner import DomainScanner

# ── App configuration ──
app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# ── Global state ──
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = None
simulator = TrafficSimulator()
domain_scanner = DomainScanner()


def init_model():
    """Load the trained model, or initialize untrained if weights not found."""
    global model
    model_path = os.path.join(os.path.dirname(__file__), "waf_model.pth")
    if os.path.exists(model_path):
        print(f"[WAF] Loading trained model from {model_path}")
        model = load_model(model_path, device)
        print("[WAF] Model loaded successfully")
    else:
        print("[WAF] WARNING: No trained model found. Run train.py first!")
        print("[WAF] Using untrained model (results will be random)")
        model = get_model(device)
        model.eval()
    simulator.set_model(model, device)


# ── Frontend routes ──

@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    # Don't serve static files for API routes
    if path.startswith("api/"):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(app.static_folder, path)


# ── API endpoints ──

@app.route("/api/analyze", methods=["POST"])
def analyze_request():
    """
    Analyze a single HTTP request for attacks.

    Expected JSON body:
    {
        "url": "/api/login",
        "method": "POST",
        "headers": {"User-Agent": "..."},
        "body": "username=admin' OR 1=1 --",
        "ip": "10.0.0.1",
        "params": {"username": "admin' OR 1=1 --"}
    }
    """
    data = request.get_json(force=True, silent=True) or {}

    # Extract features
    features = extract_features(data)

    # Classify
    with torch.no_grad():
        input_tensor = torch.FloatTensor(features).unsqueeze(0).to(device)
        output = model(input_tensor)
        probs = torch.softmax(output, dim=1)
        predicted_class = output.argmax(dim=1).item()
        confidence = probs[0, predicted_class].item()

    class_name = CLASSES[predicted_class]
    is_attack = class_name != "Normal"

    # Build response
    result = {
        "classification": class_name,
        "confidence": round(confidence * 100, 2),
        "is_attack": is_attack,
        "action": "BLOCKED" if is_attack else "ALLOWED",
        "probabilities": {
            CLASSES[i]: round(probs[0, i].item() * 100, 2) for i in range(len(CLASSES))
        },
        "features": {
            "body_length": round(float(features[0]), 3),
            "url_length": round(float(features[1]), 3),
            "special_char_density": round(float(features[4]), 3),
            "sql_keyword_count": round(float(features[5]), 3),
            "sql_pattern_score": round(float(features[6]), 3),
            "request_rate": round(float(features[8]), 3),
            "protocol_anomaly": round(float(features[12]), 3),
            "missing_security_headers": round(float(features[11]), 3),
        },
        "severity": _get_severity(class_name, confidence),
    }

    return jsonify(result)


@app.route("/api/test-attack", methods=["POST"])
def test_attack():
    """
    Test a specific attack payload.

    Expected JSON body:
    {
        "type": "sql_injection" | "ddos" | "mitm" | "normal",
        "payload": "optional custom payload"
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    attack_type = data.get("type", "normal")
    custom_payload = data.get("payload", "")

    # Generate test request based on type
    if attack_type == "sql_injection":
        default_sql = "' OR 1=1 --"
        sql_payload = custom_payload or default_sql
        test_request = {
            "url": f"/api/login?input={sql_payload}",
            "method": "POST",
            "headers": {"User-Agent": "sqlmap/1.5"},
            "body": custom_payload or "' UNION SELECT username, password FROM users --",
            "ip": "10.0.0.99",
            "params": {"input": sql_payload},
        }
    elif attack_type == "ddos":
        reset_tracker()
        # Simulate rapid requests from same IP
        for _ in range(50):
            extract_features_simple(ip="10.0.0.88", url="/")
        test_request = {
            "url": "/",
            "method": "GET",
            "headers": {"User-Agent": "bot"},
            "body": "",
            "ip": "10.0.0.88",
            "params": {},
        }
    elif attack_type == "mitm":
        test_request = {
            "url": "/api/payment",
            "method": "POST",
            "headers": {
                "X-Forwarded-Proto": "http",
                "User-Agent": "interceptor/1.0",
            },
            "body": '{"card":"4111111111111111"}',
            "ip": "172.16.0.99",
            "params": {},
        }
    else:
        test_request = {
            "url": "/api/products",
            "method": "GET",
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Cookie": "session=abc123",
                "X-Forwarded-Proto": "https",
                "Strict-Transport-Security": "max-age=31536000",
            },
            "body": "",
            "ip": "192.168.1.100",
            "params": {},
        }

    # Analyze
    features = extract_features(test_request)
    with torch.no_grad():
        input_tensor = torch.FloatTensor(features).unsqueeze(0).to(device)
        output = model(input_tensor)
        probs = torch.softmax(output, dim=1)
        predicted_class = output.argmax(dim=1).item()
        confidence = probs[0, predicted_class].item()

    class_name = CLASSES[predicted_class]

    return jsonify({
        "test_type": attack_type,
        "classification": class_name,
        "confidence": round(confidence * 100, 2),
        "is_attack": class_name != "Normal",
        "action": "BLOCKED" if class_name != "Normal" else "ALLOWED",
        "probabilities": {
            CLASSES[i]: round(probs[0, i].item() * 100, 2) for i in range(len(CLASSES))
        },
        "request_details": {
            "url": test_request["url"][:100],
            "method": test_request["method"],
            "ip": test_request["ip"],
        },
        "severity": _get_severity(class_name, confidence),
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Get real-time WAF statistics."""
    stats = simulator.get_stats()
    return jsonify(stats)


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """Get recent detection log entries."""
    limit = request.args.get("limit", 50, type=int)
    logs = simulator.get_logs(limit)
    return jsonify(logs)


@app.route("/api/traffic-history", methods=["GET"])
def get_traffic_history():
    """Get traffic history for charts."""
    seconds = request.args.get("seconds", 60, type=int)
    history = simulator.get_traffic_history(seconds)

    # Aggregate by 5-second buckets
    buckets = {}
    for entry in history:
        bucket_time = int(entry["timestamp"] // 5) * 5
        if bucket_time not in buckets:
            buckets[bucket_time] = {"Normal": 0, "SQL_Injection": 0, "DDoS": 0, "MITM": 0}
        buckets[bucket_time][entry["type"]] += 1

    timeline = []
    for ts in sorted(buckets.keys()):
        timeline.append({
            "time": time.strftime("%H:%M:%S", time.localtime(ts)),
            **buckets[ts],
        })

    return jsonify(timeline)


@app.route("/api/simulate/start", methods=["POST"])
def start_simulation():
    """Start the traffic simulation."""
    simulator.start()
    return jsonify({"status": "started", "message": "Traffic simulation started"})


@app.route("/api/simulate/stop", methods=["POST"])
def stop_simulation():
    """Stop the traffic simulation."""
    simulator.stop()
    return jsonify({"status": "stopped", "message": "Traffic simulation stopped"})


@app.route("/api/domain-scan", methods=["POST"])
def scan_domain():
    """
    Scan a domain for real-time threat intelligence.

    Expected JSON body:
    {"domain": "google.com"}
    """
    data = request.get_json(force=True, silent=True) or {}
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Please provide a domain name"}), 400

    result = domain_scanner.scan_domain(domain)
    if "error" in result:
        return jsonify(result), 400

    return jsonify(result)


@app.route("/api/domain-scan/status", methods=["GET"])
def domain_scan_status():
    """Check which threat intelligence API keys are configured."""
    return jsonify(domain_scanner.has_api_keys())


@app.route("/api/model-info", methods=["GET"])
def model_info():
    """Get model architecture info."""
    total_params = sum(p.numel() for p in model.parameters())
    return jsonify({
        "model_type": "Transformer Encoder",
        "architecture": {
            "d_model": 64,
            "num_heads": 4,
            "num_layers": 2,
            "feedforward_dim": 128,
            "sequence_length": "4 tokens (4 features each)",
            "cls_token": True,
        },
        "total_parameters": total_params,
        "input_features": FEATURE_DIM,
        "output_classes": CLASSES,
        "device": str(device),
    })


def _get_severity(class_name, confidence):
    if class_name == "Normal":
        return "info"
    elif confidence > 0.9:
        return "critical"
    elif confidence > 0.7:
        return "high"
    else:
        return "medium"


# ── Main ──
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Transformer-Based WAF Pipeline")
    print("=" * 60)
    init_model()
    print(f"\n[WAF] Starting server on http://localhost:5000")
    print(f"[WAF] Dashboard: http://localhost:5000")
    print(f"[WAF] API Base:  http://localhost:5000/api")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
