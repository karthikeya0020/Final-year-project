"""
Traffic Simulator for WAF Pipeline

Generates realistic simulated HTTP traffic with periodic attack bursts
for live dashboard demonstration.
"""

import threading
import time
import random
import numpy as np
from feature_extractor import extract_features, reset_tracker


class TrafficSimulator:
    """Simulates realistic web traffic including attack patterns."""

    def __init__(self):
        self.running = False
        self.thread = None
        self.logs = []
        self.stats = {
            "total_requests": 0,
            "normal": 0,
            "sql_injection": 0,
            "ddos": 0,
            "mitm": 0,
            "blocked": 0,
            "allowed": 0,
            "start_time": None,
        }
        self.traffic_history = []
        self._lock = threading.Lock()
        self._model = None
        self._device = None

    def set_model(self, model, device):
        """Set the ML model for classification."""
        self._model = model
        self._device = device

    def start(self):
        """Start the traffic simulation."""
        if self.running:
            return
        self.running = True
        self.stats["start_time"] = time.time()
        reset_tracker()
        self.thread = threading.Thread(target=self._simulate_traffic, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop the traffic simulation."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)

    def _simulate_traffic(self):
        """Main simulation loop."""
        attack_cycle = 0

        while self.running:
            attack_cycle += 1

            # Determine current traffic pattern
            # Normal traffic most of the time, with periodic attack bursts
            phase = (attack_cycle % 100)

            if phase < 60:
                # Normal traffic phase
                request = self._generate_normal_request()
                self._process_request(request)
                time.sleep(random.uniform(0.3, 0.8))

            elif phase < 72:
                # SQL Injection attack burst
                request = self._generate_sql_injection()
                self._process_request(request)
                time.sleep(random.uniform(0.2, 0.5))

            elif phase < 88:
                # DDoS attack burst (faster requests)
                for _ in range(random.randint(3, 8)):
                    if not self.running:
                        break
                    request = self._generate_ddos_request()
                    self._process_request(request)
                    time.sleep(random.uniform(0.02, 0.08))

            else:
                # MITM attack phase
                request = self._generate_mitm_request()
                self._process_request(request)
                time.sleep(random.uniform(0.3, 0.6))

    def _process_request(self, request_data):
        """Process a simulated request through the WAF pipeline."""
        import torch

        features = extract_features(request_data)

        # Classify using the model
        if self._model is not None:
            with torch.no_grad():
                input_tensor = torch.FloatTensor(features).unsqueeze(0).to(self._device)
                output = self._model(input_tensor)
                probs = torch.softmax(output, dim=1)
                predicted_class = output.argmax(dim=1).item()
                confidence = probs[0, predicted_class].item()
        else:
            # Fallback: rule-based classification
            predicted_class, confidence = self._rule_based_classify(features)

        from model import CLASSES
        class_name = CLASSES[predicted_class]
        is_attack = class_name != "Normal"

        # Update stats
        with self._lock:
            self.stats["total_requests"] += 1
            self.stats[class_name.lower()] += 1
            if is_attack:
                self.stats["blocked"] += 1
            else:
                self.stats["allowed"] += 1

            # Create log entry
            log_entry = {
                "id": self.stats["total_requests"],
                "timestamp": time.strftime("%H:%M:%S"),
                "ip": request_data.get("ip", "unknown"),
                "method": request_data.get("method", "GET"),
                "url": request_data.get("url", "/"),
                "classification": class_name,
                "confidence": round(confidence * 100, 1),
                "action": "BLOCKED" if is_attack else "ALLOWED",
                "severity": self._get_severity(class_name, confidence),
            }
            self.logs.insert(0, log_entry)
            self.logs = self.logs[:200]  # Keep last 200 entries

            # Traffic history for charts
            self.traffic_history.append({
                "time": time.strftime("%H:%M:%S"),
                "timestamp": time.time(),
                "type": class_name,
            })
            self.traffic_history = self.traffic_history[-500:]

    def _rule_based_classify(self, features):
        """Fallback rule-based classification."""
        if features[5] > 1.0 or features[6] > 0.5 or features[7] > 0.5:
            return 1, 0.85  # SQL Injection
        elif features[8] > 1.5 or features[9] > 1.5:
            return 2, 0.90  # DDoS
        elif features[12] > 0.5 and features[11] > 0.5:
            return 3, 0.80  # MITM
        else:
            return 0, 0.95  # Normal

    def _get_severity(self, class_name, confidence):
        if class_name == "Normal":
            return "info"
        elif confidence > 0.9:
            return "critical"
        elif confidence > 0.7:
            return "high"
        else:
            return "medium"

    def _generate_normal_request(self):
        """Generate a normal-looking HTTP request."""
        paths = [
            "/", "/index.html", "/api/users", "/api/products", "/about",
            "/contact", "/login", "/dashboard", "/api/search?q=laptop",
            "/static/style.css", "/images/logo.png", "/api/status",
        ]
        return {
            "url": random.choice(paths),
            "method": random.choice(["GET", "GET", "GET", "POST"]),
            "headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
                "Cookie": f"session={random.randbytes(8).hex()}",
                "X-Forwarded-Proto": "https",
            },
            "body": "",
            "ip": f"192.168.1.{random.randint(1, 254)}",
            "params": {},
        }

    def _generate_sql_injection(self):
        """Generate a SQL injection attack request."""
        payloads = [
            "' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "' UNION SELECT username, password FROM users --",
            "1' AND 1=1 UNION SELECT NULL, table_name FROM information_schema.tables --",
            "admin'--",
            "' OR 1=1; INSERT INTO admin VALUES('hacker','pass123') --",
            "1; EXEC xp_cmdshell('dir') --",
            "' UNION ALL SELECT CONCAT(login,char(58),password) FROM users --",
            "1' WAITFOR DELAY '0:0:5' --",
            "' AND (SELECT COUNT(*) FROM sysobjects) > 0 --",
        ]
        paths = [
            f"/api/login?username={random.choice(payloads)}",
            f"/api/search?q={random.choice(payloads)}",
            f"/api/users/{random.choice(payloads)}",
        ]
        return {
            "url": random.choice(paths),
            "method": random.choice(["GET", "POST"]),
            "headers": {
                "User-Agent": random.choice([
                    "Mozilla/5.0", "sqlmap/1.5", "python-requests/2.28",
                ]),
                "Accept": "*/*",
            },
            "body": random.choice(payloads) if random.random() > 0.5 else "",
            "ip": f"10.0.{random.randint(1, 10)}.{random.randint(1, 254)}",
            "params": {"input": random.choice(payloads)},
        }

    def _generate_ddos_request(self):
        """Generate a DDoS-like request (high volume, simple)."""
        return {
            "url": random.choice(["/", "/api/status", "/index.html"]),
            "method": "GET",
            "headers": {
                "User-Agent": random.choice([
                    "bot", "curl/7.68.0", "", "python-urllib/3.8",
                ]),
            },
            "body": "",
            "ip": f"10.0.0.{random.randint(1, 5)}",  # Few IPs = botnet
            "params": {},
        }

    def _generate_mitm_request(self):
        """Generate a MITM-like request (protocol/header anomalies)."""
        return {
            "url": random.choice([
                "/api/users", "/api/checkout", "/api/payment", "/dashboard",
            ]),
            "method": random.choice(["GET", "POST", "PUT"]),
            "headers": {
                "User-Agent": random.choice([
                    "Mozilla/5.0 (modified)", "interceptor/1.0",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                ]),
                "X-Forwarded-Proto": "http",  # Downgraded from HTTPS!
                # Missing security headers
            },
            "body": random.choice(["", '{"card":"4111111111111111"}']),
            "ip": f"172.16.{random.randint(1, 50)}.{random.randint(1, 254)}",
            "params": {},
        }

    def get_stats(self):
        """Get current statistics."""
        with self._lock:
            stats = dict(self.stats)
            if stats["start_time"]:
                stats["uptime"] = int(time.time() - stats["start_time"])
            else:
                stats["uptime"] = 0
            stats["running"] = self.running
            return stats

    def get_logs(self, limit=50):
        """Get recent log entries."""
        with self._lock:
            return self.logs[:limit]

    def get_traffic_history(self, seconds=60):
        """Get traffic history for the last N seconds."""
        with self._lock:
            cutoff = time.time() - seconds
            return [
                h for h in self.traffic_history if h["timestamp"] > cutoff
            ]
