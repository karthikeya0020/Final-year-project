"""
Feature Extractor for WAF Pipeline

Converts raw HTTP request data into a 16-dimensional numerical feature vector
for the Transformer classifier. Features are designed to capture signatures
of SQL Injection, DDoS, and MITM attacks.
"""

import re
import numpy as np
import time
from collections import defaultdict

# SQL injection keywords / patterns
SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop", "alter",
    "exec", "execute", "xp_", "sp_", "0x", "char(", "concat(",
    "information_schema", "sysobjects", "syscolumns", "declare",
    "cast(", "convert(", "waitfor", "benchmark", "sleep(",
]

SQL_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",       # Basic SQL meta-characters
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # Tautology
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # OR-based
    r"((\%27)|(\'))union",                    # UNION-based
    r"exec(\s|\+)+(s|x)p\w+",               # Stored procedure
]

# Track request rates per IP for DDoS detection
_request_tracker = defaultdict(list)


def extract_features(request_data: dict) -> np.ndarray:
    """
    Extract 16 numerical features from an HTTP request.

    Args:
        request_data: dict with keys like:
            - url: request URL/path
            - method: HTTP method (GET, POST, etc.)
            - headers: dict of headers
            - body: request body string
            - ip: source IP address
            - params: query parameters dict
            - timestamp: request timestamp

    Returns:
        numpy array of shape (16,) with float32 features
    """
    features = np.zeros(16, dtype=np.float32)

    url = request_data.get("url", "")
    method = request_data.get("method", "GET")
    headers = request_data.get("headers", {})
    body = request_data.get("body", "")
    ip = request_data.get("ip", "0.0.0.0")
    params = request_data.get("params", {})
    timestamp = request_data.get("timestamp", time.time())

    full_payload = f"{url} {body} {' '.join(str(v) for v in params.values())}"

    # ── Feature 0: Request body length (normalized) ──
    features[0] = min(len(body) / 1000.0, 5.0)

    # ── Feature 1: URL length (normalized) ──
    features[1] = min(len(url) / 200.0, 5.0)

    # ── Feature 2: Number of query parameters ──
    features[2] = min(len(params) / 10.0, 5.0)

    # ── Feature 3: Number of headers ──
    features[3] = min(len(headers) / 20.0, 5.0)

    # ── Feature 4: Special character density in payload ──
    special_chars = sum(1 for c in full_payload if c in "'\";-#()=<>{}|&\\%")
    features[4] = min(special_chars / max(len(full_payload), 1) * 10, 5.0)

    # ── Feature 5: SQL keyword count ──
    payload_lower = full_payload.lower()
    sql_count = sum(1 for kw in SQL_KEYWORDS if kw in payload_lower)
    features[5] = min(sql_count / 3.0, 5.0)

    # ── Feature 6: SQL pattern match score ──
    sql_pattern_score = 0
    for pattern in SQL_PATTERNS:
        if re.search(pattern, full_payload, re.IGNORECASE):
            sql_pattern_score += 1
    features[6] = min(sql_pattern_score / 2.0, 5.0)

    # ── Feature 7: Has suspicious SQL strings ──
    suspicious_sql = [
        "1=1", "1'='1", "or 1=1", "' or '", "admin'--",
        "' OR ''='", "1; DROP", "' UNION SELECT",
    ]
    features[7] = min(
        sum(1 for s in suspicious_sql if s.lower() in payload_lower) * 2.0, 5.0
    )

    # ── Feature 8: Request rate from this IP (DDoS indicator) ──
    now = time.time()
    _request_tracker[ip] = [
        t for t in _request_tracker[ip] if now - t < 10
    ]  # Last 10s window
    _request_tracker[ip].append(now)
    request_rate = len(_request_tracker[ip])
    features[8] = min(request_rate / 20.0, 5.0)

    # ── Feature 9: Requests per second estimate ──
    if len(_request_tracker[ip]) > 1:
        time_span = max(
            _request_tracker[ip][-1] - _request_tracker[ip][0], 0.001
        )
        rps = len(_request_tracker[ip]) / time_span
        features[9] = min(rps / 50.0, 5.0)
    else:
        features[9] = 0.0

    # ── Feature 10: HTTP method encoding ──
    method_map = {"GET": 0.2, "POST": 0.4, "PUT": 0.6, "DELETE": 0.8, "OPTIONS": 0.1}
    features[10] = method_map.get(method.upper(), 1.0)

    # ── Feature 11: Missing standard security headers (MITM indicator) ──
    security_headers = [
        "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Proto",
        "Strict-Transport-Security",
    ]
    header_keys_lower = [h.lower() for h in headers.keys()]
    missing = sum(
        1 for h in security_headers if h.lower() not in header_keys_lower
    )
    features[11] = missing / len(security_headers)

    # ── Feature 12: Protocol anomaly (MITM indicator) ──
    proto = headers.get("X-Forwarded-Proto", "https").lower()
    features[12] = 1.0 if proto == "http" else 0.0

    # ── Feature 13: User-Agent anomaly ──
    ua = headers.get("User-Agent", "")
    if not ua:
        features[13] = 3.0  # No UA is suspicious
    elif len(ua) < 10:
        features[13] = 2.0  # Very short UA
    elif any(bot in ua.lower() for bot in ["bot", "curl", "wget", "python", "script"]):
        features[13] = 1.5
    else:
        features[13] = 0.0

    # ── Feature 14: Cookie / session anomaly (MITM indicator) ──
    has_cookie = "Cookie" in headers or "cookie" in headers
    has_auth = "Authorization" in headers or "authorization" in headers
    features[14] = 0.0 if (has_cookie or has_auth) else 1.5

    # ── Feature 15: Payload entropy (high entropy = potential encoded attack) ──
    if len(full_payload) > 0:
        byte_counts = np.zeros(256)
        for byte in full_payload.encode("utf-8", errors="ignore"):
            byte_counts[byte] += 1
        byte_probs = byte_counts / len(full_payload)
        byte_probs = byte_probs[byte_probs > 0]
        entropy = -np.sum(byte_probs * np.log2(byte_probs))
        features[15] = min(entropy / 4.0, 5.0)
    else:
        features[15] = 0.0

    return features


def reset_tracker():
    """Reset the request rate tracker (useful for testing)."""
    global _request_tracker
    _request_tracker = defaultdict(list)


def extract_features_simple(
    url="", method="GET", body="", headers=None, ip="0.0.0.0", params=None
):
    """Convenience wrapper with keyword arguments."""
    return extract_features({
        "url": url,
        "method": method,
        "headers": headers or {},
        "body": body,
        "ip": ip,
        "params": params or {},
        "timestamp": time.time(),
    })
