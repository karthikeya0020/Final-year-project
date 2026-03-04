"""
Domain Scanner — Real-Time Threat Intelligence Lookup

Uses VirusTotal and SecurityTrails APIs to provide domain-level
threat intelligence including risk scores, malicious detections,
DNS records, subdomains, and a simulated real-time threat feed.
"""

import os
import time
import random
import hashlib
import threading

try:
    import requests
except ImportError:
    requests = None


class DomainScanner:
    """Queries external threat intelligence APIs for domain analysis."""

    VT_API_URL = "https://www.virustotal.com/api/v3"
    ST_API_URL = "https://api.securitytrails.com/v1"

    def __init__(self):
        self.vt_key = os.environ.get("VT_API_KEY", "")
        self.st_key = os.environ.get("ST_API_KEY", "")
        self._cache = {}          # domain -> (timestamp, result)
        self._cache_ttl = 300     # 5 minutes
        self._lock = threading.Lock()

    # ─── Public API ───────────────────────────────────────────

    def scan_domain(self, domain: str) -> dict:
        """Run full domain scan; returns unified result dict."""
        domain = self._normalize(domain)
        if not domain:
            return {"error": "Invalid domain name"}

        # Check cache
        cached = self._get_cached(domain)
        if cached:
            cached["cached"] = True
            return cached

        vt_data = self._virustotal_lookup(domain)
        st_data = self._securitytrails_lookup(domain)

        risk_score = self._calculate_risk_score(vt_data)
        threat_feed = self._generate_threat_feed(domain, vt_data)

        result = {
            "domain": domain,
            "cached": False,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "detection_stats": vt_data.get("detection_stats", {}),
            "categories": vt_data.get("categories", {}),
            "reputation": vt_data.get("reputation", 0),
            "last_analysis_date": vt_data.get("last_analysis_date", "N/A"),
            "threat_feed": threat_feed,
            "dns_records": st_data.get("dns_records", {}),
            "subdomains": st_data.get("subdomains", []),
            "associated_ips": st_data.get("associated_ips", []),
            "whois": st_data.get("whois", {}),
            "api_status": {
                "virustotal": vt_data.get("_status", "unavailable"),
                "securitytrails": st_data.get("_status", "unavailable"),
            },
        }

        self._set_cached(domain, result)
        return result

    def has_api_keys(self) -> dict:
        """Report which API keys are configured."""
        return {
            "virustotal": bool(self.vt_key),
            "securitytrails": bool(self.st_key),
            "any_configured": bool(self.vt_key or self.st_key),
        }

    # ─── VirusTotal ──────────────────────────────────────────

    def _virustotal_lookup(self, domain: str) -> dict:
        if not self.vt_key or requests is None:
            return self._vt_demo_data(domain)

        try:
            headers = {"x-apikey": self.vt_key}
            resp = requests.get(
                f"{self.VT_API_URL}/domains/{domain}",
                headers=headers,
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "_status": "live",
                    "detection_stats": {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "timeout": stats.get("timeout", 0),
                    },
                    "categories": self._flatten_categories(
                        data.get("categories", {})
                    ),
                    "reputation": data.get("reputation", 0),
                    "last_analysis_date": time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.gmtime(data.get("last_analysis_date", 0)),
                    ),
                    "total_votes": data.get("total_votes", {}),
                    "registrar": data.get("registrar", "N/A"),
                    "creation_date": data.get("creation_date", 0),
                    "last_dns_records": data.get("last_dns_records", []),
                }
            elif resp.status_code == 429:
                return {**self._vt_demo_data(domain), "_status": "rate_limited"}
            else:
                return {**self._vt_demo_data(domain), "_status": f"error_{resp.status_code}"}
        except Exception as e:
            print(f"[DomainScanner] VT error: {e}")
            return {**self._vt_demo_data(domain), "_status": "error"}

    # ─── SecurityTrails ──────────────────────────────────────

    def _securitytrails_lookup(self, domain: str) -> dict:
        if not self.st_key or requests is None:
            return self._st_demo_data(domain)

        result = {"_status": "live"}

        # DNS records
        try:
            resp = requests.get(
                f"{self.ST_API_URL}/domain/{domain}",
                headers={"APIKEY": self.st_key},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                current = data.get("current_dns", {})
                result["dns_records"] = {
                    "a": [r.get("ip", "") for r in current.get("a", {}).get("values", [])],
                    "aaaa": [r.get("ipv6", "") for r in current.get("aaaa", {}).get("values", [])],
                    "mx": [r.get("hostname", "") for r in current.get("mx", {}).get("values", [])],
                    "ns": [r.get("nameserver", "") for r in current.get("ns", {}).get("values", [])],
                    "txt": [r.get("value", "") for r in current.get("txt", {}).get("values", [])],
                }
                result["associated_ips"] = result["dns_records"].get("a", [])[:10]
                result["whois"] = {
                    "registrar": data.get("registrar", "N/A"),
                    "created_date": data.get("created_date", "N/A"),
                    "expires_date": data.get("expires_date", "N/A"),
                }
        except Exception as e:
            print(f"[DomainScanner] ST domain error: {e}")
            result.update(self._st_demo_data(domain))
            result["_status"] = "partial"

        # Subdomains
        try:
            resp = requests.get(
                f"{self.ST_API_URL}/domain/{domain}/subdomains",
                headers={"APIKEY": self.st_key},
                timeout=15,
            )
            if resp.status_code == 200:
                subs = resp.json().get("subdomains", [])
                result["subdomains"] = [f"{s}.{domain}" for s in subs[:20]]
        except Exception as e:
            print(f"[DomainScanner] ST subdomain error: {e}")
            if "subdomains" not in result:
                result["subdomains"] = self._st_demo_data(domain)["subdomains"]

        return result

    # ─── Threat Feed Generator ───────────────────────────────

    def _generate_threat_feed(self, domain: str, vt_data: dict) -> list:
        """Build a realistic threat-event feed based on VT analysis."""
        stats = vt_data.get("detection_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        feed = []
        now = time.time()

        # Generate entries based on actual detections
        threat_types = [
            ("Malware Distribution", "critical", malicious),
            ("Phishing Attempt", "high", max(malicious // 2, suspicious)),
            ("Suspicious Redirect", "medium", suspicious),
            ("SSL Certificate Issue", "low", 1 if suspicious > 0 else 0),
            ("DNS Tunneling Attempt", "high", 1 if malicious > 3 else 0),
            ("Command & Control Beacon", "critical", 1 if malicious > 5 else 0),
            ("Credential Harvesting", "critical", 1 if malicious > 4 else 0),
            ("Cryptomining Script", "medium", 1 if malicious > 2 else 0),
            ("Drive-by Download", "high", 1 if malicious > 6 else 0),
            ("Data Exfiltration", "critical", 1 if malicious > 8 else 0),
        ]

        for threat_name, severity, count in threat_types:
            if count > 0:
                seed = hashlib.md5(f"{domain}{threat_name}".encode()).digest()
                offset = int.from_bytes(seed[:2], "big") % 3600
                feed.append({
                    "threat": threat_name,
                    "severity": severity,
                    "count": count,
                    "time": time.strftime(
                        "%H:%M:%S", time.localtime(now - offset)
                    ),
                    "source": random.choice([
                        "VirusTotal", "AbuseIPDB", "OpenPhish",
                        "URLhaus", "PhishTank", "GreyNoise",
                    ]),
                    "status": "active" if random.random() > 0.3 else "mitigated",
                })

        # Always include at least a scan-complete entry
        if not feed:
            feed.append({
                "threat": "Domain Scan Complete",
                "severity": "info",
                "count": 0,
                "time": time.strftime("%H:%M:%S", time.localtime(now)),
                "source": "WAF Shield",
                "status": "clean",
            })

        feed.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x["severity"], 5))
        return feed

    # ─── Risk Score ──────────────────────────────────────────

    def _calculate_risk_score(self, vt_data: dict) -> int:
        stats = vt_data.get("detection_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + harmless + stats.get("undetected", 0)

        if total == 0:
            return 0

        # Weighted score: malicious counts 3x, suspicious 1.5x
        raw = ((malicious * 3) + (suspicious * 1.5)) / total * 100
        reputation = vt_data.get("reputation", 0)
        if reputation < 0:
            raw = min(100, raw + abs(reputation) * 0.5)

        return min(100, max(0, int(raw)))

    def _risk_level(self, score: int) -> str:
        if score >= 70:
            return "critical"
        elif score >= 40:
            return "high"
        elif score >= 15:
            return "medium"
        elif score > 0:
            return "low"
        return "safe"

    # ─── Demo / Fallback Data ────────────────────────────────

    def _vt_demo_data(self, domain: str) -> dict:
        """Realistic demo data when VT API key is not available."""
        seed = sum(ord(c) for c in domain) % 100
        is_risky = seed > 75

        return {
            "_status": "demo",
            "detection_stats": {
                "malicious": random.randint(3, 12) if is_risky else 0,
                "suspicious": random.randint(1, 5) if is_risky else random.randint(0, 1),
                "harmless": random.randint(60, 80),
                "undetected": random.randint(5, 15),
                "timeout": random.randint(0, 2),
            },
            "categories": {
                "Forcepoint ThreatSeeker": "information technology",
                "Sophos": "information technology",
            },
            "reputation": -5 if is_risky else random.randint(50, 200),
            "last_analysis_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_votes": {"harmless": 30 if not is_risky else 5, "malicious": 2 if is_risky else 0},
        }

    def _st_demo_data(self, domain: str) -> dict:
        """Realistic demo data when SecurityTrails API key is not available."""
        parts = domain.split(".")
        base = parts[0] if parts else domain

        return {
            "_status": "demo",
            "dns_records": {
                "a": [f"142.250.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(2)],
                "aaaa": [f"2607:f8b0:4004::{random.randint(1000,9999)}"],
                "mx": [f"alt{i}.aspmx.l.{domain}" for i in range(1, 4)],
                "ns": [f"ns{i}.{domain}" for i in range(1, 5)],
                "txt": [f"v=spf1 include:_spf.{domain} ~all"],
            },
            "subdomains": [
                f"www.{domain}", f"mail.{domain}", f"api.{domain}",
                f"cdn.{domain}", f"docs.{domain}", f"blog.{domain}",
                f"dev.{domain}", f"staging.{domain}",
            ],
            "associated_ips": [
                f"142.250.{random.randint(1,255)}.{random.randint(1,255)}"
                for _ in range(4)
            ],
            "whois": {
                "registrar": "MarkMonitor Inc.",
                "created_date": "1997-09-15",
                "expires_date": "2028-09-14",
            },
        }

    # ─── Helpers ─────────────────────────────────────────────

    def _normalize(self, domain: str) -> str:
        domain = domain.strip().lower()
        for prefix in ("http://", "https://", "www."):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.split("/")[0].split("?")[0].split("#")[0]
        if "." not in domain or len(domain) < 3:
            return ""
        return domain

    def _flatten_categories(self, cats: dict) -> dict:
        """VT returns {engine: category}; keep top 5."""
        return dict(list(cats.items())[:5]) if cats else {}

    def _get_cached(self, domain: str):
        with self._lock:
            if domain in self._cache:
                ts, result = self._cache[domain]
                if time.time() - ts < self._cache_ttl:
                    return dict(result)
        return None

    def _set_cached(self, domain: str, result: dict):
        with self._lock:
            self._cache[domain] = (time.time(), dict(result))
