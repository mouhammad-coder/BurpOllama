"""
BurpOllama Analyzer Server - Core backend
Receives traffic from Burp, processes with Ollama, pushes findings to dashboard
"""
import asyncio
import json
import os
import re
import time
import uuid
import hashlib
import threading
import queue
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import defaultdict

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn

# Try importing httpx for async HTTP calls to Ollama
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    print("[!] httpx not available, using urllib for API calls")

# ============================================================
# Configuration
# ============================================================
CONFIG = {
    "host": "127.0.0.1",
    "port": 9999,
    "ollama_host": "http://127.0.0.1:11434",
    "model": "llama3.1:8b",  # Default model, can be overridden
    "fallback_model": "deepseek-coder:6.7b",
    "max_concurrent_analysis": 3,
    "db_path": str(Path(__file__).parent.parent / "data" / "findings.db"),
    "data_dir": str(Path(__file__).parent.parent / "data"),
    "enable_ollama": True,
    "enable_pattern_detection": True,
    "min_confidence_to_report": 0.4,
    "rate_limit_per_host": 50,
}

# Ensure data directory exists
os.makedirs(CONFIG["data_dir"], exist_ok=True)

# ============================================================
# Vulnerability Patterns Database
# ============================================================
VULN_PATTERNS = {
    "authentication": {
        "patterns": [
            (r"password\s*[=:]\s*['\"][^'\"]{3,}['\"]", "Hardcoded password", "High"),
            (r"passwd\s*[=:]\s*['\"][^'\"]{3,}['\"]", "Hardcoded password", "High"),
            (r"(?i)jwt\s*=\s*['\"][^'\"]{50,}['\"]", "JWT token leakage", "High"),
            (r"(?i)session\s*[=:]\s*['\"][a-zA-Z0-9]{20,}['\"]", "Session token exposure", "High"),
            (r"(?i)(token|csrf|xsrf)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "Token exposure", "Medium"),
            (r"(?i)(otp|2fa|mfa|totp)\s*[=:]\s*['\"][^'\"]{3,}['\"]", "OTP/2FA code exposure", "High"),
            (r"(?i)auth_token\s*[=:]\s*['\"][^'\"]{10,}['\"]", "Auth token leakage", "Critical"),
            (r"(?i)secret\s*[=:]\s*['\"][^'\"]{10,}['\"]", "Secret exposure", "High"),
        ]
    },
    "authorization_idor": {
        "patterns": [
            (r"/api/(?:v[0-9]+/)?(?:user|account|profile|order|payment|admin)/\d+", "Potential IDOR endpoint pattern", "Medium"),
            (r"(?i)(userId|user_id|accountId|account_id|customerId|customer_id)\s*[=:]\s*\d+", "IDOR parameter pattern", "Medium"),
            (r"\?id=\d+&?(?:user|admin|role|type)", "Sequential ID parameter", "Low"),
            (r"/admin/.*?(?:\?|&)(?:id|user|account)=\d+", "Admin ID parameter", "High"),
        ]
    },
    "sensitive_exposure": {
        "patterns": [
            (r"(?i)(?:db_|database_)?(?:host|name|user|pass|password|url|connection)\s*[=:]\s*['\"][^'\"]+['\"]", "Database credential exposure", "Critical"),
            (r"(?i)amazonaws\.com.*[A-Z0-9]{20}", "AWS key exposure", "Critical"),
            (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key ID", "Critical"),
            (r"(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private key exposure", "Critical"),
            (r"(?i)(?:mongodb|postgresql|mysql|redis)://[^/\s]+:[^@\s]+@", "Database connection string with credentials", "Critical"),
            (r"(?i)(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36}", "GitHub token", "Critical"),
            (r"(?i)xox[bpras]-[0-9A-Za-z\-]{10,}", "Slack token", "High"),
            (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API key", "Critical"),
            (r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "API key exposure", "Critical"),
            (r"(?i)(?:slack|discord|telegram|twilio)_?(?:token|key|secret|webhook)", "Third-party service secret", "High"),
            (r"(?i)(?:google|gcp|azure|aws)_?(?:client|secret|key|token|certificate)", "Cloud provider secret", "Critical"),
        ]
    },
    "jwt_weakness": {
        "patterns": [
            (r"(?i)alg\s*[=:]\s*['\"]none['\"]", "JWT alg:none - potential bypass", "Critical"),
            (r"(?i)jwt.*algorithm\s*[=:]\s*['\"]HS256['\"]", "JWT using HS256 (check secret strength)", "Medium"),
            (r"(?i)jwt.*secret\s*[=:]\s*['\"][^'\"]{1,10}['\"]", "JWT weak secret", "High"),
            (r"(?i)(?:kid|jku|x5u)\s*[=:]\s*['\"].*['\"]", "JWT header parameter injection potential", "Medium"),
        ]
    },
    "ssrf": {
        "patterns": [
            (r"(?i)(?:url|uri|path|file|load|fetch|read|include|require|import|download|proxy|redirect)\s*[=:]\s*['\"](?:http|https|ftp|file)://", "Potential SSRF parameter", "High"),
            (r"(?i)(?:internal|private|local|metadata)\s*(?:ip|address|endpoint|url)", "Internal resource reference", "Medium"),
            (r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|localhost|127\.0\.0\.1|0\.0\.0\.0)", "Cloud metadata / localhost reference", "Critical"),
        ]
    },
    "xss": {
        "patterns": [
            (r"(?i)<script>.*</script>", "Script injection point", "High"),
            (r"(?i)document\.cookie", "Cookie access via JS", "Medium"),
            (r"(?i)innerHTML\s*=", "Potential XSS via innerHTML", "High"),
            (r"(?i)eval\s*\(", "Eval() usage - potential injection", "High"),
            (r"(?i)onerror\s*=", "Onerror handler", "Medium"),
            (r"(?i)onload\s*=", "Onload handler", "Medium"),
            (r"(?i)onclick\s*=", "Onclick handler", "Low"),
            (r"(?i)(?:<|%3C)[^>]*?(?:script|img|iframe|svg|input|form|a\s+href)", "HTML injection vector", "High"),
        ]
    },
    "sqli": {
        "patterns": [
            (r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\s", "SQL query in body", "High"),
            (r"(?i)SQL syntax.*MySQL|ORA|PostgreSQL|SQLite", "SQL error message", "High"),
            (r"(?i)(?:mysqli?_?|sqlsrv|pgsql|sqlite)_?(?:query|exec|connect|fetch)", "Database function call", "Medium"),
            (r"(?i)You have an error in your SQL syntax", "SQL syntax error exposed", "High"),
            (r"Warning:.*mysql_", "MySQL warning exposed", "High"),
        ]
    },
    "nosqli": {
        "patterns": [
            (r"(?i)\$ne|\$gt|\$lt|\$regex|\$where|\$nin|\$or\s*:", "NoSQL injection operator usage", "High"),
            (r"(?i)db\.\w+\.(?:find|insert|update|remove|aggregate)\s*\(", "MongoDB operation", "Medium"),
            (r"(?i)\$\{.*?\}", "Template injection potential", "Medium"),
        ]
    },
    "file_upload": {
        "patterns": [
            (r"(?i)(?:upload|file|attachment|avatar|photo|image|document|resume)\s*[=:]\s*['\"]", "File upload parameter", "Medium"),
            (r"Content-Disposition:\s*form-data;\s*name=\"[^\"]*?(?:file|upload|image|document)", "File upload form", "Medium"),
            (r"(?i)(?:\.php|\.jsp|\.war|\.exe|\.sh|\.pl|\.py|\.asp|\.aspx|\.cfm|\.shtml)(?:\"|'|\s|$|%00)", "Executable upload extension check", "High"),
        ]
    },
    "graphql": {
        "patterns": [
            (r"(?i)__typename|__schema|introspection", "GraphQL introspection query", "Medium"),
            (r"(?i)graphql", "GraphQL endpoint reference", "Low"),
            (r"(?i)(?:query|mutation)\s+\w+\s*\{[^}]*\{", "GraphQL operation pattern", "Low"),
        ]
    },
    "cors": {
        "patterns": [
            (r"Access-Control-Allow-Origin:\s*\*", "Wildcard CORS origin", "Medium"),
            (r"Access-Control-Allow-Credentials:\s*true", "Credentials with CORS", "High if with wildcard"),
        ]
    },
    "prototype_pollution": {
        "patterns": [
            (r"(?i)__proto__|constructor\.prototype|Object\.assign\s*\(target", "Prototype pollution vector", "High"),
            (r"(?i)merge\s*\(.*true|extend\s*\(.*true|clone\s*\(.*deep", "Deep merge operation", "Medium"),
        ]
    },
    "rate_limiting": {
        "patterns": [
            (r"(?i)rate.limit|rate_limit|ratelimit|429|too many requests|throttl", "Rate limiting reference", "Info"),
        ]
    },
    "hidden_endpoints": {
        "patterns": [
            (r"(?i)(?:/admin|/debug|/test|/dev|/staging|/internal|/private|/api-docs|/swagger|/health|/metrics|/actuator|/graphql|/console)", "Hidden/admin endpoint reference", "Medium"),
            (r"(?i)(?:sourceMappingURL|\.map\s)", "Source map reference", "Low"),
        ]
    },
    "race_condition": {
        "patterns": [
            (r"(?i)(?:balance|transfer|withdraw|redeem|coupon|discount|reward)\s*[=:]", "Race condition sensitive operation", "Medium"),
        ]
    },
    "web_socket": {
        "patterns": [
            (r"(?i)ws://|wss://", "WebSocket connection", "Low"),
        ]
    },
    "oauth": {
        "patterns": [
            (r"(?i)(?:client_id|client_secret|redirect_uri|response_type|grant_type|authorization_code|implicit|pkce)", "OAuth parameter", "Medium"),
            (r"(?i)(?:saml|assertion|sso|idp|sp_entity)", "SAML/SSO reference", "Medium"),
        ]
    },
    "cloud_exposure": {
        "patterns": [
            (r"(?i)(?:s3\.amazonaws|storage\.googleapis|blob\.core\.windows|digitaloceanspaces)", "Cloud storage URL", "High"),
            (r"(?i)(?:bucket|container|blob)\s*[=:]\s*['\"][a-zA-Z0-9_\-]+['\"]", "Storage container reference", "Medium"),
        ]
    },
}

# Common credentials for weak password checks
WEAK_PASSWORDS = [
    "password", "123456", "admin", "root", "test", "guest",
    "qwerty", "letmein", "welcome", "monkey", "passw0rd",
    "p@ssw0rd", "changeme", "default", "secret", "P@ssw0rd",
]

# Common hidden paths to check
HIDDEN_PATHS = [
    "/admin", "/api", "/.env", "/.git/config", "/.git/HEAD",
    "/robots.txt", "/sitemap.xml", "/swagger", "/api-docs",
    "/graphql", "/v1", "/v2", "/health", "/metrics",
    "/actuator", "/actuator/health", "/actuator/info",
    "/console", "/debug", "/test", "/dev", "/staging",
    "/backup", "/wp-admin", "/administrator", "/phpmyadmin",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/.well-known/security.txt", "/package.json",
    "/service-worker.js", "/manifest.json",
]

# ============================================================
# Data Store
# ============================================================
class FindingStore:
    """In-memory + file-backed store for findings"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.findings: List[Dict] = []
        self.hosts: Dict[str, Dict] = {}
        self.sessions: Dict[str, Dict] = {}
        self.traffic_count = 0
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path) as f:
                    data = json.load(f)
                    self.findings = data.get("findings", [])
                    self.hosts = data.get("hosts", {})
                    self.sessions = data.get("sessions", {})
                    self.traffic_count = data.get("traffic_count", 0)
            except Exception:
                pass

    def save(self):
        with self._lock:
            data = {
                "findings": self.findings[-500:],  # Keep last 500
                "hosts": self.hosts,
                "sessions": self.sessions,
                "traffic_count": self.traffic_count,
                "updated_at": datetime.now().isoformat()
            }
            try:
                with open(self.db_path, "w") as f:
                    json.dump(data, f, indent=2)
            except Exception:
                pass

    def add_finding(self, finding: Dict):
        with self._lock:
            finding["id"] = str(uuid.uuid4())
            finding["timestamp"] = datetime.now().isoformat()
            self.findings.append(finding)

            # Update host stats
            host = finding.get("host", "unknown")
            if host not in self.hosts:
                self.hosts[host] = {"findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            self.hosts[host]["findings"] += 1
            sev = finding.get("severity", "info").lower()
            if sev in self.hosts[host]:
                self.hosts[host][sev] += 1

            self.save()
            return finding["id"]

    def add_traffic(self):
        with self._lock:
            self.traffic_count += 1

    def get_stats(self) -> Dict:
        with self._lock:
            stats = {
                "total_findings": len(self.findings),
                "total_traffic": self.traffic_count,
                "total_hosts": len(self.hosts),
                "total_sessions": len(self.sessions),
                "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "category_counts": {},
                "recent_findings": self.findings[-20:][::-1],
                "hosts": dict(list(self.hosts.items())[:50]),
                "top_categories": [],
            }

            for f in self.findings:
                sev = f.get("severity", "info").lower()
                if sev in stats["severity_counts"]:
                    stats["severity_counts"][sev] += 1

                cat = f.get("category", "other")
                stats["category_counts"][cat] = stats["category_counts"].get(cat, 0) + 1

            # Sort categories
            stats["top_categories"] = sorted(
                stats["category_counts"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            return stats


# Initialize store
store = FindingStore(CONFIG["db_path"])

# ============================================================
# Pattern Detection Engine
# ============================================================
class PatternDetector:
    """Detects vulnerability patterns in traffic data"""

    def __init__(self):
        self.compiled_patterns = {}
        for category, data in VULN_PATTERNS.items():
            self.compiled_patterns[category] = []
            for pattern, name, severity in data["patterns"]:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                    self.compiled_patterns[category].append((compiled, name, severity))
                except Exception as e:
                    print(f"[!] Bad regex: {pattern} - {e}")

    def analyze(self, data: Dict) -> List[Dict]:
        """Analyze traffic data for vulnerability patterns"""
        findings = []
        body = data.get("body", "")
        url = data.get("url", "")
        headers = data.get("headers", {})
        params = data.get("params", [])
        source = data.get("source", "unknown")

        if not body and not url:
            return findings

        # Combine all text to analyze
        text_to_check = body + "\n" + url + "\n" + str(headers) + "\n" + str(params)

        for category, patterns in self.compiled_patterns.items():
            for compiled, name, severity in patterns:
                matches = compiled.findall(text_to_check)
                if matches:
                    # Deduplicate matches
                    unique_matches = list(set(matches))[:3]
                    for match_text in unique_matches:
                        match_str = str(match_text)[:200] if match_text else ""

                        finding = {
                            "type": "pattern",
                            "category": category,
                            "name": name,
                            "severity": severity,
                            "url": url,
                            "host": data.get("host", ""),
                            "method": data.get("method", ""),
                            "match": match_str,
                            "evidence": f"Pattern matched: {name}",
                            "source": source,
                            "confidence": self._get_confidence(severity),
                            "remediation": self._get_remediation(category, name),
                        }
                        findings.append(finding)

        return findings

    def _get_confidence(self, severity: str) -> float:
        mapping = {"critical": 0.95, "high": 0.85, "medium": 0.7, "low": 0.5, "info": 0.3}
        return mapping.get(severity.lower(), 0.5)

    def _get_remediation(self, category: str, name: str) -> str:
        remediation_map = {
            "authentication": "Implement proper authentication mechanisms. Never hardcode credentials.",
            "authorization_idor": "Implement proper access controls. Use UUIDs instead of sequential IDs.",
            "sensitive_exposure": "Remove sensitive data from responses. Use environment variables for secrets.",
            "jwt_weakness": "Use strong JWT secrets, set appropriate expiry, validate algorithm.",
            "ssrf": "Validate and sanitize URL inputs. Use allowlists for destinations.",
            "xss": "Implement Content-Security-Policy and proper output encoding.",
            "sqli": "Use parameterized queries or prepared statements.",
            "nosqli": "Validate and sanitize inputs. Avoid $where and $regex where possible.",
            "file_upload": "Validate file types, scan uploads, store outside webroot.",
            "graphql": "Disable introspection in production. Implement query depth limiting.",
            "cors": "Restrict Access-Control-Allow-Origin to specific trusted origins.",
            "prototype_pollution": "Use Object.create(null) or Object.freeze for objects.",
            "rate_limiting": "Implement proper rate limiting on sensitive endpoints.",
            "hidden_endpoints": "Remove debug/admin endpoints from production.",
            "race_condition": "Implement proper locking mechanisms for sensitive operations.",
            "oauth": "Follow OAuth best practices. Use PKCE for public clients.",
            "cloud_exposure": "Use signed URLs, block public access to storage buckets."
        }
        return remediation_map.get(category, "Review and fix the identified security issue.")


detector = PatternDetector()

# ============================================================
# Ollama Integration
# ============================================================
class OllamaClient:
    """Client for interacting with local Ollama API"""

    def __init__(self, base_url: str = "http://127.0.0.1:11434"):
        self.base_url = base_url
        self.timeout = 120
        self.available = False
        self.models = []
        self.check_connection()

    def check_connection(self) -> bool:
        """Check if Ollama is running and list available models"""
        try:
            if HAS_HTTPX:
                import httpx
                r = httpx.get(f"{self.base_url}/api/tags", timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    self.models = [m["name"] for m in data.get("models", [])]
                    self.available = True
                    print(f"[+] Ollama connected. Models: {', '.join(self.models[:5])}")
                    return True
            else:
                import urllib.request
                r = urllib.request.urlopen(f"{self.base_url}/api/tags", timeout=5)
                if r.status == 200:
                    data = json.loads(r.read())
                    self.models = [m["name"] for m in data.get("models", [])]
                    self.available = True
                    return True
        except Exception as e:
            print(f"[!] Ollama not available: {e}")
            self.available = False
            return False
        return False

    def get_recommended_model(self) -> str:
        """Get the best available model"""
        preferred = ["llama3.1:8b", "llama3:8b", "deepseek-coder:6.7b", "deepseek-coder-v2",
                     "codellama:7b", "mistral:7b", "mixtral:8x7b", "qwen2.5-coder:7b"]
        for model in preferred:
            for avail in self.models:
                if model in avail or avail.startswith(model):
                    print(f"[+] Using model: {avail}")
                    return avail
        if self.models:
            return self.models[0]
        return CONFIG["model"]

    def analyze(self, data: Dict) -> Dict:
        """Send traffic data to Ollama for deep analysis"""
        if not self.available:
            return {"ai_analyzed": False, "reason": "Ollama not available"}

        model = self.get_recommended_model()
        prompt = self._build_prompt(data)

        try:
            if HAS_HTTPX:
                import httpx
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(
                        f"{self.base_url}/api/generate",
                        json={
                            "model": model,
                            "prompt": prompt,
                            "stream": False,
                            "options": {
                                "temperature": 0.1,
                                "top_p": 0.9,
                                "num_predict": 1024,
                            }
                        }
                    )

                    if response.status_code == 200:
                        result = response.json()
                        return self._parse_ai_response(result.get("response", ""))
                    else:
                        return {"ai_analyzed": False, "error": f"HTTP {response.status_code}"}
            else:
                import urllib.request
                req_data = json.dumps({
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,
                        "top_p": 0.9,
                        "num_predict": 1024,
                    }
                }).encode()

                req = urllib.request.Request(
                    f"{self.base_url}/api/generate",
                    data=req_data,
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    result = json.loads(r.read())
                    return self._parse_ai_response(result.get("response", ""))

        except Exception as e:
            return {"ai_analyzed": True, "error": str(e), "findings": []}

    def _build_prompt(self, data: Dict) -> str:
        """Build security analysis prompt"""
        data_type = data.get("type", "unknown")
        url = data.get("url", "")
        method = data.get("method", "")
        host = data.get("host", "")
        path = data.get("path", "")
        status_code = data.get("status_code", 0)
        body = data.get("body", "")[:3000]  # Limit body size for prompt
        headers = data.get("headers", {})
        params = data.get("params", [])
        content_type = data.get("content_type", "")
        interesting = data.get("interesting_patterns", [])

        prompt = f"""You are a ruthless security analyst conducting a bug bounty assessment. 
Analyze the following HTTP {data_type} and identify ALL security vulnerabilities.

IMPORTANT: Be extremely thorough. Look for subtle issues that automated scanners miss.

DATA:
- URL: {url}
- Method: {method}
- Host: {host}
- Path: {path}
- Status Code: {status_code}
- Content-Type: {content_type}
- Interesting Patterns: {interesting}

HEADERS:
{json.dumps(headers, indent=2) if isinstance(headers, dict) else headers}

PARAMETERS:
{json.dumps(params, indent=2) if isinstance(params, list) else params}

BODY:
{body[:2000]}

INSTRUCTIONS:
Analyze for:
1. Authentication & Authorization flaws (IDOR, privilege escalation, access control)
2. Injection vulnerabilities (SQL, NoSQL, Command, LDAP, XSS)
3. Sensitive data exposure (keys, tokens, PII, credentials)
4. Logic flaws & business logic issues
5. Server-Side Request Forgery (SSRF)
6. Insecure Direct Object References (IDOR)
7. Cross-Site Request Forgery (CSRF)
8. Race conditions & timing attacks
9. JWT weaknesses & session handling issues
10. API misconfigurations & GraphQL abuse
11. CORS & CSRF issues
12. Rate limiting & brute force protection gaps
13. Hidden endpoints, debug routes, source maps
14. Prototype pollution (for JS/Node apps)
15. File upload & path traversal issues
16. Cache poisoning & Web Cache deception
17. OAuth & SAML misconfigurations
18. Cloud storage exposure

For EACH finding, output exactly in this JSON format:
{{
  "findings": [
    {{
      "vulnerability": "Finding name",
      "type": "CATEGORY",
      "severity": "Critical|High|Medium|Low|Info",
      "description": "Concise description of the vulnerability",
      "evidence": "Specific evidence from the data",
      "impact": "What an attacker could do",
      "remediation": "How to fix it",
      "confidence": 0.0-1.0
    }}
  ]
}}

If no vulnerabilities are found, output: {{"findings": []}}
Be aggressive but realistic. A finding with low confidence is better than a missed finding.
"""
        return prompt

    def _parse_ai_response(self, response: str) -> Dict:
        """Parse the AI response, extracting JSON findings"""
        result = {"ai_analyzed": True, "findings": []}

        try:
            # Try to extract JSON from the response
            json_match = re.search(r'\{[\s\S]*"findings"[\s\S]*\]\s*\}', response)
            if json_match:
                parsed = json.loads(json_match.group())
                findings = parsed.get("findings", [])
                result["findings"] = findings
            else:
                # Fallback: look for any JSON object
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    parsed = json.loads(json_match.group())
                    result["findings"] = parsed.get("findings", [])
                else:
                    result["error"] = "Could not parse AI response"
                    result["raw_response"] = response[:500]
        except Exception as e:
            result["error"] = f"Parse error: {str(e)}"
            result["raw_response"] = response[:500]

        return result


ollama_client = OllamaClient(CONFIG["ollama_host"])

# ============================================================
# FastAPI Application
# ============================================================
app = FastAPI(
    title="BurpOllama Analyzer",
    version="2.0.0",
    description="Local bug hunting pipeline with AI-powered analysis"
)

# CORS - allow Burp and dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket connections
active_websockets: List[WebSocket] = []

# ============================================================
# Analysis Pipeline
# ============================================================
analysis_queue = queue.Queue()
analysis_in_progress = 0
analysis_lock = threading.Lock()


def process_traffic(data: Dict):
    """Process incoming traffic data - pattern detection + optional AI analysis"""
    store.add_traffic()

    # 1. Pattern-based detection (always runs, instant)
    if CONFIG["enable_pattern_detection"]:
        pattern_findings = detector.analyze(data)
        for finding in pattern_findings:
            finding["host"] = data.get("host", data.get("host", ""))
            fid = store.add_finding(finding)
            _broadcast_finding(finding)

    # 2. Ollama AI analysis (runs async)
    if CONFIG["enable_ollama"] and ollama_client.available:
        # Queue for background processing
        analysis_queue.put(data)
        _process_analysis_queue()


def _process_analysis_queue():
    """Process queued items for AI analysis"""
    global analysis_in_progress

    with analysis_lock:
        if analysis_in_progress >= CONFIG["max_concurrent_analysis"]:
            return
        if analysis_queue.empty():
            return
        analysis_in_progress += 1

    try:
        while not analysis_queue.empty():
            data = analysis_queue.get_nowait()
            try:
                result = ollama_client.analyze(data)
                if result.get("ai_analyzed") and result.get("findings"):
                    for finding in result["findings"]:
                        finding["type"] = "ai_analysis"
                        finding["url"] = data.get("url", "")
                        finding["host"] = data.get("host", "")
                        finding["method"] = data.get("method", "")
                        finding["source"] = "ollama_analysis"
                        fid = store.add_finding(finding)
                        _broadcast_finding(finding)
            except Exception as e:
                print(f"[!] AI analysis error: {e}")
            finally:
                analysis_queue.task_done()
    finally:
        with analysis_lock:
            analysis_in_progress -= 1


def _broadcast_finding(finding: Dict):
    """Broadcast finding to all connected dashboard clients"""
    message = json.dumps({
        "type": "new_finding",
        "data": finding,
        "stats": store.get_stats()
    })

    # Run async broadcast
    loop = None
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        pass

    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(
            _broadcast(message), loop
        )


async def _broadcast(message: str):
    """Send message to all connected WebSocket clients"""
    dead_sockets = []
    for ws in active_websockets:
        try:
            await ws.send_text(message)
        except Exception:
            dead_sockets.append(ws)

    for ws in dead_sockets:
        if ws in active_websockets:
            active_websockets.remove(ws)


# ============================================================
# API Endpoints
# ============================================================

@app.get("/")
async def root():
    """Serve the dashboard"""
    dashboard_path = Path(__file__).parent.parent / "dashboard" / "index.html"
    if dashboard_path.exists():
        return HTMLResponse(dashboard_path.read_text())
    return {
        "service": "BurpOllama Analyzer",
        "version": "2.0.0",
        "status": "running",
        "ollama": ollama_client.available,
        "ollama_models": ollama_client.models,
        "stats": store.get_stats()
    }


@app.get("/dashboard")
async def dashboard():
    """Explicit dashboard endpoint"""
    dashboard_path = Path(__file__).parent.parent / "dashboard" / "index.html"
    if dashboard_path.exists():
        return HTMLResponse(dashboard_path.read_text())
    return {"error": "Dashboard not found"}


@app.post("/api/traffic")
async def receive_traffic(request: Request):
    """Receive traffic data from Burp extension"""
    try:
        data = await request.json()
        # Process in background thread to not block
        thread = threading.Thread(target=process_traffic, args=(data,), daemon=True)
        thread.start()
        return {"status": "received", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(e)}
        )


@app.post("/api/analyze")
async def analyze_manual(request: Request):
    """Manual analysis endpoint - send arbitrary data for analysis"""
    try:
        data = await request.json()
        pattern_findings = detector.analyze(data)

        ai_result = {"ai_analyzed": False}
        if ollama_client.available:
            ai_result = ollama_client.analyze(data)

        return {
            "pattern_findings": pattern_findings,
            "ai_analysis": ai_result,
            "stats": store.get_stats()
        }
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"status": "error", "message": str(e)}
        )


@app.get("/api/stats")
async def get_stats():
    """Get current statistics"""
    return store.get_stats()


@app.get("/api/findings")
async def get_findings(limit: int = 50, severity: str = None, category: str = None):
    """Get findings with optional filtering"""
    findings = store.findings

    if severity:
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]

    if category:
        findings = [f for f in findings if f.get("category", "").lower() == category.lower()]

    return {
        "total": len(findings),
        "findings": findings[::-1][:limit]  # Most recent first
    }


@app.get("/api/hosts")
async def get_hosts():
    """Get host information"""
    return store.hosts


@app.get("/api/config")
async def get_config():
    """Get current configuration"""
    config = dict(CONFIG)
    config["ollama_models"] = ollama_client.models
    config["ollama_available"] = ollama_client.available
    config["recommended_model"] = ollama_client.get_recommended_model() if ollama_client.available else None
    return config


@app.post("/api/config")
async def update_config(request: Request):
    """Update configuration"""
    global CONFIG
    try:
        updates = await request.json()
        for key, value in updates.items():
            if key in CONFIG and key not in ["db_path", "data_dir"]:
                CONFIG[key] = value
        return {"status": "updated", "config": CONFIG}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.post("/api/ollama/check")
async def check_ollama():
    """Re-check Ollama connection"""
    available = ollama_client.check_connection()
    return {
        "available": available,
        "models": ollama_client.models,
        "recommended": ollama_client.get_recommended_model() if available else None
    }


@app.post("/api/clear")
async def clear_findings():
    """Clear all findings"""
    global store
    store = FindingStore(CONFIG["db_path"])
    return {"status": "cleared"}


@app.post("/api/scan_host")
async def scan_host(request: Request):
    """Trigger a focused analysis on a specific host"""
    try:
        data = await request.json()
        host = data.get("host", "")
        url = data.get("url", "")

        # Focus analysis on this host's traffic
        host_findings = [f for f in store.findings if f.get("host") == host or host in f.get("url", "")]

        return {
            "host": host,
            "total_findings": len(host_findings),
            "critical": len([f for f in host_findings if f.get("severity", "").lower() == "critical"]),
            "high": len([f for f in host_findings if f.get("severity", "").lower() == "high"]),
            "findings": host_findings[-20:][::-1]
        }
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


# ============================================================
# WebSocket for Real-time Dashboard
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    try:
        # Send initial stats
        await websocket.send_text(json.dumps({
            "type": "init",
            "stats": store.get_stats(),
            "ollama_available": ollama_client.available,
            "ollama_models": ollama_client.models,
            "config": {k: v for k, v in CONFIG.items() if k not in ["data_dir"]}
        }))

        # Keep connection alive and handle incoming messages
        while True:
            try:
                data = await websocket.receive_text()
                msg = json.loads(data)

                # Handle client commands
                if msg.get("action") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))

                elif msg.get("action") == "scan_host":
                    host = msg.get("host", "")
                    host_findings = [f for f in store.findings if f.get("host") == host]
                    await websocket.send_text(json.dumps({
                        "type": "host_scan",
                        "host": host,
                        "findings": host_findings[-20:][::-1]
                    }))

                elif msg.get("action") == "get_config":
                    cfg = dict(CONFIG)
                    cfg["ollama_models"] = ollama_client.models
                    cfg["ollama_available"] = ollama_client.available
                    await websocket.send_text(json.dumps({
                        "type": "config",
                        "config": cfg
                    }))

            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                pass
    except Exception as e:
        print(f"[!] WebSocket error: {e}")
    finally:
        if websocket in active_websockets:
            active_websockets.remove(websocket)


# ============================================================
# Entry Point
# ============================================================

def start_server():
    """Start the analyzer server"""
    print("""
    ╔════════════════════════════════════════════╗
    ║       BurpOllama Analyzer Server v2.0       ║
    ║    Local AI-Powered Bug Hunting Pipeline     ║
    ╚════════════════════════════════════════════╝
    """)
    print(f"[+] Listening on http://{CONFIG['host']}:{CONFIG['port']}")
    print(f"[+] Ollama: {'Connected' if ollama_client.available else 'Not available'}")
    if ollama_client.available:
        print(f"[+] Models: {', '.join(ollama_client.models[:5])}")
        print(f"[+] Recommended: {ollama_client.get_recommended_model()}")
    print(f"[+] Pattern detection: {'Enabled' if CONFIG['enable_pattern_detection'] else 'Disabled'}")
    print(f"[+] AI analysis: {'Enabled' if CONFIG['enable_ollama'] else 'Disabled'}")
    print(f"[+] Dashboard: http://{CONFIG['host']}:{CONFIG['port']}")
    print(f"[+] WebSocket: ws://{CONFIG['host']}:{CONFIG['port']}/ws")
    print(f"[+] Burp extension endpoint: POST http://{CONFIG['host']}:{CONFIG['port']}/api/traffic")
    print()

    uvicorn.run(
        app,
        host=CONFIG["host"],
        port=CONFIG["port"],
        log_level="info",
        ws_max_size=16777216
    )


if __name__ == "__main__":
    start_server()
