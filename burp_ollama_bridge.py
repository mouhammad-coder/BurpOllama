"""
BurpOllama Bridge - Burp Suite Extension (Jython)
Intercepts HTTP traffic and routes to local analyzer server + Ollama
"""
from __future__ import absolute_import, division, print_function

import json
import socket
import threading
import time
import uuid
from datetime import datetime
from java.io import PrintWriter
from java.net import URL
from java.util import List, ArrayList

# Burp imports - these are provided by Jython at runtime in Burp
try:
    from burp import IBurpExtender, IScannerCheck, IScanIssue, IHttpListener, ITab
    from javax.swing import JPanel, JTextArea, JScrollPane, JButton, JLabel, BorderFactory
    from javax.swing import SwingUtilities
    from java.awt import BorderLayout, FlowLayout
    from java.awt import Color, Font
except ImportError:
    # For development/testing outside Burp
    pass

import base64

BURP_OLLAMA_VERSION = "2.0.0"
ANALYZER_HOST = "127.0.0.1"
ANALYZER_PORT = 9999

class BurpOllamaBridge:
    """Main Burp extension class - intercepts traffic and sends to analyzer"""

    def __init__(self):
        self._callbacks = None
        self._helpers = None
        self._stdout = None
        self._stderr = None
        self._session_id = str(uuid.uuid4())[:8]
        self._analyzer_url = "http://{}:{}".format(ANALYZER_HOST, ANALYZER_PORT)
        self._stats = {
            "requests_sent": 0,
            "findings_found": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
            "info": 0
        }
        self._scope_urls = []
        self._enabled = True
        self._config = {
            "intercept_requests": True,
            "intercept_responses": True,
            "max_body_size": 500000,  # 500KB max
            "send_to_ollama": True,
            "include_source_maps": False
        }

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpOllama Bridge v" + BURP_OLLAMA_VERSION)

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        self._stdout.println("[+] BurpOllama Bridge v{} loaded".format(BURP_OLLAMA_VERSION))
        self._stdout.println("[+] Session: {}".format(self._session_id))
        self._stdout.println("[+] Analyzer target: {}".format(self._analyzer_url))

        # Register HTTP listener
        callbacks.registerHttpListener(self)

        # Register scanner if available
        try:
            callbacks.registerScannerCheck(self)
            self._stdout.println("[+] Registered scanner check")
        except:
            self._stdout.println("[*] Scanner check not available")

        self._stdout.println("[+] Ready - all traffic being intercepted")
        self._stdout.flush()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Called for every HTTP message - this is the core interceptor"""
        if not self._enabled:
            return

        try:
            tool_name = self._get_tool_name(toolFlag)

            if messageIsRequest:
                if not self._config["intercept_requests"]:
                    return
                self._analyze_request(messageInfo, tool_name)
            else:
                if not self._config["intercept_responses"]:
                    return
                self._analyze_response(messageInfo, tool_name)

        except Exception as e:
            self._stderr.println("[!] Error processing HTTP message: {}".format(str(e)))
            self._stderr.flush()

    def _analyze_request(self, messageInfo, tool_name):
        """Extract and send request data to analyzer"""
        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            host = url.getHost()
            port = url.getPort()
            protocol = url.getProtocol()
            path = url.getPath()
            query = url.getQuery()
            method = request_info.getMethod()

            # Get raw request body
            body_offset = request_info.getBodyOffset()
            request_bytes = messageInfo.getRequest()
            body = ""
            if len(request_bytes) > body_offset:
                body = self._helpers.bytesToString(request_bytes[body_offset:])

            # Get headers
            headers_dict = {}
            for header in request_info.getHeaders():
                if ": " in header:
                    key, val = header.split(": ", 1)
                    headers_dict[key] = val
                elif header.startswith("GET ") or header.startswith("POST ") or header.startswith("PUT ") or header.startswith("DELETE ") or header.startswith("PATCH ") or header.startswith("OPTIONS ") or header.startswith("HEAD "):
                    continue

            # Get parameters
            params = []
            parameters = request_info.getParameters()
            if parameters:
                for param in parameters:
                    params.append({
                        "name": str(param.getName()),
                        "value": str(param.getValue()),
                        "type": str(param.getType())
                    })

            # Build payload
            payload = {
                "type": "request",
                "tool": tool_name,
                "session_id": self._session_id,
                "timestamp": datetime.now().isoformat(),
                "url": str(url.toString()),
                "host": str(host),
                "port": port,
                "protocol": str(protocol),
                "path": str(path),
                "query": str(query) if query else "",
                "method": str(method),
                "headers": headers_dict,
                "body": body[:self._config["max_body_size"]],
                "params": params,
                "content_type": headers_dict.get("Content-Type", ""),
                "source": "burp_intercept"
            }

            self._send_to_analyzer(payload)
            self._stats["requests_sent"] += 1

        except Exception as e:
            self._stderr.println("[!] Request analysis error: {}".format(str(e)))

    def _analyze_response(self, messageInfo, tool_name):
        """Extract response data and send to analyzer"""
        try:
            response_bytes = messageInfo.getResponse()
            if not response_bytes:
                return

            response_info = self._helpers.analyzeResponse(response_bytes)
            status_code = response_info.getStatusCode()
            body_offset = response_info.getBodyOffset()
            body = ""
            if len(response_bytes) > body_offset:
                body = self._helpers.bytesToString(response_bytes[body_offset:])

            # Get response headers
            headers_dict = {}
            for header in response_info.getHeaders():
                if ": " in header:
                    key, val = header.split(": ", 1)
                    headers_dict[key] = val

            # Get associated request info
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()

            # Check for interesting response patterns
            interesting_patterns = self._check_interesting_responses(body, headers_dict, status_code)

            payload = {
                "type": "response",
                "tool": tool_name,
                "session_id": self._session_id,
                "timestamp": datetime.now().isoformat(),
                "url": str(url.toString()),
                "status_code": status_code,
                "headers": headers_dict,
                "body": body[:self._config["max_body_size"]],
                "content_type": headers_dict.get("Content-Type", ""),
                "content_length": headers_dict.get("Content-Length", str(len(body))),
                "interesting_patterns": interesting_patterns,
                "source": "burp_intercept"
            }

            self._send_to_analyzer(payload)

            if interesting_patterns:
                self._stdout.println("[!] Interesting patterns found at {}: {}".format(
                    url.toString(), ", ".join(interesting_patterns)))

        except Exception as e:
            self._stderr.println("[!] Response analysis error: {}".format(str(e)))

    def _check_interesting_responses(self, body, headers, status_code):
        """Check for interesting patterns in responses"""
        patterns = []
        if not body:
            return patterns

        # Check for sensitive exposure
        checks = [
            ('.env', 'Environment file detected'),
            ('-----BEGIN RSA PRIVATE KEY-----', 'Private key exposed'),
            ('-----BEGIN OPENSSH PRIVATE KEY-----', 'SSH key exposed'),
            ('-----BEGIN CERTIFICATE-----', 'Certificate exposed'),
            ('access_key', 'Access key pattern'),
            ('secret_key', 'Secret key pattern'),
            ('aws_secret', 'AWS secret pattern'),
            ('api_key', 'API key pattern'),
            ('apiKey', 'API key (camelCase)'),
            ('API_KEY', 'API_KEY pattern'),
            ('password', 'Password field in response'),
            ('passwd', 'Passwd pattern'),
            ('db_password', 'Database password'),
            ('jdbc:mysql', 'JDBC connection string'),
            ('jdbc:postgresql', 'PostgreSQL connection string'),
            ('mongodb://', 'MongoDB connection string'),
            ('redis://', 'Redis connection string'),
            ('s3://', 'S3 bucket pattern'),
            ('bucket', 'Bucket reference'),
            ('storage.googleapis.com', 'GCP storage reference'),
            ('blob.core.windows.net', 'Azure blob reference'),
            ('sourceMappingURL', 'Source map detected'),
            ('swagger', 'Swagger/OpenAPI reference'),
            ('api-docs', 'API documentation'),
            ('graphql', 'GraphQL endpoint reference'),
            ('localhost', 'Localhost reference'),
            ('internal', 'Internal reference'),
            ('admin', 'Admin reference'),
            ('debug', 'Debug mode in response'),
            ('stacktrace', 'Stacktrace in response'),
            ('error', 'Error information'),
            ('exception', 'Exception details'),
            ('token', 'Token pattern'),
            ('jwt', 'JWT token reference'),
            ('session', 'Session reference'),
            ('csrf', 'CSRF token'),
            ('xsrf', 'XSRF token'),
            ('Set-Cookie', 'Cookie set'),
            ('credentials', 'Credentials reference'),
            ('authorization', 'Authorization header'),
            ('bearer', 'Bearer token'),
            ('otp', 'OTP/2FA code'),
            ('secret', 'Secret reference'),
            ('private_key', 'Private key reference'),
            ('-----END', 'End of certificate/key block'),
        ]

        for pattern, label in checks:
            if pattern.lower() in body.lower():
                patterns.append(label)

        # Check status codes
        if status_code == 401:
            patterns.append("401 Unauthorized - possible auth bypass target")
        elif status_code == 403:
            patterns.append("403 Forbidden - possible access control issue")
        elif status_code == 500:
            patterns.append("500 Internal Server Error - debugging opportunity")
        elif status_code == 302:
            patterns.append("302 Redirect - check for open redirect")
        elif status_code == 405:
            patterns.append("405 Method Not Allowed - check for method bypass")

        # Check headers
        for header, value in headers.items():
            header_lower = header.lower()
            if header_lower == "server" and "nginx" in value.lower():
                pass  # Common, not notable
            elif header_lower == "x-powered-by" and "express" in value.lower():
                patterns.append("Express.js detected - check for known vulns")
            elif header_lower == "access-control-allow-origin" and value == "*":
                patterns.append("CORS: Wildcard origin - potential CORS vuln")
            elif header_lower == "access-control-allow-credentials" and value == "true":
                if headers.get("Access-Control-Allow-Origin", "") == "*":
                    patterns.append("CORS: Credentials + wildcard - VULNERABLE")
            elif header_lower == "x-aspnet-version":
                patterns.append("ASP.NET version exposed - " + value)

        return list(set(patterns))

    def _send_to_analyzer(self, payload):
        """Send payload to the local analyzer server"""
        try:
            data = json.dumps(payload)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((ANALYZER_HOST, ANALYZER_PORT))

            # Simple HTTP POST
            http_request = (
                "POST /api/traffic HTTP/1.1\r\n"
                "Host: {}:{}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: {}\r\n"
                "X-Burp-Session: {}\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{}"
            ).format(ANALYZER_HOST, ANALYZER_PORT, len(data), self._session_id, data)

            sock.sendall(http_request.encode("utf-8"))
            sock.close()
        except Exception:
            pass  # Analyzer might be down - silently retry later

    def _get_tool_name(self, toolFlag):
        tools = {
            1: "Suite", 2: "Target", 4: "Proxy", 8: "Spider",
            16: "Scanner", 32: "Intruder", 64: "Repeater", 
            128: "Sequencer", 256: "Decoder", 512: "Comparer",
            1024: "Extender", 2048: "WebSocket"
        }
        return tools.get(toolFlag, "Unknown")

    # --- Scanner Check for active scanning ---
    def doPassiveScan(self, baseRequestResponse):
        """Passive scanning - checks responses for issues"""
        findings = []
        try:
            response = baseRequestResponse.getResponse()
            if not response:
                return findings

            response_info = self._helpers.analyzeResponse(response)
            body_offset = response_info.getBodyOffset()
            body = ""
            if len(response) > body_offset:
                body = self._helpers.bytesToString(response[body_offset:])

            headers_dict = {}
            for header in response_info.getHeaders():
                if ": " in header:
                    key, val = header.split(": ", 1)
                    headers_dict[key] = val

            # Check for various issues
            ctype = headers_dict.get("Content-Type", "")

            # Source map disclosure
            if "sourceMappingURL" in body and "application/json" not in ctype.lower():
                start = body.find("sourceMappingURL=")
                if start > 0:
                    sm_end = body.find("\n", start)
                    if sm_end < 0:
                        sm_end = min(start + 200, len(body))
                    sourcemap_url = body[start:sm_end].strip()
                    findings.append(self._make_issue(
                        baseRequestResponse,
                        "Source Map Disclosure",
                        "The response contains a source map reference which could expose source code.",
                        "Information", "Firm"
                    ))

            # Check for .env exposure
            if body.strip().startswith("APP_ENV=") or "DB_HOST=" in body:
                findings.append(self._make_issue(
                    baseRequestResponse,
                    "Environment File Exposure",
                    "The response contains environment variable patterns (.env file).",
                    "High", "Certain"
                ))

            # Check for API keys
            api_key_patterns = ['api_key', 'apiKey', 'api-key', 'apikey', 'secret_key', 'aws_secret']
            for pattern in api_key_patterns:
                if pattern in body.lower():
                    findings.append(self._make_issue(
                        baseRequestResponse,
                        "Potential API Key Exposure",
                        "Response may contain exposed API keys or secrets.",
                        "High", "Tentative"
                    ))
                    break

            # Check CORS
            acao = headers_dict.get("Access-Control-Allow-Origin", "")
            acac = headers_dict.get("Access-Control-Allow-Credentials", "")
            if acao == "*" and acac.lower() == "true":
                findings.append(self._make_issue(
                    baseRequestResponse,
                    "CORS Misconfiguration",
                    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                    "High", "Certain"
                ))

        except Exception as e:
            self._stderr.println("[!] Passive scan error: {}".format(str(e)))

        return findings

    def _make_issue(self, baseRequestResponse, name, detail, severity, confidence):
        """Create a scan issue"""
        from burp import IScanIssue
        import sys

        class CustomIssue(IScanIssue):
            def __init__(self, parent, base, name, detail, severity, confidence):
                self._parent = parent
                self._base = base
                self._name = name
                self._detail = detail
                self._severity = severity
                self._confidence = confidence

            def getUrl(self):
                return self._parent._helpers.analyzeRequest(self._base).getUrl()

            def getIssueName(self):
                return self._name

            def getIssueType(self):
                return 0x08000000  # Custom issue type

            def getSeverity(self):
                return self._severity

            def getConfidence(self):
                return self._confidence

            def getIssueBackground(self):
                return "Detection by BurpOllama Bridge - Automated Analysis"

            def getRemediationBackground(self):
                return "Review and address the identified security issue."

            def getIssueDetail(self):
                return self._detail

            def getRemediationDetail(self):
                return ""

            def getHttpMessages(self):
                return [self._base]

            def getHttpService(self):
                return self._base.getHttpService()

        return CustomIssue(
            self, baseRequestResponse, name, detail, severity, confidence
        )

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning stub - real AI-powered scanning happens via Ollama"""
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0


# Required for Jython Burp Extender
try:
    if __name__ in ("__builtin__", "builtins"):
        burp_extender = BurpOllamaBridge()
        registerExtenderCallbacks = burp_extender.registerExtenderCallbacks
        print("[+] BurpOllama Bridge loaded as extender")
except NameError:
    pass
