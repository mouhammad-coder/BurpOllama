#!/usr/bin/env python3
"""End-to-end production readiness smoke test for the scan pipeline."""

import asyncio
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hunt_engine import run_hunt  # noqa: E402
from recon_engine import run_full_recon  # noqa: E402


PORT = 19999
TARGET = f"http://localhost:{PORT}"


class MockTargetHandler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def log_message(self, fmt, *args):
        return

    def _send(self, status=200, body="", content_type="text/html"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(
                200,
                """
                <html>
                  <body>
                    <a href="/login">login</a>
                    <a href="/api/users">users</a>
                    <a href="/admin">admin</a>
                  </body>
                </html>
                """,
            )
        elif path == "/login":
            self._send(
                200,
                '<form method="post" action="/login"><input name="email"></form>',
            )
        elif path == "/api/users":
            self._send(
                200,
                json.dumps({"users": [{"id": 1, "email": "test@test.com"}]}),
                "application/json",
            )
        elif path == "/admin":
            self._send(403, "Forbidden", "text/plain")
        elif path == "/.env":
            self._send(200, "DB_PASSWORD=secret123", "text/plain")
        elif path == "/api/users/1":
            self._send(200, json.dumps({"id": 1, "name": "Alice"}), "application/json")
        elif path == "/api/users/2":
            self._send(200, json.dumps({"id": 2, "name": "Bob"}), "application/json")
        else:
            self._send(404, "Not found", "text/plain")


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), MockTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.25)
    return server, thread


def _finding_text(finding):
    return " ".join(str(finding.get(key, "")) for key in (
        "vuln_type",
        "title",
        "category",
        "url",
        "affected_url",
        "evidence",
        "description",
    )).lower()


async def run_pipeline_check():
    logs = []

    async def log(message, level="info"):
        logs.append((level, str(message)))

    results = []
    errors = []
    recon_data = {}
    findings = []

    try:
        recon_data = await run_full_recon(
            TARGET,
            log,
            adaptive_plan={"level": "LIGHT", "max_urls": 50, "concurrency": 4},
        )
    except Exception as exc:
        errors.append(f"recon exception: {exc}")

    urls = recon_data.get("urls", []) if isinstance(recon_data, dict) else []
    live_hosts = recon_data.get("live_hosts", []) if isinstance(recon_data, dict) else []
    results.append((
        "recon discovers at least 4 URLs",
        len(urls) >= 4,
        f"discovered {len(urls)} URL(s): {urls[:8]}",
    ))

    try:
        findings = await run_hunt(
            urls,
            live_hosts,
            log,
            enabled_classes=["Security Headers", "Sensitive Paths"],
            scan_level="LIGHT",
            max_urls=30,
            concurrency_override=4,
            request_timeout=5,
        )
    except Exception as exc:
        errors.append(f"hunt exception: {exc}")

    findings = findings or []
    security_header_hits = [
        f for f in findings
        if any(token in _finding_text(f) for token in (
            "missing x-frame-options",
            "security header",
            "x-frame-options",
            "clickjacking",
        ))
    ]
    sensitive_path_hits = [
        f for f in findings
        if "/.env" in _finding_text(f) or "db_password" in _finding_text(f)
    ]

    results.append((
        "hunt finds at least 1 security header finding",
        len(security_header_hits) >= 1,
        f"found {len(security_header_hits)} security header finding(s)",
    ))
    results.append((
        "hunt finds at least 1 sensitive path finding",
        len(sensitive_path_hits) >= 1,
        f"found {len(sensitive_path_hits)} sensitive path finding(s)",
    ))
    results.append((
        "hunt has 0 errors/exceptions",
        not errors,
        "; ".join(errors) if errors else "no exceptions",
    ))

    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'} - {name}: {detail}")

    if not all(ok for _, ok, _ in results):
        print("\nRecent pipeline logs:")
        for level, message in logs[-20:]:
            safe_message = str(message).encode("ascii", "replace").decode("ascii")
            print(f"[{level}] {safe_message}")
        return 1
    return 0


def main():
    server = None
    thread = None
    try:
        server, thread = start_server()
        return asyncio.run(run_pipeline_check())
    finally:
        if server:
            server.shutdown()
            server.server_close()
        if thread:
            thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
