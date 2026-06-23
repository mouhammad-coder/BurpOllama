#!/usr/bin/env python3
"""
BurpOllama CLI — see exactly what is happening in real time

Usage:
  python3 cli.py scan https://target.com
  python3 cli.py scan https://target.com --mode bounty
  python3 cli.py scan https://target.com --mode passive
  python3 cli.py scan https://target.com --mode deep
  python3 cli.py recon https://target.com
  python3 cli.py validate "IDOR on /api/users/{id}"
  python3 cli.py report --scan-id <id>
  python3 cli.py status
  python3 cli.py history
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import websockets
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text


ROOT = Path(__file__).resolve().parent
DEFAULT_API = "http://127.0.0.1:8888"
MODE_MAP = {
    "bounty": ("conservative", "Bounty Scan"),
    "passive": ("passive_only", "Safe Passive Scan"),
    "deep": ("normal", "Deep Authorized Scan"),
}
TERMINAL_STATES = {"complete", "completed", "failed", "error", "stopped"}
console = Console(highlight=False)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="BurpOllama CLI-first authorized security scanner.",
    )
    parser.add_argument("--api", default=DEFAULT_API)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Start a scan and stream everything live.")
    scan.add_argument("target")
    scan.add_argument("--mode", choices=tuple(MODE_MAP), default="bounty")
    scan.add_argument("--yes", action="store_true", help="Confirm authorization non-interactively.")
    scan.add_argument("--no-auto-start", action="store_true")

    watch = sub.add_parser("watch", help="Watch an existing scan in real time.")
    watch.add_argument("--scan-id", required=True)

    recon = sub.add_parser("recon", help="Run authorized reconnaissance directly.")
    recon.add_argument("target")
    recon.add_argument("--yes", action="store_true")
    recon.add_argument("--mode", choices=tuple(MODE_MAP), default="bounty")

    validate = sub.add_parser("validate", help="Classify a finding candidate offline.")
    validate.add_argument("finding")
    validate.add_argument("--url", default="")
    validate.add_argument("--evidence", default="")

    report = sub.add_parser("report", help="Print or save a completed scan report.")
    report.add_argument("--scan-id", required=True)
    report.add_argument(
        "--format",
        choices=("markdown", "hackerone", "bugcrowd", "json", "csv", "sarif"),
        default="markdown",
    )
    report.add_argument("--output")

    sub.add_parser("status", help="Show backend and AI readiness.")
    sub.add_parser("history", help="List past scans.")

    analyze = sub.add_parser(
        "analyze",
        help="Send captured Burp traffic JSON to passive analysis.",
    )
    analyze.add_argument("--file", help="JSON object/list file. Defaults to stdin.")
    return parser


def banner() -> None:
    console.print(
        Panel(
            "[bold cyan]BurpOllama — Authorized Security Scanner[/bold cyan]",
            box=box.DOUBLE,
            border_style="cyan",
            width=58,
        )
    )


def phase(title: str) -> None:
    console.print()
    console.print(Rule("[bold cyan]{}[/bold cyan]".format(escape(title))))


def timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def normalized_target(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    return value


def authorized(args, target: str) -> bool:
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        console.print(
            "[red]Authorization confirmation required. Re-run with --yes only "
            "when you own the target or have written permission.[/red]"
        )
        return False
    answer = console.input(
        "[bold yellow]Confirm you own or have written authorization for "
        "{} [y/N]: [/bold yellow]".format(escape(target))
    )
    return answer.strip().lower() in {"y", "yes"}


def ws_url(api: str) -> str:
    parsed = urlparse(api)
    scheme = "wss" if parsed.scheme == "https" else "ws"
    return "{}://{}/ws".format(scheme, parsed.netloc)


async def api_json(
    api: str,
    method: str,
    path: str,
    payload: dict | None = None,
    timeout: float = 30.0,
) -> Any:
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        response = await client.request(
            method,
            api.rstrip("/") + path,
            json=payload,
        )
        if response.status_code >= 400:
            raise RuntimeError(
                "HTTP {}: {}".format(response.status_code, response.text[:1000])
            )
        return response.json()


async def api_text(api: str, path: str) -> tuple[str, str]:
    async with httpx.AsyncClient(timeout=60.0, trust_env=False) as client:
        response = await client.get(api.rstrip("/") + path)
        if response.status_code >= 400:
            raise RuntimeError(
                "HTTP {}: {}".format(response.status_code, response.text[:1000])
            )
        return response.text, response.headers.get("content-type", "text/plain")


async def backend_ready(api: str) -> bool:
    try:
        data = await api_json(api, "GET", "/health", timeout=3.0)
        return data.get("status") == "ok"
    except Exception:
        return False


async def start_local_backend(api: str) -> subprocess.Popen | None:
    parsed = urlparse(api)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        return None
    if await backend_ready(api):
        return None
    console.print("[yellow]Backend is not running — starting it locally...[/yellow]")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "main:app",
            "--host",
            parsed.hostname or "127.0.0.1",
            "--port",
            str(parsed.port or 8888),
        ],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        if process.poll() is not None:
            raise RuntimeError("The BurpOllama backend failed to start.")
        if await backend_ready(api):
            console.print("[green]✓ Backend ready[/green]")
            return process
        await asyncio.sleep(0.25)
    process.terminate()
    raise RuntimeError("Timed out waiting for the BurpOllama backend.")


def stop_local_backend(process: subprocess.Popen | None) -> None:
    if not process or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def cloudflare_panel() -> Panel:
    return Panel(
        "[bold yellow]⚠  CLOUDFLARE DETECTED[/bold yellow]\n\n"
        "This target uses Cloudflare WAF with JS challenges.\n"
        "HTTP-only scanners cannot bypass this automatically.\n\n"
        "[bold]Options:[/bold]\n"
        "1. Use Safe Passive Scan mode (recommended)\n"
        "2. Use Burp Suite extension to capture traffic\n"
        "   then analyze with: [cyan]python3 cli.py analyze[/cyan]\n"
        "3. Disable Cloudflare temporarily for testing",
        border_style="yellow",
        box=box.SQUARE,
        width=58,
    )


class StreamPrinter:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.finding_ids: set[str] = set()
        self.finding_counts = Counter()
        self.last_phase = ""
        self.historical_keys: set[tuple[str, str]] = set()

    def print_historical(self, logs: list[dict]) -> None:
        for entry in logs or []:
            key = (str(entry.get("ts", "")), str(entry.get("msg", "")))
            self.historical_keys.add(key)
            self._log(entry)

    def _log(self, entry: dict) -> None:
        level = str(entry.get("level", "info"))
        msg = str(entry.get("msg", ""))
        ts = entry.get("ts") or timestamp()
        phase_titles = (
            ("P1:", "PHASE 1 — RECONNAISSANCE"),
            ("P2:", "PHASE 2 — VULNERABILITY HUNT"),
            ("P3:", "PHASE 3 — TRIAGE"),
            ("P4:", "PHASE 4 — DEEP ANALYSIS"),
            ("P5:", "PHASE 5 — REPORTING"),
            ("P6:", "PHASE 6 — INTELLIGENCE"),
        )
        for prefix, title in phase_titles:
            if msg.startswith(prefix):
                phase(title)
                return
        if level == "phase":
            phase(msg)
            return
        color = {
            "error": "red",
            "warning": "yellow",
            "success": "green",
            "adaptive": "cyan",
        }.get(level, "white")
        symbol = {
            "error": "✗",
            "warning": "!",
            "success": "✓",
            "adaptive": "◆",
        }.get(level, "→")
        console.print(
            "[dim][{}][/dim] [{}]{}[/{}] {}".format(
                ts, color, symbol, color, escape(msg)
            )
        )

    def _finding(self, finding: dict, count: int | None = None) -> None:
        finding_id = str(finding.get("id", ""))
        if finding_id and finding_id in self.finding_ids:
            return
        if finding_id:
            self.finding_ids.add(finding_id)
        severity = str(finding.get("severity", "INFO")).upper()
        self.finding_counts[severity] += 1
        color = (
            "bold red"
            if severity == "CRITICAL"
            else "bold green"
            if severity == "HIGH"
            else "bold yellow"
            if severity == "MEDIUM"
            else "cyan"
        )
        title = finding.get("title") or finding.get("vuln_type") or "Finding"
        url = finding.get("affected_url") or finding.get("url") or ""
        total = count if count is not None else len(self.finding_ids)
        console.print(
            "[dim][{}][/dim] [{}]⚠ FINDING: {} [{}][/]".format(
                timestamp(), color, escape(str(title)), severity
            )
        )
        if url:
            console.print("             [dim]{}[/dim]".format(escape(str(url))))
        console.print(
            "             [green]Found {} issue{} so far[/green]".format(
                total, "" if total == 1 else "s"
            )
        )

    def handle(self, message: dict) -> bool:
        event_type = message.get("type")
        event_scan = message.get("scan_id") or message.get("data", {}).get("scan_id")
        if event_type != "init" and event_scan and event_scan != self.scan_id:
            return False
        if event_type == "log":
            entry = message.get("entry", {})
            key = (str(entry.get("ts", "")), str(entry.get("msg", "")))
            if key not in self.historical_keys:
                self._log(entry)
        elif event_type == "phase_change":
            phase_name = str(message.get("phase", "")).upper()
            if phase_name != self.last_phase:
                self.last_phase = phase_name
                console.print(
                    Rule("[bold cyan]{}[/bold cyan]".format(escape(phase_name)))
                )
        elif event_type == "progress":
            console.print(
                "[dim][{}][/dim] [cyan]Testing [{}/{}] {}...[/cyan]".format(
                    timestamp(),
                    message.get("current", 0),
                    message.get("total", 0),
                    escape(str(message.get("label", ""))),
                )
            )
        elif event_type == "url_test":
            console.print(
                "[dim][{}][/dim] → Testing URL {}/{} [[cyan]{}[/cyan]] {}".format(
                    timestamp(),
                    message.get("current", 0),
                    message.get("total", 0),
                    escape(str(message.get("vulnerability_class", ""))),
                    escape(str(message.get("url", ""))),
                )
            )
        elif event_type == "request":
            status = message.get("status_code")
            suffix = (
                " → HTTP {}".format(status)
                if status is not None
                else " → {}".format(message.get("error", "no response"))
            )
            style = "yellow" if status in {401, 403, 429, 503} else "dim"
            console.print(
                "[dim][{}][/dim] [{}]{} {}{}[/{}]".format(
                    timestamp(),
                    style,
                    message.get("method", "GET"),
                    escape(str(message.get("url", ""))),
                    escape(suffix),
                    style,
                )
            )
        elif event_type in {"finding", "finding_live"}:
            self._finding(message.get("data", {}), message.get("finding_count"))
        elif event_type == "waf_detected":
            waf = message.get("waf", {})
            console.print(
                "[yellow]! WAF detected: {} ({}%) — strategy {}[/yellow]".format(
                    escape(str(waf.get("vendor", "Unknown"))),
                    waf.get("confidence", 0),
                    escape(str(waf.get("strategy", ""))),
                )
            )
        elif event_type == "cloudflare_detected":
            console.print(cloudflare_panel())
            console.print(
                "[yellow]The scan has automatically continued in passive-only mode.[/yellow]"
            )
        elif event_type == "throttle_warning":
            console.print(
                "[yellow]! {} — {}[/yellow]".format(
                    escape(str(message.get("message", "Throttle warning"))),
                    escape(str(message.get("reason", ""))),
                )
            )
        elif event_type == "scan_error":
            console.print("[red]Scan failed: {}[/red]".format(
                escape(str(message.get("error", "Unknown error")))
            ))
            return True
        elif event_type in {"scan_complete", "scan_stopped"}:
            return True
        return False


async def scan_state(api: str, scan_id: str) -> dict:
    return await api_json(api, "GET", "/scan/{}".format(scan_id), timeout=10.0)


async def stream_scan(
    api: str,
    scan_id: str,
    websocket=None,
    historical: bool = True,
) -> dict:
    printer = StreamPrinter(scan_id)
    if historical:
        current = await scan_state(api, scan_id)
        printer.print_historical(current.get("logs", []))
        if str(current.get("status", "")).lower() in TERMINAL_STATES:
            return current

    owns_socket = websocket is None
    if owns_socket:
        websocket = await websockets.connect(ws_url(api), max_size=4_000_000)
    try:
        while True:
            try:
                raw = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                message = json.loads(raw)
                if printer.handle(message):
                    break
            except asyncio.TimeoutError:
                current = await scan_state(api, scan_id)
                if str(current.get("status", "")).lower() in TERMINAL_STATES:
                    break
                await websocket.send("ping")
        return await scan_state(api, scan_id)
    finally:
        if owns_socket:
            await websocket.close()


async def print_results(api: str, scan_id: str, started: float) -> None:
    phase("RESULTS")
    buckets = await api_json(
        api, "GET", "/findings/{}/buckets".format(scan_id), timeout=60.0
    )
    findings = []
    for name in (
        "valid_bugs",
        "needs_more_proof",
        "candidates",
        "informational",
        "false_positives_removed",
    ):
        findings.extend(buckets.get(name, []))
    counts = Counter(str(item.get("severity", "INFO")).upper() for item in findings)
    elapsed = max(0, int(time.monotonic() - started))
    console.print(
        "[bold green]✓ Scan complete in {}m {}s[/bold green]".format(
            elapsed // 60, elapsed % 60
        )
    )
    table = Table(box=box.SIMPLE, show_header=False)
    for severity, style in (
        ("CRITICAL", "red"),
        ("HIGH", "green"),
        ("MEDIUM", "yellow"),
        ("LOW", "cyan"),
        ("INFO", "dim"),
    ):
        table.add_row(
            Text(severity + ":", style=style),
            Text(str(counts.get(severity, 0)), style=style),
        )
    console.print(table)
    console.print(
        "\nRun: [cyan]python3 cli.py report --scan-id {}[/cyan]\n"
        "     [cyan]python3 cli.py report --scan-id {} --format hackerone[/cyan]".format(
            scan_id, scan_id
        )
    )


async def command_scan(args) -> int:
    target = normalized_target(args.target)
    if not authorized(args, target):
        return 2
    backend_process = None
    if not await backend_ready(args.api):
        if args.no_auto_start:
            raise RuntimeError("Backend is not running. Run: bash start.sh")
        backend_process = await start_local_backend(args.api)
    mode_value, mode_label = MODE_MAP[args.mode]
    banner()
    console.print("Target: [bold]{}[/bold]".format(escape(target)))
    console.print("Mode:   [bold]{}[/bold]".format(mode_label))
    console.print("Time:   {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    started = time.monotonic()
    try:
        await api_json(
            args.api,
            "POST",
            "/scope",
            {
                "scan_mode": mode_value,
                "active_testing_enabled": args.mode != "passive",
                "passive_only_mode": args.mode == "passive",
            },
        )
        async with websockets.connect(
            ws_url(args.api), max_size=4_000_000
        ) as websocket:
            await websocket.recv()  # initial state snapshot
            result = await api_json(
                args.api,
                "POST",
                "/scan",
                {
                    "target": target,
                    "scan_mode": mode_value,
                    "authorization_confirmed": True,
                },
            )
            scan_id = result["scan_id"]
            console.print("Scan ID: [cyan]{}[/cyan]".format(scan_id))
            current = await stream_scan(
                args.api,
                scan_id,
                websocket=websocket,
                historical=False,
            )
        if str(current.get("status", "")).lower() in {"failed", "error"}:
            console.print(
                "[red]Scan failed: {}[/red]".format(
                    escape(str(current.get("error", "Unknown error")))
                )
            )
            return 1
        await print_results(args.api, scan_id, started)
        return 0
    finally:
        if backend_process and backend_process.poll() is None:
            console.print(
                "[dim]Backend remains running in the background (PID {}). "
                "Use start.sh or your process manager to stop it.[/dim]".format(
                    backend_process.pid
                )
            )


async def command_watch(args) -> int:
    banner()
    current = await stream_scan(args.api, args.scan_id)
    console.print(
        "[bold]Final status:[/bold] {}".format(
            escape(str(current.get("status", "unknown")))
        )
    )
    return 0


async def command_recon(args) -> int:
    from adaptive_scan import build_adaptive_plan, TargetProfile
    from recon_engine import run_full_recon

    target = normalized_target(args.target)
    if not authorized(args, target):
        return 2
    banner()
    phase("PHASE 1 — RECONNAISSANCE")

    async def async_log(message: str, level: str = "info"):
        StreamPrinter("recon")._log({
            "ts": timestamp(),
            "msg": message,
            "level": level,
        })

    def log(message: str, level: str = "info"):
        asyncio.create_task(async_log(message, level))

    plan = build_adaptive_plan(TargetProfile(target=target), MODE_MAP[args.mode][0])
    recon = await run_full_recon(target, log, adaptive_plan=plan.to_dict())
    await asyncio.sleep(0)
    stats = recon.get("stats", {})
    console.print(
        Panel(
            "Live hosts: {}\nURLs: {}\nJavaScript files: {}\nTechnologies: {}".format(
                len(recon.get("live_hosts", [])),
                len(recon.get("urls", [])),
                len(recon.get("js_urls", [])),
                ", ".join(recon.get("tech_stack", [])) or "Unknown",
            ),
            title="Recon complete",
            border_style="green",
        )
    )
    if stats:
        console.print_json(json.dumps(stats))
    return 0


def command_validate(args) -> int:
    from finding_model import ProofGate, normalize_finding
    from report_quality_scorer import score_finding

    finding = normalize_finding({
        "title": args.finding,
        "vuln_type": args.finding,
        "url": args.url,
        "evidence": args.evidence,
        "confidence": 70 if args.evidence else 40,
        "severity": "MEDIUM",
        "verdict": "NEEDS_MANUAL_REVIEW",
    })
    finding.update(ProofGate.evaluate(finding))
    quality = score_finding(finding)
    banner()
    console.print(Panel(
        "Candidate: {}\nStatus: {}\nEvidence: {}\n"
        "False-positive risk: {}\nQuality score: {}\n\n"
        "This command classifies supplied evidence; it does not prove a "
        "vulnerability without an authorized reproducible request/response.".format(
            args.finding,
            finding.get("exploitability_status"),
            finding.get("evidence_strength"),
            finding.get("false_positive_risk"),
            quality.get("score", 0),
        ),
        title="Validation assessment",
        border_style="yellow",
    ))
    return 0


async def command_report(args) -> int:
    paths = {
        "markdown": "/scan/{}/report".format(args.scan_id),
        "hackerone": "/scan/{}/bounty/markdown?platform=hackerone".format(args.scan_id),
        "bugcrowd": "/scan/{}/bounty/markdown?platform=bugcrowd".format(args.scan_id),
        "json": "/scan/{}/report/json".format(args.scan_id),
        "csv": "/scan/{}/report/csv".format(args.scan_id),
        "sarif": "/scan/{}/report/sarif".format(args.scan_id),
    }
    body, _ = await api_text(args.api, paths[args.format])
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
        console.print("[green]✓ Saved {}[/green]".format(escape(args.output)))
    else:
        console.print(body, markup=False)
    return 0


async def command_status(args) -> int:
    banner()
    ready = await api_json(args.api, "GET", "/ready")
    table = Table(title="BurpOllama status", box=box.ROUNDED)
    table.add_column("Capability")
    table.add_column("Status")
    for label, value in (
        ("Backend", ready.get("ready")),
        ("Scanning", ready.get("scan_capable")),
        ("AI triage", ready.get("triage_capable")),
        ("AI provider", ready.get("ai_provider")),
        ("AI model", ready.get("ai_model")),
        ("Database", ready.get("database_ok")),
    ):
        table.add_row(label, str(value))
    console.print(table)
    return 0


async def command_history(args) -> int:
    scans = await api_json(args.api, "GET", "/scans")
    table = Table(title="Scan history", box=box.ROUNDED)
    for column in ("Scan ID", "Target", "Status", "Phase", "Started"):
        table.add_column(column)
    for scan in scans:
        table.add_row(
            str(scan.get("id", "")),
            str(scan.get("target", "")),
            str(scan.get("status", "")),
            str(scan.get("phase", "")),
            str(scan.get("started", "")),
        )
    console.print(table)
    return 0


async def command_analyze(args) -> int:
    if args.file:
        raw = Path(args.file).read_text(encoding="utf-8")
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        console.print(
            "Pass Burp traffic JSON with [cyan]--file traffic.json[/cyan] or stdin.\n"
            "Each object needs request_method, request_url, request_headers, "
            "response_status, response_headers, and response_body."
        )
        return 2
    payload = json.loads(raw)
    rows = payload if isinstance(payload, list) else [payload]
    found = 0
    for index, row in enumerate(rows, start=1):
        result = await api_json(args.api, "POST", "/analyze", row)
        found += int(result.get("instant_findings", 0))
        console.print(
            "[{}] {} → {} finding(s){}".format(
                index,
                escape(str(row.get("request_url", ""))),
                result.get("instant_findings", 0),
                " [yellow](deduplicated)[/yellow]" if result.get("deduped") else "",
            )
        )
    console.print("[green]Passive analysis complete: {} finding(s)[/green]".format(found))
    return 0


async def async_main(args) -> int:
    if args.command == "scan":
        return await command_scan(args)
    if args.command == "watch":
        return await command_watch(args)
    if args.command == "recon":
        return await command_recon(args)
    if args.command == "report":
        return await command_report(args)
    if args.command == "status":
        return await command_status(args)
    if args.command == "history":
        return await command_history(args)
    if args.command == "analyze":
        return await command_analyze(args)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        return command_validate(args)
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user.[/yellow]")
        return 130
    except (RuntimeError, httpx.HTTPError, OSError, json.JSONDecodeError) as exc:
        console.print("[red]Error: {}[/red]".format(escape(str(exc))))
        if args.command != "scan":
            console.print("[dim]Start the backend with: bash start.sh[/dim]")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
