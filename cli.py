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
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import webbrowser
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import websockets
from rich import box
from rich.console import Console
from rich.console import Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from core import __version__
from core.config import config_status, load_config, ollama_health
from core.reports import render_report
from core.scanner import scanner
from core.storage import scan_store


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
    parser.add_argument(
        "--api",
        default=DEFAULT_API,
        help="Dashboard API used only by watch and optional web commands.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Start a scan and stream everything live.")
    scan.add_argument("target")
    scan.add_argument("--mode", choices=tuple(MODE_MAP), default="passive")
    scan.add_argument("--yes", action="store_true", help="Confirm authorization non-interactively.")
    scan.add_argument(
        "--scope",
        action="append",
        default=None,
        metavar="DOMAIN",
        help="Restrict the scan to this domain. Repeat for multiple domains.",
    )
    scan.add_argument("--concurrency", type=int, default=5)
    scan.add_argument("--rate-limit", type=float, default=2.0)
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--retries", type=int, default=1)
    scan.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI agents from the start if a provider is configured.",
    )
    scan.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI agents completely.",
    )
    scan.add_argument(
        "--ai-provider",
        default="",
        metavar="PROVIDER",
        help="Advanced AI provider override, e.g. ollama, gemini, openai.",
    )
    scan.add_argument("--model", default="")
    scan.add_argument("--quiet", action="store_true")
    scan.add_argument("--json", action="store_true", dest="json_output")
    scan.add_argument("--follow", action="store_true")
    scan.add_argument("--output", default="reports")

    from core.benchmarks import BENCHMARKS

    benchmark = sub.add_parser(
        "benchmark",
        help="Run an explicit benchmark harness; never used by normal scans.",
    )
    benchmark.add_argument("lab", choices=tuple(BENCHMARKS))
    benchmark.add_argument("--target", default="")
    benchmark.add_argument("--yes", action="store_true")
    benchmark.add_argument("--output", default="reports")
    benchmark.add_argument("--timeout", type=float, default=10.0)

    watch = sub.add_parser("watch", help="Watch an existing scan in real time.")
    watch.add_argument("--scan-id", required=True)

    recon = sub.add_parser("recon", help="Run authorized reconnaissance directly.")
    recon.add_argument("target")
    recon.add_argument("--yes", action="store_true")
    recon.add_argument("--mode", choices=tuple(MODE_MAP), default="passive")

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

    sub.add_parser("status", help="Show local scanner, storage, tools, and AI readiness.")
    sub.add_parser("history", help="List locally stored scans.")
    sub.add_parser("doctor", help="Diagnose the local CLI installation.")
    sub.add_parser("version", help="Print the BurpOllama version.")

    serve = sub.add_parser("serve", help="Start the optional FastAPI dashboard.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8888)

    dashboard = sub.add_parser(
        "dashboard", help="Start the optional dashboard and open a browser."
    )
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8888)

    analyze = sub.add_parser(
        "analyze",
        help="Send captured Burp traffic JSON to passive analysis.",
    )
    analyze.add_argument("--file", help="JSON object/list file. Defaults to stdin.")

    skills = sub.add_parser("skills", help="Manage and run modular CLI skills.")
    skill_sub = skills.add_subparsers(dest="skill_command", required=True)
    skill_sub.add_parser("list", help="Show installed skills.")
    show = skill_sub.add_parser("show", help="Show skill details.")
    show.add_argument("skill")
    validate_skill = skill_sub.add_parser("validate", help="Validate skill structure.")
    validate_skill.add_argument("skill")
    refresh = skill_sub.add_parser(
        "refresh-knowledge",
        help="Refresh local cached fingerprints/knowledge.",
    )
    refresh.add_argument("skill")
    run_skill = skill_sub.add_parser("run", help="Run a skill explicitly.")
    run_skill.add_argument("skill")
    run_skill.add_argument("--target", required=True)
    run_skill.add_argument("--mode", choices=("passive", "validate", "report"), default="passive")
    run_skill.add_argument("--scope", action="append", default=None)
    run_skill.add_argument("--yes", action="store_true", help="Confirm authorization and scope non-interactively.")
    run_skill.add_argument("--active-permission", action="store_true")
    run_skill.add_argument("--proof-of-control", action="store_true")
    run_skill.add_argument("--proof-confirmed", action="store_true")
    run_skill.add_argument("--output", default="runs/skills")
    run_skill.add_argument("--timeout", type=float, default=8.0)
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
    if getattr(args, "mode", "passive") == "passive":
        return True
    console.print(
        Panel(
            "[bold yellow]Active testing can affect the target.[/bold yellow]\n"
            "Continue only if you own this system or have explicit written "
            "authorization and the selected tests are allowed by scope.",
            title="LEGAL AND SCOPE WARNING",
            border_style="yellow",
        )
    )
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
        elif event_type in {"ai_note", "ai_hypothesis", "ai_strategy"}:
            agent = message.get("agent") or "ai-agent"
            console.print(
                "[dim][{}][/dim] [magenta][{}][/magenta] {}".format(
                    timestamp(),
                    escape(str(agent)),
                    escape(str(message.get("message", ""))),
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


class LiveScanUI:
    PHASE_INDEX = {
        "target_check": 1,
        "reconnaissance": 2,
        "vulnerability_hunt": 3,
        "ai_triage": 4,
        "proof_validation": 5,
        "report_export": 6,
    }

    def __init__(self, scan: dict, ai: dict):
        self.scan = scan
        self.ai = ai
        self.phase_name = "queued"
        self.phase_label = "Preparing scan"
        self.agent_states: dict[str, dict] = {}
        self.discovered_urls = 0
        self.discovered_url_values: set[str] = set()
        self.tested_requests = 0
        self.confirmed = 0
        self.candidates = 0
        self.confirmed_ids: set[str] = set()
        self.candidate_ids: set[str] = set()
        self.findings = Counter()
        self.last_findings: list[dict] = []
        self.blackboard: list[dict] = []
        self.phase_progress = Progress(
            TextColumn("[bold cyan]Overall[/bold cyan]"),
            BarColumn(bar_width=38),
            TextColumn("{task.completed:.0f}/6 phases"),
            expand=True,
        )
        self.phase_task = self.phase_progress.add_task("", total=6, completed=0)
        self.agent_progress = Progress(
            TextColumn("[cyan]{task.description:<20}[/cyan]"),
            BarColumn(bar_width=30),
            TextColumn("{task.completed:.0f}/{task.total:.0f}"),
            expand=True,
        )
        self.agent_tasks: dict[str, int] = {}
        self.live = Live(
            self.render(),
            console=console,
            refresh_per_second=8,
            transient=False,
        )

    def start(self):
        options = self.scan.get("options", {})
        scope = self.scan.get("scope", {}).get("allowed_domains", [])
        ai_enabled = bool(self.ai.get("agents_enabled"))
        ai_text = (
            "{} / {}".format(
                self.ai.get("active_provider"),
                self.ai.get("active_model"),
            )
            if ai_enabled
            else "disabled — manual review only"
        )
        ai_agents_text = (
            "enabled from start" if ai_enabled else "inactive"
        )
        banner()
        console.print(
            Panel(
                "\n".join([
                    "[bold]Target:[/bold]      {}".format(
                        escape(self.scan.get("target", ""))
                    ),
                    "[bold]Mode:[/bold]        {}".format(
                        str(options.get("mode", "passive")).upper()
                    ),
                    "[bold]Scope:[/bold]       {}".format(
                        escape(", ".join(scope))
                    ),
                    "[bold]Concurrency:[/bold] {}".format(
                        options.get("concurrency", 5)
                    ),
                    "[bold]Rate limit:[/bold]  {} req/s".format(
                        options.get("rate_limit", 2)
                    ),
                    "[bold]AI:[/bold]          {}".format(escape(ai_text)),
                    "[bold]AI agents:[/bold]   {}".format(
                        escape(ai_agents_text)
                    ),
                    "[bold]Scan ID:[/bold]     {}".format(
                        escape(self.scan.get("id", ""))
                    ),
                ]),
                title="CLI Swarm Scan",
                border_style="cyan",
            )
        )
        self.live.start()

    def stop(self):
        self.live.update(self.render(), refresh=True)
        self.live.stop()

    def render(self):
        agents = Table(
            title="Live agent status",
            box=box.ROUNDED,
            expand=True,
        )
        agents.add_column("Agent", style="cyan", no_wrap=True)
        agents.add_column("Status", no_wrap=True)
        agents.add_column("Tasks", justify="right")
        agents.add_column("Findings", justify="right")
        agents.add_column("Last event")
        for name in sorted(self.agent_states):
            state = self.agent_states[name]
            status = str(state.get("status", "pending"))
            style = {
                "running": "yellow",
                "complete": "green",
                "error": "red",
                "skipped": "dim",
                "stopped": "red",
            }.get(status, "white")
            agents.add_row(
                name,
                "[{}]{}[/{}]".format(style, status, style),
                str(state.get("tasks", 0)),
                str(state.get("findings", 0)),
                str(state.get("last_event", ""))[:70],
            )
        metrics = Table(box=box.SIMPLE, expand=True, show_header=False)
        metrics.add_row(
            "URLs", str(self.discovered_urls),
            "Requests", str(self.tested_requests),
            "Confirmed", str(self.confirmed),
            "Candidates", str(self.candidates),
        )
        finding_text = "\n".join(
            "[{severity}] {title} ({confidence}% · {proof})".format(
                severity=item.get("severity", "INFO"),
                title=item.get("title", "Finding"),
                confidence=item.get("confidence", 0),
                proof=item.get("proof", "candidate"),
            )
            for item in self.last_findings[-5:]
        ) or "No findings yet"
        blackboard_text = "\n".join(
            "[{agent}] {message}".format(
                agent=item.get("agent", "ai-agent"),
                message=item.get("message", ""),
            )
            for item in self.blackboard[-6:]
        ) or "AI agents inactive or no strategy notes yet"
        return Group(
            Rule("[bold cyan]{}[/bold cyan]".format(
                escape(self.phase_label)
            )),
            self.phase_progress,
            self.agent_progress,
            agents,
            metrics,
            Panel(
                blackboard_text,
                title="Blackboard stream",
                border_style="magenta",
            ),
            Panel(finding_text, title="Live findings ticker", border_style="yellow"),
        )

    def _agent(self, name: str) -> dict:
        return self.agent_states.setdefault(
            name or "core",
            {
                "status": "pending",
                "tasks": 0,
                "findings": 0,
                "last_event": "",
            },
        )

    def _line(self, event: dict, symbol: str, style: str):
        agent = str(event.get("agent") or "core")
        message = str(event.get("message") or "")
        self.live.console.print(
            "[dim][{}][/dim] [cyan]{:<14}[/cyan] [{}]{}[/{}] {}".format(
                datetime.now().strftime("%H:%M:%S"),
                escape(agent),
                style,
                symbol,
                style,
                escape(message),
            )
        )

    def handle(self, event: dict):
        event_type = str(event.get("type", ""))
        agent = str(event.get("agent") or "core")
        data = event.get("data") or {}
        state = self._agent(agent)
        message = str(event.get("message") or "")
        state["last_event"] = message
        if event_type == "phase_started":
            self.phase_name = str(event.get("phase", ""))
            self.phase_label = message
            completed = max(0, self.PHASE_INDEX.get(self.phase_name, 1) - 1)
            self.phase_progress.update(self.phase_task, completed=completed)
            self._line(event, "▶", "cyan")
        elif event_type == "phase_completed":
            completed = self.PHASE_INDEX.get(str(event.get("phase", "")), 0)
            self.phase_progress.update(self.phase_task, completed=completed)
            self._line(event, "✓", "green")
        elif event_type == "agent_started":
            state["status"] = "running"
            self._line(event, "→", "cyan")
        elif event_type == "agent_completed":
            state["status"] = "complete"
            state["tasks"] += 1
            state["findings"] = max(
                state["findings"], int(data.get("findings", 0) or 0)
            )
            self._line(event, "✓", "green")
        elif event_type == "agent_progress":
            current = int(data.get("current", 0) or 0)
            total = max(1, int(data.get("total", 1) or 1))
            task_id = self.agent_tasks.get(agent)
            if task_id is None:
                task_id = self.agent_progress.add_task(
                    agent, total=total, completed=current
                )
                self.agent_tasks[agent] = task_id
            else:
                self.agent_progress.update(
                    task_id, total=total, completed=current
                )
        elif event_type == "url_discovered":
            url = str(data.get("url", ""))
            if url:
                self.discovered_url_values.add(url)
                self.discovered_urls = len(self.discovered_url_values)
            self._line(event, "✓", "green")
        elif event_type in {"request_tested", "response_received"}:
            if event_type == "response_received":
                self.tested_requests += 1
            self._line(event, "→", "white")
        elif event_type in {"finding_candidate", "finding_confirmed"}:
            finding = data.get("finding", {})
            finding_id = str(
                finding.get("id")
                or "{}|{}".format(
                    finding.get("vuln_type", ""),
                    finding.get("url", ""),
                )
            )
            severity = str(finding.get("severity", "INFO")).upper()
            if event_type == "finding_confirmed":
                if finding_id in self.confirmed_ids:
                    return
                self.confirmed_ids.add(finding_id)
                self.confirmed = len(self.confirmed_ids)
                proof = "confirmed"
                symbol, style = "✓", "green"
            else:
                if finding_id in self.candidate_ids:
                    return
                self.candidate_ids.add(finding_id)
                self.candidates = len(self.candidate_ids)
                proof = "needs proof"
                symbol, style = "⚠", "yellow"
            self.findings[severity] += 1
            state["findings"] += 1
            self.last_findings.append({
                "severity": severity,
                "title": finding.get("title") or finding.get("vuln_type"),
                "confidence": finding.get("confidence", 0),
                "proof": proof,
            })
            self._line(event, symbol, style)
        elif event_type == "skipped":
            state["status"] = (
                "skipped" if state["status"] == "pending" else state["status"]
            )
            self._line(event, "⏭", "dim")
        elif event_type == "throttled":
            self._line(event, "!", "yellow")
        elif event_type == "error":
            state["status"] = "error"
            self._line(event, "✗", "red")
        elif event_type == "report_written":
            self._line(event, "✓", "green")
        elif event_type in {"ai_note", "ai_hypothesis", "ai_strategy"}:
            self.blackboard.append({
                "agent": agent,
                "message": message,
            })
            self._line(event, "✦", "magenta")
        elif event_type == "ai_triage":
            self._line(event, "✓", "magenta")
        elif event_type == "log":
            level = str(data.get("level", "info"))
            if level in {"warning", "error", "success"}:
                self._line(
                    event,
                    "!" if level == "warning" else "✗" if level == "error" else "✓",
                    "yellow" if level == "warning" else "red" if level == "error" else "green",
                )
        self.live.update(self.render(), refresh=True)


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


def print_results(scan: dict, started: float) -> None:
    phase("RESULTS")
    scan_id = scan.get("id", "")
    findings = (
        scan.get("triaged_findings")
        or scan.get("findings")
        or scan.get("raw_findings")
        or []
    )
    counts = Counter(str(item.get("severity", "INFO")).upper() for item in findings)
    elapsed = max(0, int(time.monotonic() - started))
    analysis = scan.get("analysis", {})
    coverage = analysis.get("coverage", {})
    table = Table(box=box.ROUNDED, title="Scan summary")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Scan ID", str(scan_id))
    table.add_row("Target", str(scan.get("target", "")))
    table.add_row("Mode", str(scan.get("mode", "")))
    table.add_row("Status", str(scan.get("status", "")))
    table.add_row("Duration", "{:02d}:{:02d}:{:02d}".format(
        elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
    ))
    table.add_row(
        "Discovered URLs", str(len(scan.get("recon", {}).get("urls", [])))
    )
    table.add_row(
        "Tested requests",
        str(scan.get("rate_limiter", {}).get("total_requests", 0)),
    )
    table.add_row(
        "Confirmed findings", str(len(scan.get("confirmed_findings", [])))
    )
    table.add_row(
        "Candidate findings", str(len(scan.get("candidate_findings", [])))
    )
    table.add_row(
        "Coverage", "{}%".format(coverage.get("coverage_percent", 0))
    )
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        table.add_row(severity, str(counts.get(severity, 0)))
    console.print(table)
    report_paths = scan.get("report_paths", {})
    if report_paths:
        console.print("[bold]Reports:[/bold]")
        for report_format, path in report_paths.items():
            console.print("  {}: {}".format(report_format, path))
    console.print(
        "\nNext:\n[cyan]burpollama report --scan-id {}[/cyan]\n"
        "[cyan]burpollama report --scan-id {} --format hackerone[/cyan]".format(
            scan_id, scan_id
        )
    )


async def command_scan(args) -> int:
    target = normalized_target(args.target)
    if not authorized(args, target):
        return 2
    availability = await _ai_status(args.ai_provider, args.model)
    ai_enabled = _scan_ai_enabled(args, availability)
    if args.ai and not availability.get("triage_capable"):
        console.print(
            "[yellow]AI requested, but no provider is available. "
            "Continuing manual-review only.[/yellow]"
        )
    started = time.monotonic()
    prepared = scanner.prepare(
        target,
        args.mode,
        authorization_confirmed=True,
        allowed_domains=args.scope,
        concurrency=args.concurrency,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        retries=args.retries,
        ai_provider=args.ai_provider,
        ai_enabled=ai_enabled,
        model=args.model,
        output=args.output,
    )
    prepared["ai"] = {
        **prepared.get("ai", {}),
        **availability,
        "agents_enabled": bool(
            ai_enabled is not False and availability.get("triage_capable")
        ),
    }
    scan_id = prepared["id"]
    ui = None if args.quiet or args.json_output else LiveScanUI(
        prepared, availability
    )
    if ui:
        ui.start()
    elif not args.json_output:
        console.print("Scan ID: {}".format(scan_id))

    async def event_callback(event: dict):
        if args.json_output:
            print(json.dumps(event, ensure_ascii=False, default=str), flush=True)
        elif ui:
            ui.handle(event)

    try:
        current = await scanner.run_prepared(
            prepared, event_callback=event_callback
        )
    finally:
        if ui:
            ui.stop()
    if str(current.get("status", "")).lower() in {"failed", "error"}:
        if args.json_output:
            print(json.dumps({"type": "result", "scan": current}, default=str))
        else:
            console.print("[red]Scan failed: {}[/red]".format(
                escape(str(current.get("error", "Unknown error")))
            ))
        return 1
    if args.json_output:
        print(json.dumps({"type": "result", "scan": current}, default=str))
    else:
        print_results(current, started)
    return 0


async def command_benchmark(args) -> int:
    from core.benchmarks import BENCHMARKS

    benchmark = BENCHMARKS.get(args.lab)
    if not benchmark:
        raise RuntimeError("Unsupported benchmark: {}".format(args.lab))
    target = normalized_target(args.target or benchmark["default_target"])
    if not getattr(args, "yes", False):
        console.print(
            "[red]Benchmark mode is lab-specific. Re-run with --yes only for "
            "your local authorized {} instance.[/red]".format(
                escape(str(benchmark["label"]))
            )
        )
        return 2

    from attack_graph import build_attack_graph
    from coverage_intelligence import compute_coverage
    from zero_fp_gate import apply_zero_fp_gate
    from core.agents.base import ScanContext
    from core.agents.report_agent import ReportAgent
    from core.benchmarks.juice_shop import JuiceShopBenchmark
    from core.events import event_bus
    from core.ratelimit import RateLimiter
    from core.scheduler import Scheduler
    from core.scope import ScanScope

    started = time.monotonic()
    prepared = scanner.prepare(
        target,
        "bounty",
        authorization_confirmed=True,
        concurrency=2,
        rate_limit=2.0,
        timeout=args.timeout,
        retries=0,
        ai_enabled=False,
        output=args.output,
    )
    prepared["mode"] = "benchmark"
    prepared["requested_scan_mode"] = benchmark["requested_scan_mode"]
    context = ScanContext(
        scan=prepared,
        options=type("BenchmarkOptions", (), {
            "timeout": args.timeout,
            "concurrency": 2,
            "rate_limit": 2.0,
            "retries": 0,
            "mode": "bounty",
            "api_key": "",
            "output": args.output,
        })(),
        events=event_bus,
        scheduler=Scheduler(2),
        rate_limiter=RateLimiter(2.0),
        scope=ScanScope(target, []),
        store=scan_store,
    )
    banner()
    console.print(
        Panel(
            "Lab: {}\nTarget: {}\n"
            "This benchmark path is isolated from normal scans.".format(
                escape(str(benchmark["label"])),
                escape(target)
            ),
            title="Benchmark mode",
            border_style="yellow",
        )
    )
    await JuiceShopBenchmark().execute(context)
    context.triaged_findings = list(context.raw_findings)
    context.scan["triaged_findings"] = context.triaged_findings
    graph = build_attack_graph(context.triaged_findings).to_dict()
    gated = apply_zero_fp_gate(
        context.triaged_findings,
        context.scope.to_dict(),
        graph,
        tech_stack=[],
        scan_context={"benchmark": args.lab},
    )
    context.analysis["zero_fp_gate"] = gated
    context.analysis["coverage"] = compute_coverage(
        context.recon,
        context.triaged_findings,
        tested_urls=sorted(context.tested_urls),
    )
    context.scan["analysis"] = context.analysis
    context.scan["confirmed_findings"] = gated.get("valid_bugs", [])
    context.scan["candidate_findings"] = (
        gated.get("needs_more_proof", [])
        + gated.get("candidates", [])
        + gated.get("informational", [])
    )
    await ReportAgent().execute(context)
    context.scan["status"] = "complete"
    context.scan["phase"] = "complete"
    context.scan["finished"] = datetime.utcnow().isoformat()
    context.scan["agent_status"] = context.scheduler.snapshot()
    context.scan["rate_limiter"] = context.rate_limiter.snapshot()
    scan_store.save(context.scan, context.triaged_findings)
    print_results(context.scan, started)
    return 0


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
    scan = scan_store.get(args.scan_id)
    if not scan:
        raise RuntimeError("Local scan not found: {}".format(args.scan_id))
    body = render_report(scan, args.format)
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
        console.print("[green]✓ Saved {}[/green]".format(escape(args.output)))
    else:
        console.print(body, markup=False)
    return 0


async def command_status(args) -> int:
    banner()
    storage = scan_store.status()
    ai = await _ai_status()
    table = Table(title="Standalone BurpOllama status", box=box.ROUNDED)
    table.add_column("Capability")
    table.add_column("Status")
    for label, value in (
        ("CLI scanner", "ready"),
        ("Web backend required", False),
        ("Local database", storage.get("writable")),
        ("Stored scans", storage.get("scan_count")),
        (
            "AI",
            "{}/{}".format(
                ai.get("active_provider"), ai.get("active_model")
            )
            if ai.get("triage_capable")
            else "disabled — manual review only",
        ),
        ("AI provider", ai.get("active_provider")),
        ("AI model", ai.get("active_model")),
    ):
        table.add_row(label, str(value))
    console.print(table)
    return 0


async def command_history(args) -> int:
    scans = scan_store.list()
    table = Table(title="Scan history", box=box.ROUNDED)
    for column in ("Scan ID", "Target", "Status", "Phase", "Started"):
        table.add_column(column)
    for scan in scans:
        table.add_row(
            str(scan.get("scan_id", "")),
            str(scan.get("target", "")),
            str(scan.get("status", "")),
            str(scan.get("phase", "")),
            str(scan.get("started_at", "")),
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
        from main import BurpTraffic, pattern_scan_traffic

        findings = await pattern_scan_traffic(BurpTraffic(**row))
        result = {"instant_findings": len(findings), "deduped": False}
        found += len(findings)
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


async def command_skills(args) -> int:
    from core.skills.knowledge_base import SkillKnowledgeBase
    from core.skills.registry import SkillRegistry
    from core.skills.runner import SkillRunOptions, SkillRunner, SkillSafetyError
    from core.skills.validator import SkillValidator

    registry = SkillRegistry()
    validator = SkillValidator()
    knowledge = SkillKnowledgeBase()

    if args.skill_command == "list":
        table = Table(title="Installed skills", box=box.ROUNDED)
        table.add_column("Skill")
        table.add_column("Description")
        table.add_column("Modes")
        for skill in registry.list():
            table.add_row(
                skill.name,
                skill.description[:120],
                ", ".join(skill.supported_modes),
            )
        console.print(table)
        return 0

    if args.skill_command == "show":
        skill = registry.get(args.skill)
        result = validator.validate(args.skill)
        table = Table(title="Skill: {}".format(skill.name), box=box.ROUNDED)
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Name", skill.name)
        table.add_row("Purpose", skill.purpose[:500])
        table.add_row("Safety", skill.safety_summary[:500])
        table.add_row("Required inputs", "\n".join(skill.required_inputs))
        table.add_row("Supported modes", ", ".join(skill.supported_modes))
        table.add_row("Valid", str(result.valid))
        if result.errors:
            table.add_row("Validation errors", "\n".join(result.errors))
        console.print(table)
        return 0 if result.valid else 1

    if args.skill_command == "validate":
        result = validator.validate(args.skill)
        console.print_json(json.dumps(result.to_dict(), indent=2))
        return 0 if result.valid else 1

    if args.skill_command == "refresh-knowledge":
        skill = registry.get(args.skill)
        path = knowledge.refresh(skill.name)
        console.print("[green]✓ Refreshed local knowledge cache:[/green] {}".format(path))
        return 0

    if args.skill_command == "run":
        skill = registry.get(args.skill)
        validation = validator.validate(args.skill)
        if not validation.valid:
            console.print("[red]Skill validation failed:[/red]")
            for error in validation.errors:
                console.print("  - {}".format(escape(error)))
            return 1
        if not args.yes and not sys.stdin.isatty():
            console.print(
                "[red]Authorization and scope confirmation required. "
                "Re-run with --yes only for targets you own or are authorized to test.[/red]"
            )
            return 2
        authorized_run = bool(args.yes)
        if not authorized_run:
            panel = Panel(
                "Run only against assets you own or have written authorization for.\n"
                "Proof-of-control is disabled unless explicitly allowed and confirmed.",
                title="Skill safety gate",
                border_style="yellow",
            )
            console.print(panel)
            try:
                answer = console.input(
                    "[bold yellow]Confirm authorization and in-scope target {} [y/N]: [/bold yellow]".format(
                        escape(args.target)
                    )
                )
            except EOFError:
                console.print(
                    "\n[red]Authorization confirmation required. Re-run with --yes "
                    "only for targets you own or are authorized to test.[/red]"
                )
                return 2
            authorized_run = answer.strip().lower() in {"y", "yes"}
        if not authorized_run:
            return 2
        try:
            result = await SkillRunner().run(
                skill,
                SkillRunOptions(
                    target=args.target,
                    mode=args.mode,
                    scope=args.scope,
                    authorization_confirmed=True,
                    scope_confirmed=True,
                    active_permission=bool(args.active_permission),
                    proof_of_control_allowed=bool(args.proof_of_control),
                    proof_of_control_confirmed=bool(args.proof_confirmed),
                    output_root=args.output,
                    timeout=args.timeout,
                ),
            )
        except SkillSafetyError as exc:
            console.print("[red]Safety gate refused run:[/red] {}".format(escape(str(exc))))
            return 2
        if result.get("warning"):
            console.print("[yellow]{}[/yellow]".format(escape(result["warning"])))
        table = Table(title="Skill run complete", box=box.ROUNDED)
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Skill", result["skill"])
        table.add_row("Target", result["target"])
        table.add_row("Mode", result["mode"])
        table.add_row("Run directory", result["run_dir"])
        table.add_row("Evidence", result["evidence_path"])
        table.add_row("Report", result["report_path"])
        for record in result.get("records", []):
            table.add_row("Final status", str(record.get("final_status", "")))
            table.add_row(
                "Proof performed",
                str(record.get("proof_performed", False)),
            )
        console.print(table)
        return 0

    return 1


def _scan_ai_enabled(args, availability: dict) -> bool:
    if getattr(args, "no_ai", False):
        return False
    if getattr(args, "ai", False):
        return True
    return bool(availability.get("triage_capable"))


async def _ai_status(provider: str = "", model: str = "") -> dict:
    load_config()
    from ai_provider import ai_router

    if provider:
        os.environ["BURPOLLAMA_PREFERRED_AI_PROVIDER"] = provider
    if model:
        env_provider = (provider or "OLLAMA").upper().replace("-", "_")
        os.environ["{}_MODEL".format(env_provider)] = model
    ai_router.reload_from_env()
    return await ai_router.availability()


async def command_doctor(args) -> int:
    load_config()
    checks = []

    def add(name: str, ok: bool, detail: str, blocking: bool = True):
        checks.append((name, ok, detail, blocking))

    add("Python", sys.version_info >= (3, 10), platform.python_version())
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    add("Virtual environment", in_venv, sys.prefix, blocking=False)
    env = config_status()
    add(".env", bool(env.get("env_exists")), env.get("path", ""))
    database = scan_store.status()
    add("Local scan database", bool(database.get("writable")), database.get("database", ""))
    report_dir = ROOT / "reports"
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        probe = report_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        reports_ok = True
    except OSError:
        reports_ok = False
    add("Reports directory", reports_ok, str(report_dir))
    evidence_dir = ROOT / "evidence"
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        probe = evidence_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        evidence_ok = True
    except OSError:
        evidence_ok = False
    add("Evidence directory writable", evidence_ok, str(evidence_dir))

    requirements = {
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "httpx": "httpx",
        "pydantic": "pydantic",
        "python-dotenv": "python-dotenv",
        "psutil": "psutil",
        "psycopg": "psycopg",
        "cvss": "cvss",
        "rich": "rich",
    }
    missing = []
    for label, distribution in requirements.items():
        try:
            importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            missing.append(label)
    add(
        "Required Python packages",
        not missing,
        "all installed" if not missing else "missing: " + ", ".join(missing),
    )

    from external_tools import tool_status

    tools = tool_status()
    available = [tool["name"] for tool in tools if tool["available"]]
    add(
        "Optional external tools",
        True,
        "{} available: {}".format(len(available), ", ".join(available) or "none"),
    )
    try:
        from core.skills.registry import SkillRegistry

        installed_skills = [skill.name for skill in SkillRegistry().list()]
        skills_ok = "subdomain-takeover-hunter" in installed_skills
        skills_detail = ", ".join(installed_skills) or "none"
    except Exception as exc:
        skills_ok = False
        skills_detail = "{}: {}".format(type(exc).__name__, exc)
    add("Skills installed", skills_ok, skills_detail)
    ai = await _ai_status()
    add(
        "AI provider (optional)",
        True,
        "{} / {}".format(
            ai.get("active_provider", "none"),
            ai.get("active_model", "none"),
        ),
    )
    ollama = await ollama_health()
    add(
        "Ollama",
        True,
        (
            "{} | model={} | available={} | {} | {}".format(
                "running" if ollama.get("running") else "not running",
                ollama.get("model"),
                ollama.get("model_available"),
                ollama.get("ram_estimate"),
                ollama.get("recommendation"),
            )
        ),
    )
    if not ollama.get("running"):
        add(
            "Ollama setup hint",
            True,
            "Install/start Ollama, then run: ollama pull {}".format(
                ollama.get("model") or "mistral:7b-instruct"
            ),
        )
    elif not ollama.get("model_available"):
        add("Ollama model", True, ollama.get("setup", "configured model is missing"))
    semgrep_path = ROOT / ".tools" / "semgrep" / "bin" / "semgrep"
    if os.name == "nt":
        semgrep_path = ROOT / ".tools" / "semgrep" / "Scripts" / "semgrep.exe"
    add(
        "Semgrep isolation",
        True,
        (
            str(semgrep_path)
            if semgrep_path.exists()
            else "optional isolated environment not installed"
        ),
    )
    dependency_check = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        timeout=30,
    )
    dependency_detail = (
        dependency_check.stdout.strip()
        or dependency_check.stderr.strip()
        or "no critical conflicts"
    )
    add(
        "Dependency conflicts",
        dependency_check.returncode == 0,
        dependency_detail,
    )
    launcher = shutil.which("burpollama")
    launcher_ok = bool(launcher)
    if launcher:
        try:
            launcher_path = Path(launcher).resolve()
            launcher_text = launcher_path.read_text(
                encoding="utf-8", errors="ignore"
            )
            launcher_ok = launcher_path.exists() and "cli.py" in launcher_text
        except OSError:
            launcher_ok = False
    add("CLI launcher", launcher_ok, launcher or "not found in PATH", blocking=False)
    add(
        "Dashboard (optional)",
        True,
        "available with `burpollama serve`; not required for scans",
    )

    table = Table(title="BurpOllama doctor", box=box.ROUNDED)
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Detail")
    for name, ok, detail, blocking in checks:
        if ok:
            result = "[green]PASS[/green]"
        elif blocking:
            result = "[red]FAIL[/red]"
        else:
            result = "[yellow]WARN[/yellow]"
        table.add_row(name, result, str(detail))
    console.print(table)
    console.print(
        "[dim]AI is optional and does not block scanning.[/dim]"
    )
    return 0 if all(ok or not blocking for _name, ok, _detail, blocking in checks) else 1


async def command_launcher() -> int:
    banner()
    availability = await _ai_status()
    if availability.get("triage_capable"):
        console.print(
            "[green]AI detected: {} / {}[/green]".format(
                availability.get("active_provider"),
                availability.get("active_model"),
            )
        )
        use_ai = True
        if sys.stdin.isatty():
            answer = console.input(
                "[bold cyan]Use AI agents from the start? [Y/n]: [/bold cyan]"
            )
            use_ai = answer.strip().lower() not in {"n", "no"}
        console.print(
            "[green]AI agents: enabled from start[/green]"
            if use_ai
            else "[yellow]AI: disabled — manual review only[/yellow]"
        )
    else:
        use_ai = False
        console.print("[yellow]AI: disabled — manual review only[/yellow]")
        console.print("[dim]AI agents: inactive[/dim]")

    if not sys.stdin.isatty():
        console.print(
            "\nTry:\n"
            "  [cyan]burpollama doctor[/cyan]\n"
            "  [cyan]burpollama scan https://authorized-target.example --mode passive[/cyan]\n"
            "  [cyan]burpollama scan https://authorized-target.example --mode bounty --ai --yes[/cyan]"
        )
        return 0

    target = console.input(
        "\n[bold]Target to scan[/bold] "
        "[dim](Enter to show commands only): [/dim]"
    ).strip()
    if not target:
        console.print(
            "\nCommands:\n"
            "  [cyan]burpollama doctor[/cyan]\n"
            "  [cyan]burpollama status[/cyan]\n"
            "  [cyan]burpollama scan <target> --mode passive[/cyan]\n"
            "  [cyan]burpollama scan <target> --mode bounty --yes[/cyan]\n"
            "  [cyan]burpollama history[/cyan]\n"
        )
        return 0
    mode = console.input("[bold]Mode[/bold] [passive/bounty/deep] (passive): ").strip().lower() or "passive"
    if mode not in MODE_MAP:
        console.print("[red]Unknown mode: {}[/red]".format(escape(mode)))
        return 2
    args = argparse.Namespace(
        command="scan",
        target=target,
        mode=mode,
        yes=False,
        scope=None,
        concurrency=5,
        rate_limit=2.0,
        timeout=10.0,
        retries=1,
        ai=use_ai,
        no_ai=not use_ai,
        ai_provider="",
        model="",
        quiet=False,
        json_output=False,
        follow=False,
        output="reports",
    )
    return await command_scan(args)


async def command_serve(args, open_browser: bool = False) -> int:
    dashboard_url = "http://{}:{}/ui".format(args.host, args.port)
    os.environ["BURPOLLAMA_DASHBOARD_URL"] = dashboard_url
    if open_browser:
        url = dashboard_url

        async def delayed_open():
            await asyncio.sleep(1.5)
            webbrowser.open(url)

        asyncio.get_event_loop().create_task(delayed_open())
    import uvicorn

    config = uvicorn.Config(
        "main:app",
        host=args.host,
        port=args.port,
    )
    server = uvicorn.Server(config)
    await server.serve()
    return 0


async def async_main(args) -> int:
    if args.command == "scan":
        return await command_scan(args)
    if args.command == "benchmark":
        return await command_benchmark(args)
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
    if args.command == "skills":
        return await command_skills(args)
    if args.command == "doctor":
        return await command_doctor(args)
    if args.command == "version":
        console.print("BurpOllama {}".format(__version__))
        return 0
    if args.command == "serve":
        return await command_serve(args)
    if args.command == "dashboard":
        return await command_serve(args, open_browser=True)
    return 1


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        try:
            return asyncio.run(command_launcher())
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped by user.[/yellow]")
            return 130
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        return command_validate(args)
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user.[/yellow]")
        return 130
    except (RuntimeError, httpx.HTTPError, OSError, json.JSONDecodeError) as exc:
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in {
            22, 32,
        }:
            # Downstream JSON/quiet consumers may intentionally close stdout.
            return 0
        console.print("[red]Error: {}[/red]".format(escape(str(exc))))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
