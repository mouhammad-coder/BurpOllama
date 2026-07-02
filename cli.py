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
  python3 cli.py findings --latest
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
import re
import shutil
import socket
import subprocess
import sys
import time
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree

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
from core.findings import (
    filter_final_findings,
    final_findings,
    render_final_tables,
    write_scan_artifacts,
)
from core.scope import ScanScope
from core.program_profile import (
    FINAL_OUTPUTS,
    GOALS,
    host_scope_entry,
    load_program_profile,
)
from core.scanner import scanner
from core.storage import scan_store


ROOT = Path(__file__).resolve().parent
FEEDBACK_PATH = ROOT / "data" / "feedback.jsonl"
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
    scan.add_argument(
        "--scope-file",
        help="Plain-text HackerOne/Bugcrowd scope file with includes and ! exclusions.",
    )
    scan.add_argument("--concurrency", type=int, default=5)
    scan.add_argument("--rate-limit", type=float, default=2.0)
    scan.add_argument("--timeout", type=float, default=10.0)
    scan.add_argument("--retries", type=int, default=1)
    scan.add_argument(
        "--time-budget",
        type=int,
        default=900,
        help="Maximum scan runtime in seconds before writing partial findings.",
    )
    scan.add_argument(
        "--max-urls",
        type=int,
        default=100,
        help="Maximum discovered in-scope URLs to carry into scan phases.",
    )
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
    scan.add_argument("--output", default="scans")
    scan.add_argument(
        "--no-external-tools",
        action="store_true",
        help="Skip optional Katana, Nuclei, TruffleHog, and Gitleaks integrations.",
    )
    scan.add_argument(
        "--oob-server",
        default="",
        help="Explicit OOB callback URL for authorized bounty/deep SSRF validation.",
    )

    autopilot = sub.add_parser(
        "ai-autopilot",
        help="Run a goal-based multi-agent workflow from program.yml scope.",
    )
    autopilot.add_argument("target", nargs="?")
    autopilot.add_argument("--from-burp", choices=("latest",), default="")
    autopilot.add_argument("--program", help="program.yml with scope and scanner permissions.")
    autopilot.add_argument("--goal", choices=GOALS, default="bounty-hunt")
    autopilot.add_argument("--mode", choices=tuple(MODE_MAP), default="passive")
    autopilot.add_argument("--multi-agent", action="store_true")
    autopilot.add_argument("--final-output", choices=FINAL_OUTPUTS, default="terminal")
    autopilot.add_argument("--yes", action="store_true", help="Confirm authorization non-interactively.")
    autopilot.add_argument("--scope", action="append", default=None, metavar="DOMAIN")
    autopilot.add_argument("--scope-file")
    autopilot.add_argument("--auth-profile", action="append", default=None)
    autopilot.add_argument("--concurrency", type=int, default=5)
    autopilot.add_argument("--rate-limit", type=float, default=2.0)
    autopilot.add_argument("--timeout", type=float, default=10.0)
    autopilot.add_argument("--retries", type=int, default=1)
    autopilot.add_argument("--time-budget", type=int, default=900)
    autopilot.add_argument("--max-urls", type=int, default=100)
    autopilot.add_argument("--ai", action="store_true")
    autopilot.add_argument("--no-ai", action="store_true")
    autopilot.add_argument("--ai-provider", default="")
    autopilot.add_argument("--model", default="")
    autopilot.add_argument("--output", default="scans")
    autopilot.add_argument("--no-external-tools", action="store_true")
    autopilot.add_argument("--oob-server", default="")
    autopilot.add_argument(
        "--dry-run-plan",
        action="store_true",
        help="Print the authorized scan plan without sending scan requests.",
    )

    burp = sub.add_parser("burp", help="Import or analyze Burp Suite traffic.")
    burp_sub = burp.add_subparsers(dest="burp_command", required=True)
    burp_import = burp_sub.add_parser("import", help="Import Burp HTTP history for passive analysis.")
    burp_import.add_argument("file")
    burp_import.add_argument("--program")

    preflight = sub.add_parser("preflight", help="Check scope and permission status without vulnerability testing.")
    preflight.add_argument("target")
    preflight.add_argument("--program", required=True, help="program.yml with scope and scanner permissions.")
    preflight.add_argument("--goal", choices=GOALS, default="bounty-hunt")
    preflight.add_argument("--mode", choices=tuple(MODE_MAP), default="passive")

    from core.benchmarks import BENCHMARKS

    benchmark = sub.add_parser(
        "benchmark",
        help="Run an explicit benchmark harness; never used by normal scans.",
    )
    benchmark.add_argument("lab", choices=tuple(BENCHMARKS))
    benchmark.add_argument("--target", default="")
    benchmark.add_argument("--yes", action="store_true")
    benchmark.add_argument("--output", default="scans")
    benchmark.add_argument("--timeout", type=float, default=10.0)
    benchmark.add_argument("--check", action="store_true", help="Check whether the benchmark target is reachable without running probes.")

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

    report = sub.add_parser(
        "report",
        help="Deprecated. Use `burpollama findings --latest` instead.",
    )
    report.add_argument("--scan-id")
    report.add_argument("--latest", action="store_true", help="Use the most recent stored scan.")
    report.add_argument(
        "--format",
        default="markdown",
        help="Deprecated; ignored.",
    )
    report.add_argument("--output")

    findings = sub.add_parser("findings", help="Show final scan findings.")
    findings.add_argument("--scan-id")
    findings.add_argument("--latest", action="store_true", help="Use the most recent stored scan.")
    findings.add_argument("--show-info", action="store_true")
    findings.add_argument("--show-rejected", action="store_true")
    findings.add_argument("--show-all", action="store_true")
    findings.add_argument("--json", action="store_true", dest="json_output")
    findings.add_argument(
        "--min-rate",
        choices=("critical", "high", "medium", "low", "info"),
        default="",
    )
    findings.add_argument("--min-confidence", type=int, default=0)

    train = sub.add_parser("train", help="Label findings for local AI feedback data.")
    train.add_argument("--scan-id", help="Scan ID to label interactively.")
    train.add_argument("--stats", action="store_true", help="Show feedback dataset stats.")

    scope_check = sub.add_parser("scope-check", help="Check a URL against a scope file.")
    scope_check.add_argument("--scope-file")
    scope_check.add_argument("--program-json", help="Import a saved HackerOne/Bugcrowd-style program scope JSON export.")
    scope_check.add_argument("--write-scope", help="Write normalized scope entries from --program-json.")
    scope_check.add_argument("--write-manifest", help="Write the scope preflight audit as JSON.")
    scope_check.add_argument("--audit", action="store_true", help="Print a full scope preflight audit.")
    scope_check.add_argument("--target", default="", help="Target URL to audit against the scope file.")
    scope_check.add_argument("url", nargs="?")

    sub.add_parser("status", help="Show local scanner, storage, tools, and AI readiness.")
    history = sub.add_parser("history", help="List locally stored scans.")
    history.add_argument("--ready-only", action="store_true", help="Only show scans with great or manual-check findings.")
    history.add_argument("--limit", type=int, default=100)
    readiness_check = sub.add_parser(
        "readiness-check",
        help="Deprecated. Use `burpollama findings --latest` instead.",
    )
    readiness_check.add_argument("--scan-id")
    readiness_check.add_argument("--latest", action="store_true", help="Use the most recent stored scan.")
    readiness_check.add_argument(
        "--require-great-finding",
        action="store_true",
        help="Deprecated; retained for old scripts and ignored.",
    )
    readiness_check.add_argument("--json", action="store_true", help="Deprecated.")
    readiness_check.add_argument("--output", help="Deprecated; no file is written.")
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
    run_skill.add_argument("--mode", choices=("passive", "validate", "findings", "report"), default="passive")
    run_skill.add_argument("--scope", action="append", default=None)
    run_skill.add_argument("--scope-file")
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


def _combined_scope_entries(args) -> list[str]:
    entries = list(getattr(args, "scope", None) or [])
    scope_file = getattr(args, "scope_file", None)
    if scope_file:
        from core.scope import load_scope_file

        loaded, warnings = load_scope_file(scope_file)
        entries.extend(loaded)
        for warning in warnings:
            console.print("[yellow]Scope warning: {}[/yellow]".format(escape(warning)))
    return entries


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
            ("P5:", "PHASE 5 - FINAL FINDINGS"),
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
        "final_findings": 6,
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
        elif event_type == "findings_prepared":
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
    elapsed = max(0, int(time.monotonic() - started))
    if not isinstance(scan.get("final_findings"), dict):
        scan["final_findings"] = final_findings(scan)
    console.print(render_final_tables(scan, scan["final_findings"]), markup=False)
    console.print(
        "Scan ID: {}\nDuration: {:02d}:{:02d}:{:02d}\nNext: [cyan]burpollama findings --scan-id {}[/cyan]".format(
            escape(str(scan_id)),
            elapsed // 3600,
            (elapsed % 3600) // 60,
            elapsed % 60,
            escape(str(scan_id)),
        )
    )


def _finding_url(finding: dict, fallback: str = "") -> str:
    return str(
        finding.get("url")
        or finding.get("affected_url")
        or finding.get("target")
        or fallback
        or ""
    )


def _finding_confidence(finding: dict) -> str:
    value = finding.get("confidence")
    if value is None:
        value = finding.get("confidence_score")
    if value is None:
        return ""
    return "{}%".format(value)


def _findings_table_rows(scan: dict) -> list[dict]:
    target = str(scan.get("target", ""))
    analysis = scan.get("analysis", {})
    gate = analysis.get("zero_fp_gate") if isinstance(analysis, dict) else {}
    rows = []
    if isinstance(gate, dict) and gate:
        buckets = (
            ("Great Finding", gate.get("valid_bugs", []) or []),
            ("Needs Manual Check", gate.get("needs_more_proof", []) or []),
            ("Needs Manual Check", gate.get("candidates", []) or []),
            ("Informational", gate.get("informational", []) or []),
        )
    elif "confirmed_findings" in scan or "candidate_findings" in scan:
        buckets = (
            ("Great Finding", scan.get("confirmed_findings", []) or []),
            ("Needs Manual Check", scan.get("candidate_findings", []) or []),
        )
    else:
        buckets = (("Observed", scan.get("triaged_findings") or scan.get("findings") or scan.get("raw_findings") or []),)
    for readiness, findings in buckets:
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            rows.append({
                "finding": _clip("[{}] {}".format(
                    _finding_badge(finding, readiness),
                    str(finding.get("title") or finding.get("vuln_type") or "Finding"),
                ), 48),
                "url": _clip(_finding_url(finding, target), 44),
            })
    return rows


def _short_severity(finding: dict) -> str:
    severity = str(finding.get("severity", "INFO")).upper()
    return {
        "CRITICAL": "CRIT",
        "HIGH": "HIGH",
        "MEDIUM": "MED",
        "LOW": "LOW",
        "INFO": "INFO",
        "INFORMATIONAL": "INFO",
    }.get(severity, severity[:4] or "INFO")


def _finding_badge(finding: dict, readiness: str) -> str:
    parts = [_short_severity(finding), _short_readiness(readiness)]
    confidence = _finding_confidence(finding)
    if confidence:
        parts.append(confidence)
    return " ".join(parts)


def _short_readiness(readiness: str) -> str:
    return {
        "Great Finding": "Great",
        "Needs Manual Check": "Manual",
        "Observed": "Observed",
        "Informational": "Info",
    }.get(readiness, readiness)


def _clip(value: str, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    keep = max(1, (limit - 3) // 2)
    tail = max(1, limit - 3 - keep)
    return "{}...{}".format(text[:keep], text[-tail:])


def _print_findings_table(scan: dict, limit: int = 15) -> None:
    rows = _findings_table_rows(scan)
    if not rows:
        console.print("[dim]No findings table to display.[/dim]")
        return
    table = Table(box=box.ROUNDED, title="Bounty findings", expand=True)
    table.add_column("Finding", no_wrap=True, overflow="ellipsis")
    table.add_column("Target / URL", no_wrap=True, overflow="ellipsis")
    for row in rows[:limit]:
        table.add_row(
            row["finding"],
            row["url"],
        )
    console.print(table)
    if len(rows) > limit:
        console.print("[dim]{} additional finding(s) omitted; use `burpollama findings --latest` for the full list.[/dim]".format(len(rows) - limit))


def _scan_readiness_summary(scan: dict) -> dict:
    analysis = scan.get("analysis", {})
    gate = analysis.get("zero_fp_gate") if isinstance(analysis, dict) else {}
    if isinstance(gate, dict) and gate:
        valid = list(gate.get("valid_bugs", []) or [])
        manual = (
            list(gate.get("needs_more_proof", []) or [])
            + list(gate.get("candidates", []) or [])
            + list(gate.get("informational", []) or [])
        )
        proof_blocked = list(gate.get("needs_more_proof", []) or [])
    else:
        valid = list(scan.get("confirmed_findings", []) or [])
        manual = list(scan.get("candidate_findings", []) or [])
        proof_blocked = [
            finding for finding in manual
            if str(finding.get("zero_fp_label") or "").upper() == "NEEDS PROOF"
        ]
    issue_keys = set()
    for finding in valid:
        issue_keys.add((
            str(finding.get("title") or finding.get("vuln_type") or "").strip().lower(),
            str(finding.get("severity") or "").strip().upper(),
            str(finding.get("vuln_type") or "").strip().lower(),
        ))
    return {
        "great_finding_issues": len(issue_keys),
        "great_findings": len(valid),
        "manual_check_findings": len(manual),
        "proof_blocked_findings": len(proof_blocked),
        "missing_evidence_artifacts": _missing_evidence_artifacts(valid),
    }


def _finding_artifact_path(finding: dict) -> str:
    artifact = finding.get("evidence_artifact") or {}
    if not isinstance(artifact, dict):
        artifact = {}
    path = artifact.get("artifact_path")
    if path is None and isinstance(artifact.get("metadata"), dict):
        path = artifact["metadata"].get("artifact_path")
    if path is None:
        path = finding.get("artifact_path", "")
    return str(path or "").strip()


def _missing_evidence_artifacts(findings: list[dict]) -> int:
    missing = 0
    for finding in findings:
        path = _finding_artifact_path(finding)
        if not path or not Path(path).exists():
            missing += 1
    return missing


async def command_scan(args) -> int:
    target = normalized_target(args.target)
    if not authorized(args, target):
        return 2
    scope_entries = _combined_scope_entries(args)
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
        allowed_domains=scope_entries,
        concurrency=args.concurrency,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        retries=args.retries,
        time_budget=args.time_budget,
        max_urls=args.max_urls,
        ai_provider=args.ai_provider,
        ai_enabled=ai_enabled,
        model=args.model,
        output=args.output,
        oob_server=args.oob_server,
        no_external_tools=args.no_external_tools,
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
    if getattr(args, "check", False):
        return await command_benchmark_check(args, benchmark, target)
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
    from core.agents.final_findings_presenter_agent import FinalFindingsPresenterAgent
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
    await FinalFindingsPresenterAgent().execute(context)
    context.scan["status"] = "complete"
    context.scan["phase"] = "complete"
    context.scan["finished"] = datetime.now(timezone.utc).isoformat()
    context.scan["agent_status"] = context.scheduler.snapshot()
    context.scan["rate_limiter"] = context.rate_limiter.snapshot()
    scan_store.save(context.scan, context.triaged_findings)
    print_results(context.scan, started)
    return 0


BURP_IMPORT_DIR = ROOT / "data" / "burp-imports"


def _load_latest_burp_import() -> dict:
    path = BURP_IMPORT_DIR / "latest.json"
    if not path.exists():
        raise RuntimeError("No Burp import found. Run: burpollama burp import <file> --program program.yml")
    return json.loads(path.read_text(encoding="utf-8"))


def _program_target_from_scope(program_profile) -> str:
    for entry in program_profile.in_scope:
        text = str(entry).strip()
        if text and not text.startswith("!"):
            return normalized_target(text.lstrip("*."))
    return ""


def _autopilot_target(args, program_profile=None) -> str:
    if getattr(args, "target", ""):
        return normalized_target(args.target)
    if getattr(args, "from_burp", "") == "latest":
        imported = _load_latest_burp_import()
        if imported.get("target"):
            return normalized_target(imported["target"])
    if program_profile:
        return _program_target_from_scope(program_profile)
    return ""


def _manual_auth_required_message(target: str) -> str:
    return (
        'Authorization confirmation required: "I confirm I am authorized to test this target." '
        "For non-interactive use, pass --yes and --scope {}.".format(
            host_scope_entry(target) or "target.com"
        )
    )


def _redacted_auth_profile(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("auth profile must be a JSON object: {}".format(path))
    profile = {
        "name": str(data.get("name") or Path(path).stem),
        "base_url": str(data.get("base_url") or ""),
        "cookies": {str(key): "[REDACTED]" for key in dict(data.get("cookies") or {})},
        "headers": {str(key): "[REDACTED]" for key in dict(data.get("headers") or {})},
        "role": str(data.get("role") or ""),
        "notes": str(data.get("notes") or ""),
    }
    from core.findings import redact_json

    return redact_json(profile)


def _load_auth_profiles(paths: list[str] | None) -> list[dict[str, Any]]:
    profiles = [_redacted_auth_profile(path) for path in (paths or [])]
    if len(profiles) > 2:
        raise ValueError("At most two --auth-profile files are supported for safe comparison.")
    return profiles


def _burp_url_metadata(urls: list[str]) -> dict[str, Any]:
    patterns = {
        "auth_endpoints": re.compile(r"(?i)/(login|logout|signin|signup|password|reset|mfa|oauth|sso)(/|$)"),
        "object_id_endpoints": re.compile(r"/(?:[A-Za-z0-9_-]+/)*(\d+|[0-9a-fA-F-]{16,})(?:[/?#]|$)"),
        "upload_endpoints": re.compile(r"(?i)/(upload|file|files|attachment|avatar|media)(/|$)"),
        "graphql_endpoints": re.compile(r"(?i)/graphql(?:/|$)|query="),
        "redirect_parameters": re.compile(r"(?i)[?&](next|url|redirect|return|continue|dest|destination)="),
        "admin_routes": re.compile(r"(?i)/(admin|administrator|dashboard|manage|internal)(/|$)"),
        "api_routes": re.compile(r"(?i)/api/|/v[0-9]+/"),
    }
    return {
        key: [url for url in urls if pattern.search(url)]
        for key, pattern in patterns.items()
    }


def _burp_passive_findings(urls: list[str], imported: dict) -> list[dict[str, Any]]:
    metadata = _burp_url_metadata(urls)
    findings: list[dict[str, Any]] = []

    def add(key: str, title: str, severity: str, evidence: str, manual_step: str) -> None:
        matches = metadata.get(key, [])
        if not matches:
            return
        findings.append({
            "id": "burp-{}".format(key.replace("_", "-")),
            "source": "burp-import",
            "title": title,
            "vuln_type": title,
            "severity": severity,
            "confidence": 65,
            "url": matches[0],
            "evidence": "{}: {} example(s), e.g. {}".format(evidence, len(matches), matches[0]),
            "description": "Passive Burp import observation. No replay was performed.",
            "business_impact": "Imported traffic shows a high-value surface that may contain bounty-relevant authorization or workflow issues.",
            "manual_check_needed": manual_step,
            "missing_proof": "No replay or two-account proof from imported traffic",
            "evidence_strength": "weak",
            "exploitability_status": "candidate",
            "redaction_status": "redacted",
        })

    add("object_id_endpoints", "IDOR/BOLA candidate from Burp traffic", "HIGH", "Object ID route observed", "Use two authorized accounts and test whether User A can access User B's object response for the same endpoint shape.")
    add("upload_endpoints", "Upload testing candidate from Burp traffic", "MEDIUM", "Upload route observed", "If upload testing is allowed, upload a benign text/image file and verify storage, content-type, and access controls only on owned test data.")
    add("graphql_endpoints", "GraphQL endpoint candidate from Burp traffic", "MEDIUM", "GraphQL route observed", "Confirm GraphQL testing permission, then manually check introspection and authorization with authorized accounts.")
    add("redirect_parameters", "Open redirect parameter candidate from Burp traffic", "MEDIUM", "Redirect-like parameter observed", "Manually test a harmless external URL parameter only if the program allows redirect testing.")
    add("admin_routes", "Exposed admin route candidate from Burp traffic", "MEDIUM", "Admin route observed", "Check whether the route is only a login page or exposes sensitive admin functionality to the current authorized role.")
    add("auth_endpoints", "Authentication workflow manual-check candidate", "MEDIUM", "Auth route observed", "Review account enumeration, password reset, MFA, and session behavior with owned authorized test accounts.")
    add("api_routes", "API route cluster from Burp traffic", "INFO", "API routes observed", "Cluster API routes by resource and manually review object ownership, excessive data exposure, and role boundaries.")
    return findings


def _normalize_url_for_import(url: str) -> str:
    from core.scanner import normalize_scan_url

    return normalize_scan_url(url).rstrip("#")


def _urls_from_burp_file(path: str, scope_entries: list[str]) -> list[str]:
    source = Path(path)
    found: list[str] = []
    if source.suffix.lower() == ".har":
        payload = json.loads(source.read_text(encoding="utf-8", errors="replace"))
        for entry in (((payload.get("log") or {}).get("entries")) or []):
            request = entry.get("request") if isinstance(entry, dict) else {}
            if isinstance(request, dict) and request.get("url"):
                found.append(str(request["url"]))
    else:
        try:
            for _event, elem in ElementTree.iterparse(str(source), events=("end",)):
                if elem.text:
                    found.extend(re.findall(r"https?://[^\s\"'<>]+", elem.text))
                elem.clear()
        except ElementTree.ParseError:
            text = source.read_text(encoding="utf-8", errors="replace")
            found.extend(re.findall(r"https?://[^\s\"'<>]+", text))
    scope = None
    target = (
        _program_target_from_scope(SimpleNamespace(in_scope=scope_entries))
        if scope_entries
        else (found[0] if found else "")
    )
    if target and scope_entries:
        scope = ScanScope(target, scope_entries)
    urls = []
    for url in found:
        cleaned = _normalize_url_for_import(url.rstrip(".,);]"))
        if scope and not scope.allows(cleaned):
            continue
        urls.append(cleaned)
    return list(dict.fromkeys(urls))


def _offline_burp_scan(args, target: str, program_profile, warnings: list[str]) -> dict:
    imported = _load_latest_burp_import()
    scope_entries = program_profile.scope_entries if program_profile else list(getattr(args, "scope", None) or [])
    urls = _urls_from_burp_file(imported["path"], scope_entries)
    passive_findings = _burp_passive_findings(urls, imported)
    scan_id = "burp-import-{}".format(int(time.time()))
    scan = {
        "id": scan_id,
        "target": target,
        "status": "complete",
        "mode": "passive",
        "goal": "burp-import-analysis",
        "program_profile": program_profile.to_dict() if program_profile else {
            "program": "not provided",
            "automated_scanning_allowed": "user-confirmed",
        },
        "program": program_profile.name if program_profile else "not provided",
        "automated_scanning_allowed": program_profile.scanner_permission_label if program_profile else "user-confirmed",
        "program_warnings": warnings,
        "recon": {"urls": urls, "burp_import": imported},
        "raw_findings": passive_findings,
        "triaged_findings": passive_findings,
        "analysis": {
            "burp_import": imported,
            "burp_import_metadata": _burp_url_metadata(urls),
            "no_replay": True,
        },
        "auth_profiles": _load_auth_profiles(getattr(args, "auth_profile", None)),
        "agent_status": {
            "scope": {},
            "recon": {},
            "final-findings-presenter": {},
        },
        "options": {"output": args.output},
    }
    scan["final_findings"] = final_findings(scan)
    scan["artifact_paths"] = write_scan_artifacts(scan, args.output)
    return scan


def _resolve_target_host(target: str) -> tuple[bool, str]:
    host = urlparse(normalized_target(target)).hostname or ""
    if not host:
        return False, "target has no hostname"
    try:
        socket.getaddrinfo(host, None)
        return True, "resolves"
    except OSError as exc:
        return False, "{}: {}".format(type(exc).__name__, exc)


def _plan_for_target(args, program_profile) -> dict[str, Any]:
    target = normalized_target(args.target)
    allowed, scope_reason = program_profile.target_allowed(target)
    mode, warnings = program_profile.choose_mode(args.mode, args.goal)
    rate_limit, concurrency = program_profile.safe_limits(
        getattr(args, "rate_limit", program_profile.max_rps),
        getattr(args, "concurrency", program_profile.max_concurrency),
    )
    validation = program_profile.validation_errors()
    checks_allowed = ["scope validation", "passive reconnaissance", "header review", "Burp import analysis"]
    checks_blocked = []
    if program_profile.scanner_permission_label != "yes" or mode == "passive":
        checks_blocked.append("active scanner probes")
    if program_profile.upload_testing_allowed is not True:
        checks_blocked.append("upload testing")
    if program_profile.auth_testing_allowed is not True:
        checks_blocked.append("authenticated access-control comparison")
    if program_profile.graphql_introspection_allowed is not True:
        checks_blocked.append("GraphQL introspection")
    if program_profile.oob_testing_allowed is not True:
        checks_blocked.append("OOB testing")
    if program_profile.cloud_ai_allowed is not True:
        checks_blocked.append("cloud AI")
    agents = ["Scope Guardian", "Recon", "Crawler", "Header/Cookie", "Final Findings Presenter"]
    if mode != "passive":
        agents.extend(["Access Control", "GraphQL", "Upload", "Redirect", "Rate Limit"])
    return {
        "target": target,
        "scope_allowed": allowed,
        "scope_reason": scope_reason or ("in scope" if allowed else "outside scope"),
        "mode": mode,
        "warnings": warnings,
        "program_warnings": validation,
        "scanner_permission": program_profile.scanner_permission_label,
        "rate_limit": rate_limit,
        "concurrency": concurrency,
        "cloud_ai_allowed": program_profile.cloud_ai_allowed,
        "auth_testing_allowed": program_profile.auth_testing_allowed,
        "upload_testing_allowed": program_profile.upload_testing_allowed,
        "oob_testing_allowed": program_profile.oob_testing_allowed,
        "checks_allowed": checks_allowed,
        "checks_blocked": checks_blocked,
        "agents": agents,
        "estimated_request_budget": int(rate_limit * 60),
        "active_reason": "active checks enabled by program.yml" if mode != "passive" and program_profile.scanner_permission_label == "yes" else "active checks disabled because permission is missing, false, or passive mode was selected",
        "recommended_command": "burpollama ai-autopilot {} --program {} --goal {} --mode {} --multi-agent --final-output terminal".format(target, program_profile.path, args.goal, mode),
    }


async def command_preflight(args) -> int:
    program_profile = load_program_profile(args.program)
    plan = _plan_for_target(args, program_profile)
    resolves, resolve_reason = _resolve_target_host(plan["target"])
    table = Table(title="BurpOllama Preflight", box=box.SIMPLE_HEAVY)
    table.add_column("Check")
    table.add_column("Result")
    rows = [
        ("Target", plan["target"]),
        ("Target resolves", "yes" if resolves else "no ({})".format(resolve_reason)),
        ("In scope", "yes" if plan["scope_allowed"] else "no ({})".format(plan["scope_reason"])),
        ("Scanner allowed", str(program_profile.scanner_allowed).lower() if program_profile.scanner_allowed is not None else "unknown"),
        ("Automated testing allowed", str(program_profile.automated_testing_allowed).lower() if program_profile.automated_testing_allowed is not None else "unknown"),
        ("Mode allowed", "yes" if plan["mode"] == args.mode or not program_profile.allowed_modes else "no; requested mode changed"),
        ("Effective mode", plan["mode"]),
        ("Max RPS", str(plan["rate_limit"])),
        ("Max concurrency", str(plan["concurrency"])),
        ("Cloud AI allowed", str(plan["cloud_ai_allowed"]).lower() if plan["cloud_ai_allowed"] is not None else "unknown"),
        ("Auth testing allowed", str(plan["auth_testing_allowed"]).lower() if plan["auth_testing_allowed"] is not None else "unknown"),
        ("Upload testing allowed", str(plan["upload_testing_allowed"]).lower() if plan["upload_testing_allowed"] is not None else "unknown"),
        ("OOB allowed", str(plan["oob_testing_allowed"]).lower() if plan["oob_testing_allowed"] is not None else "unknown"),
        ("Blocked checks", ", ".join(plan["checks_blocked"]) or "none"),
        ("Recommended safe command", plan["recommended_command"]),
    ]
    for key, value in rows:
        table.add_row(key, escape(str(value)))
    console.print(table)
    for warning in plan["program_warnings"] + plan["warnings"]:
        console.print("[yellow]{}[/yellow]".format(escape(warning)))
    if plan["scanner_permission"] == "unknown":
        console.print("[yellow]Scanner permission is unknown; recommended command is passive-only.[/yellow]")
    return 0 if resolves and plan["scope_allowed"] else 1


def _print_dry_run_plan(plan: dict[str, Any]) -> None:
    console.print("Dry Run Plan")
    console.print("Scope status: {}".format("in scope" if plan["scope_allowed"] else plan["scope_reason"]))
    console.print("Scanner permission status: {}".format(plan["scanner_permission"]))
    console.print("Agents that would run: {}".format(", ".join(plan["agents"])))
    console.print("Checks allowed: {}".format(", ".join(plan["checks_allowed"]) or "none"))
    console.print("Checks blocked: {}".format(", ".join(plan["checks_blocked"]) or "none"))
    console.print("Estimated request budget: {} requests/minute".format(plan["estimated_request_budget"]))
    console.print("Reason active checks are disabled/enabled: {}".format(plan["active_reason"]))
    console.print("Recommended command: {}".format(plan["recommended_command"]))


async def command_ai_autopilot(args) -> int:
    program_profile = load_program_profile(args.program) if args.program else None
    target = _autopilot_target(args, program_profile)
    if not target:
        raise RuntimeError("Pass a target URL or use --from-burp latest with a prior Burp import.")

    warnings: list[str] = []
    if program_profile:
        allowed, reason = program_profile.target_allowed(target)
        if not allowed:
            raise PermissionError(reason)
        if reason:
            warnings.append(reason)
        mode, mode_warnings = program_profile.choose_mode(args.mode, args.goal)
        warnings.extend(mode_warnings)
        rate_limit, concurrency = program_profile.safe_limits(args.rate_limit, args.concurrency)
        scope_entries = program_profile.scope_entries
    else:
        if not getattr(args, "yes", False) or not getattr(args, "scope", None):
            if sys.stdin.isatty():
                answer = console.input(
                    '[bold yellow]Type "I confirm I am authorized to test this target" to continue: [/bold yellow]'
                )
                if answer.strip() == "I confirm I am authorized to test this target":
                    args.scope = list(getattr(args, "scope", None) or []) or [host_scope_entry(target)]
                else:
                    console.print("[red]Authorization confirmation did not match.[/red]")
                    return 2
            else:
                console.print("[red]{}[/red]".format(escape(_manual_auth_required_message(target))))
                return 2
        if not getattr(args, "scope", None):
            console.print("[red]{}[/red]".format(escape(_manual_auth_required_message(target))))
            return 2
        mode = "passive" if args.goal in {"recon", "passive-analysis", "manual-check", "burp-import-analysis"} else args.mode
        rate_limit = args.rate_limit
        concurrency = args.concurrency
        scope_entries = _combined_scope_entries(args)
        if not scope_entries:
            scope_entries = [host_scope_entry(target)]

    if getattr(args, "dry_run_plan", False):
        if not program_profile:
            raise RuntimeError("--dry-run-plan requires --program so permissions can be evaluated.")
        plan_args = SimpleNamespace(
            target=target,
            mode=args.mode,
            goal=args.goal,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
        )
        _print_dry_run_plan(_plan_for_target(plan_args, program_profile))
        return 0

    if program_profile and program_profile.cloud_ai_allowed is False:
        warnings.append("Cloud AI is not allowed by program.yml. AI agents disabled.")
        ai_requested = False
    else:
        ai_requested = _scan_ai_enabled(args, await _ai_status(args.ai_provider, args.model))

    if program_profile:
        if program_profile.upload_testing_allowed is False:
            warnings.append("Upload testing is disabled by program.yml; upload findings stay manual-check only.")
        if program_profile.auth_testing_allowed is False and getattr(args, "auth_profile", None):
            warnings.append("Authenticated testing is disabled by program.yml; ignoring --auth-profile values.")
            args.auth_profile = []
        if program_profile.graphql_introspection_allowed is False:
            warnings.append("GraphQL introspection is disabled by program.yml; GraphQL findings stay passive/manual-check.")
        if program_profile.oob_testing_allowed is False and args.oob_server:
            warnings.append("OOB testing is disabled by program.yml; ignoring --oob-server.")
            args.oob_server = ""
        if any(item.lower() in {"dos", "brute_force", "brute-force", "waf_bypass", "evasion"} for item in program_profile.forbidden_tests):
            warnings.append("Forbidden tests are blocked by program.yml.")

    if args.goal == "burp-import-analysis" and getattr(args, "from_burp", "") == "latest":
        result = _offline_burp_scan(args, target, program_profile, warnings)
        if args.final_output == "json":
            console.print_json(json.dumps({
                "scan_id": result.get("id"),
                "target": result.get("target"),
                "goal": result.get("goal"),
                "mode": result.get("mode"),
                "program": result.get("program_profile", {}),
                "automated_scanning_allowed": result.get("automated_scanning_allowed"),
                "warnings": warnings,
                "findings": result["final_findings"],
            }, ensure_ascii=False, sort_keys=True))
        else:
            banner()
            for warning in warnings:
                console.print("[yellow]{}[/yellow]".format(escape(warning)))
            console.print(render_final_tables(result, result["final_findings"]), markup=False)
        return 0

    prepared = scanner.prepare(
        target,
        mode,
        authorization_confirmed=True,
        allowed_domains=scope_entries,
        concurrency=concurrency,
        rate_limit=rate_limit,
        timeout=args.timeout,
        retries=args.retries,
        time_budget=args.time_budget,
        max_urls=args.max_urls,
        ai_provider=args.ai_provider,
        ai_enabled=ai_requested,
        model=args.model,
        output=args.output,
        oob_server=args.oob_server,
        no_external_tools=args.no_external_tools or args.goal in {"passive-analysis", "burp-import-analysis"},
        goal=args.goal,
        final_output=args.final_output,
        program_profile=program_profile.to_dict() if program_profile else {
            "program": "not provided",
            "automated_scanning_allowed": "user-confirmed",
            "in_scope": scope_entries,
        },
    )
    prepared["program_warnings"] = warnings
    prepared["auth_profiles"] = _load_auth_profiles(getattr(args, "auth_profile", None))
    if len(prepared["auth_profiles"]) == 1:
        prepared.setdefault("program_warnings", []).append("One auth profile supplied; IDOR/BOLA items require manual two-account validation.")
    if len(prepared["auth_profiles"]) == 2:
        prepared.setdefault("analysis", {})["access_control_comparison"] = {
            "profiles": [profile.get("name") for profile in prepared["auth_profiles"]],
            "safe_compare_enabled": True,
        }
    if getattr(args, "from_burp", ""):
        prepared["burp_import"] = _load_latest_burp_import()

    if args.final_output != "json":
        banner()
        for warning in warnings:
            console.print("[yellow]{}[/yellow]".format(escape(warning)))

    result = await scanner.run_prepared(prepared)
    result["program_warnings"] = warnings
    if args.final_output == "json":
        findings = final_findings(result)
        console.print_json(json.dumps({
            "scan_id": result.get("id"),
            "target": result.get("target"),
            "goal": result.get("goal"),
            "mode": result.get("mode"),
            "program": result.get("program_profile", {}),
            "automated_scanning_allowed": result.get("automated_scanning_allowed"),
            "warnings": warnings,
            "findings": findings,
        }, ensure_ascii=False, sort_keys=True))
    else:
        console.print(render_final_tables(result, final_findings(result)), markup=False)
    return 0 if str(result.get("status", "")).lower() not in {"failed", "error"} else 1


async def command_burp(args) -> int:
    if args.burp_command != "import":
        return 1
    source = Path(args.file).expanduser()
    if not source.exists():
        raise RuntimeError("Burp import file not found: {}".format(source))
    program_profile = load_program_profile(args.program) if args.program else None
    scope_entries = program_profile.scope_entries if program_profile else []
    urls = _urls_from_burp_file(str(source), scope_entries)
    BURP_IMPORT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "path": str(source),
        "program": program_profile.to_dict() if program_profile else {},
        "target": _program_target_from_scope(program_profile) if program_profile else "",
        "size_bytes": source.stat().st_size,
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "url_count": len(urls),
        "metadata": _burp_url_metadata(urls),
        "secret_redaction": "final output and artifacts redact cookies, authorization headers, tokens, emails, and common secrets",
        "no_replay": True,
    }
    latest = BURP_IMPORT_DIR / "latest.json"
    latest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    console.print("[green]Imported Burp history metadata[/green]: {}".format(escape(str(source))))
    console.print("[cyan]Next: burpollama ai-autopilot --from-burp latest --goal burp-import-analysis --final-output chat[/cyan]")
    return 0


async def command_benchmark_check(args, benchmark: dict, target: str) -> int:
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(float(args.timeout), connect=min(float(args.timeout), 3.0)),
        ) as client:
            response = await client.get(target)
    except httpx.HTTPError as exc:
        console.print(
            "[red]Benchmark target is not reachable: {}[/red]".format(
                escape(str(exc))
            )
        )
        console.print(
            "Start OWASP Juice Shop locally, for example:\n"
            "[cyan]docker run --rm -p 3000:3000 bkimminich/juice-shop[/cyan]\n"
            "Then run:\n"
            "[cyan]python cli.py benchmark {} --yes[/cyan]".format(
                escape(str(args.lab))
            )
        )
        return 2
    body = response.text[:1000]
    looks_expected = (
        "OWASP Juice Shop" in body
        or "juice-shop" in body.lower()
        or response.status_code in {200, 301, 302}
    )
    console.print(
        "[green]Benchmark target reachable[/green]: {} HTTP {}".format(
            escape(target),
            response.status_code,
        )
    )
    console.print("Lab: {}".format(escape(str(benchmark["label"]))))
    if not looks_expected:
        console.print(
            "[yellow]Warning: response did not look like the expected lab. "
            "Confirm this is your authorized benchmark target before running probes.[/yellow]"
        )
    console.print(
        "Run benchmark:\n[cyan]python cli.py benchmark {} --target {} --yes[/cyan]".format(
            escape(str(args.lab)),
            escape(target),
        )
    )
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
    console.print(
        "[yellow]This command is deprecated. Use `burpollama findings --latest` instead.[/yellow]"
    )
    return 2


async def command_findings(args) -> int:
    scan_id = _resolve_scan_id(args)
    scan = scan_store.get(scan_id)
    if not scan:
        raise RuntimeError("Local scan not found: {}".format(scan_id))
    findings = scan.get("final_findings")
    if not isinstance(findings, dict):
        findings = final_findings(scan)
    filtered = filter_final_findings(
        findings,
        show_info=args.show_info,
        show_rejected=args.show_rejected,
        show_all=args.show_all,
        min_rate=args.min_rate,
        min_confidence=args.min_confidence,
    )
    if args.json_output:
        console.print_json(json.dumps({
            "scan_id": scan_id,
            "target": scan.get("target", ""),
            "findings": filtered,
            "counts": findings.get("counts", {}),
        }, ensure_ascii=False, sort_keys=True))
        return 0
    if (
        not args.show_info
        and not args.show_rejected
        and not args.show_all
        and not args.min_rate
        and not args.min_confidence
    ):
        console.print(render_final_tables(scan, findings), markup=False)
        return 0
    table = Table(box=box.ROUNDED, title="Filtered Findings")
    table.add_column("#", justify="right")
    table.add_column("Status")
    table.add_column("Finding")
    table.add_column("Rate")
    table.add_column("Confidence", justify="right")
    table.add_column("Affected Asset")
    table.add_column("Next Step")
    for index, finding in enumerate(filtered, start=1):
        table.add_row(
            str(index),
            str(finding.get("status", "")),
            str(finding.get("title", "")),
            str(finding.get("rate", "")),
            "{}%".format(finding.get("confidence", 0)),
            str(finding.get("affected_asset", "")),
            str(finding.get("manual_check_needed") or finding.get("next_step") or ""),
        )
    console.print(table)
    return 0


def _resolve_scan_id(args) -> str:
    scan_id = str(getattr(args, "scan_id", "") or "").strip()
    if scan_id:
        return scan_id
    if getattr(args, "latest", False):
        scans = scan_store.list(1)
        if not scans:
            raise RuntimeError("No stored scans found.")
        return str(scans[0].get("scan_id", ""))
    raise RuntimeError("Pass --scan-id <id> or --latest.")


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
    scans = scan_store.list(getattr(args, "limit", 100))
    table = Table(title="Scan history", box=box.ROUNDED)
    for column in ("Scan ID", "Target", "Status", "Great", "Manual", "Proof", "Started"):
        table.add_column(column)
    for scan in scans:
        scan_id = str(scan.get("scan_id", ""))
        stored = scan_store.get(scan_id) or scan
        readiness = _scan_readiness_summary(stored)
        if getattr(args, "ready_only", False) and not (
            readiness["great_finding_issues"]
            or readiness["manual_check_findings"]
            or readiness["proof_blocked_findings"]
        ):
            continue
        table.add_row(
            scan_id,
            str(scan.get("target", "")),
            str(scan.get("status", "")),
            str(readiness["great_finding_issues"]),
            str(readiness["manual_check_findings"]),
            str(readiness["proof_blocked_findings"]),
            str(scan.get("started_at", "")),
        )
    console.print(table)
    return 0


async def command_readiness_check(args) -> int:
    console.print(
        "[yellow]This command is deprecated. Use `burpollama findings --latest` instead.[/yellow]"
    )
    return 2


async def command_scope_check(args) -> int:
    from core.scope import audit_scope, is_in_scope, load_scope_file

    entries = []
    load_warnings = []
    if getattr(args, "scope_file", None):
        entries, load_warnings = load_scope_file(args.scope_file)
    if getattr(args, "program_json", None):
        from discovery_workflows import aggregate_scope_documents

        program_path = Path(args.program_json)
        aggregate = aggregate_scope_documents([
            (str(program_path), program_path.read_text(encoding="utf-8"))
        ])
        entries.extend(aggregate.get("allowed_assets", []))
        entries.extend("!" + asset for asset in aggregate.get("disallowed_assets", []))
        load_warnings.append(str(aggregate.get("warning", "")))
        if getattr(args, "write_scope", None):
            output = Path(args.write_scope)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("\n".join(entries) + "\n", encoding="utf-8")
            console.print("[green]✓ Wrote normalized scope {}[/green]".format(escape(str(output))))
    if not entries:
        raise RuntimeError("Pass --scope-file or --program-json.")
    for warning in load_warnings:
        if warning:
            console.print("[yellow]Scope warning: {}[/yellow]".format(escape(warning)))
    target = getattr(args, "target", "") or getattr(args, "url", "") or ""
    if getattr(args, "audit", False):
        audit = audit_scope(entries, target)
        command_scope = getattr(args, "write_scope", None) or getattr(args, "scope_file", None)
        cli_runbook = (
            _scope_preflight_runbook(target, command_scope)
            if target and audit["target_in_scope"] and command_scope
            else []
        )
        safe_passive_command = cli_runbook[0] if cli_runbook else ""
        if getattr(args, "write_manifest", None):
            manifest_path = Path(args.write_manifest)
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scope_source": str(args.scope_file or args.program_json),
                "normalized_scope_file": str(command_scope or ""),
                "target": target,
                "target_in_scope": audit["target_in_scope"],
                "entries": entries,
                "audit": audit,
                "safe_passive_command": safe_passive_command,
                "cli_runbook": cli_runbook,
                "warning": "Preflight is advisory; verify current program policy and authorization before scanning.",
            }
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            console.print("[green]✓ Wrote preflight manifest {}[/green]".format(escape(str(manifest_path))))
        table = Table(title="Scope preflight")
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row("Scope source", str(args.scope_file or args.program_json))
        table.add_row("Included rules", str(audit["included_rules"]))
        table.add_row("Excluded rules", str(audit["excluded_rules"]))
        table.add_row("Wildcard rules", str(audit["wildcard_rules"]))
        table.add_row("Host rules", str(audit["host_rules"]))
        table.add_row("URL-prefix rules", str(audit["url_prefix_rules"]))
        if target:
            table.add_row(
                "Target status",
                "IN SCOPE" if audit["target_in_scope"] else "OUT OF SCOPE",
            )
        console.print(table)
        if audit["warnings"]:
            for warning in audit["warnings"]:
                console.print("[yellow]Scope warning: {}[/yellow]".format(escape(warning)))
        if audit["excluded"]:
            console.print("[bold]Excluded rules:[/bold]")
            for rule in audit["excluded"][:20]:
                console.print("- {}".format(escape(rule["raw"])))
        if safe_passive_command:
            console.print(
                "\nSafe passive command:\n[cyan]{}[/cyan]".format(
                    escape(safe_passive_command)
                )
            )
            console.print("\nCLI runbook:")
            for index, command in enumerate(cli_runbook, start=1):
                console.print("[cyan]{}. {}[/cyan]".format(index, escape(command)))
        return 0 if not target or audit["target_in_scope"] else 2
    if not target:
        raise RuntimeError("Pass a URL to check or use --audit --target <url>.")
    result, _parse_warnings = is_in_scope(target, entries)
    console.print("IN SCOPE" if result else "OUT OF SCOPE")
    return 0


def _scope_preflight_runbook(target: str, scope_file: str) -> list[str]:
    scan_command = (
        "python cli.py scan {} --mode passive --yes --scope-file {} "
        "--max-urls 100 --time-budget 900 --no-ai --no-external-tools "
        "--output scans\\authorized-program"
    ).format(target, scope_file)
    return [
        scan_command,
        "python cli.py findings --latest",
        "python cli.py findings --latest --json",
        "python cli.py history --ready-only --limit 20",
    ]


def _feedback_candidates(scan: dict) -> list[dict]:
    seen = set()
    selected = []
    pools = (
        scan.get("confirmed_findings", []),
        scan.get("candidate_findings", []),
        scan.get("triaged_findings", []),
        scan.get("findings", []),
    )
    for pool in pools:
        for finding in pool or []:
            if not isinstance(finding, dict):
                continue
            status = str(finding.get("exploitability_status") or "").lower()
            if status not in {"confirmed", "needs_manual_validation"}:
                continue
            key = str(finding.get("id") or id(finding))
            if key in seen:
                continue
            seen.add(key)
            selected.append(finding)
    return selected


def _feedback_record(scan_id: str, finding: dict, verdict: str) -> dict:
    artifact = finding.get("evidence_artifact") or {}
    if not isinstance(artifact, dict):
        artifact = {}
    ai = finding.get("ai_triage") or {}
    if not isinstance(ai, dict):
        ai = {}
    return {
        "scan_id": str(scan_id),
        "vuln_class": str(
            finding.get("vulnerability_class")
            or finding.get("vuln_type")
            or finding.get("title")
            or ""
        ),
        "matched_indicator": str(artifact.get("matched_indicator") or ""),
        "indicator_location": str(artifact.get("indicator_location") or ""),
        "ai_exploitability": str(ai.get("exploitability") or ""),
        "ai_fp_risk": str(ai.get("false_positive_risk") or ""),
        "human_verdict": verdict,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _append_feedback(record: dict, path: Path | None = None) -> None:
    path = path or FEEDBACK_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _read_feedback(path: Path | None = None) -> list[dict]:
    path = path or FEEDBACK_PATH
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _feedback_stats(path: Path | None = None) -> dict:
    path = path or FEEDBACK_PATH
    records = _read_feedback(path)
    verdicts = Counter(record.get("human_verdict", "") for record in records)
    classes = Counter(str(record.get("vuln_class", "")) for record in records)
    fp_patterns = Counter(
        str(record.get("matched_indicator", ""))
        for record in records
        if record.get("human_verdict") == "false_positive"
    )
    return {
        "total": len(records),
        "valid": verdicts.get("valid", 0),
        "false_positive": verdicts.get("false_positive", 0),
        "top_vuln_classes": classes.most_common(5),
        "top_fp_patterns": fp_patterns.most_common(5),
    }


async def command_train(args) -> int:
    if args.stats:
        stats = _feedback_stats()
        table = Table(title="Feedback dataset stats", box=box.ROUNDED)
        table.add_column("Metric")
        table.add_column("Value")
        table.add_row("Total labeled", str(stats["total"]))
        table.add_row("Valid", str(stats["valid"]))
        table.add_row("False positives", str(stats["false_positive"]))
        table.add_row(
            "Top vuln classes",
            "\n".join(
                "{} ({})".format(label or "unknown", count)
                for label, count in stats["top_vuln_classes"]
            ) or "none",
        )
        table.add_row(
            "Top FP patterns",
            "\n".join(
                "{} ({})".format(label or "unknown", count)
                for label, count in stats["top_fp_patterns"]
            ) or "none",
        )
        console.print(table)
        return 0

    if not args.scan_id:
        console.print("[red]Pass --scan-id <id> or --stats.[/red]")
        return 2
    scan = scan_store.get(args.scan_id)
    if not scan:
        raise RuntimeError("Local scan not found: {}".format(args.scan_id))
    findings = _feedback_candidates(scan)
    if not findings:
        console.print("[yellow]No confirmed or needs_manual_validation findings to label.[/yellow]")
        return 0

    written = 0
    for index, finding in enumerate(findings, start=1):
        artifact = finding.get("evidence_artifact") or {}
        ai = finding.get("ai_triage") or {}
        note = ""
        if isinstance(ai, dict):
            note = ai.get("triage_note") or ai.get("recommended_action") or ""
        console.print(
            Panel(
                "Finding {}/{}\nClass: {}\nTitle: {}\nSeverity: {}\nStatus: {}\n"
                "Matched indicator: {}\nIndicator location: {}\nAI note: {}".format(
                    index,
                    len(findings),
                    escape(str(
                        finding.get("vulnerability_class")
                        or finding.get("vuln_type")
                        or ""
                    )),
                    escape(str(finding.get("title") or "")),
                    escape(str(finding.get("severity") or "")),
                    escape(str(finding.get("exploitability_status") or "")),
                    escape(str(artifact.get("matched_indicator") or "")) if isinstance(artifact, dict) else "",
                    escape(str(artifact.get("indicator_location") or "")) if isinstance(artifact, dict) else "",
                    escape(str(note)),
                ),
                title="Training label",
                border_style="cyan",
            )
        )
        try:
            answer = console.input("[bold cyan][v]alid / [f]alse positive / [s]kip: [/bold cyan]")
        except EOFError:
            answer = "s"
        choice = answer.strip().lower()[:1]
        if choice == "v":
            verdict = "valid"
        elif choice == "f":
            verdict = "false_positive"
        else:
            console.print("[dim]Skipped.[/dim]")
            continue
        _append_feedback(_feedback_record(args.scan_id, finding, verdict))
        written += 1
        console.print("[green]Recorded {} label.[/green]".format(verdict))
    console.print("[green]Wrote {} feedback record(s) to {}[/green]".format(written, FEEDBACK_PATH))
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
        scope_entries = _combined_scope_entries(args)
        try:
            result = await SkillRunner().run(
                skill,
                SkillRunOptions(
                    target=args.target,
                    mode=args.mode,
                    scope=scope_entries,
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
        table.add_row("Findings", result["findings_path"])
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
    add(".env", True, env.get("path", "not required for passive scans"), blocking=False)
    config_dir = Path.home() / ".burpollama"
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        probe = config_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        config_ok = True
    except OSError:
        config_ok = False
    add("Config directory writable", config_ok, str(config_dir))
    database = scan_store.status()
    add("Local scan database", bool(database.get("writable")), database.get("database", ""))
    scans_dir = ROOT / "scans"
    try:
        scans_dir.mkdir(parents=True, exist_ok=True)
        probe = scans_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        scans_ok = True
    except OSError:
        scans_ok = False
    add("Scans directory writable", scans_ok, str(scans_dir))
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
    from core.integrations.tool_checker import tool_detail

    tools = tool_status()
    available = [tool["name"] for tool in tools if tool["available"]]
    add(
        "Optional external tools",
        True,
        "{} available: {}".format(len(available), ", ".join(available) or "none"),
    )
    for tool_name in ("katana", "nuclei", "trufflehog", "gitleaks"):
        ok, detail = tool_detail(tool_name)
        add(tool_name, ok, detail, blocking=False)
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
    launcher_ok = bool(launcher and Path(launcher).exists())
    add("CLI launcher", launcher_ok, launcher or "not found in PATH", blocking=False)
    add(
        "Dashboard (optional)",
        True,
        "available with `burpollama serve`; not required for scans",
    )
    add(
        "Safe defaults",
        True,
        "passive mode by default; program.yml required for preflight; final findings only",
    )
    add(
        "Report generation dependency",
        True,
        "none; old reports directory is not required",
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
    if args.command == "ai-autopilot":
        return await command_ai_autopilot(args)
    if args.command == "burp":
        return await command_burp(args)
    if args.command == "preflight":
        return await command_preflight(args)
    if args.command == "benchmark":
        return await command_benchmark(args)
    if args.command == "watch":
        return await command_watch(args)
    if args.command == "recon":
        return await command_recon(args)
    if args.command == "report":
        return await command_report(args)
    if args.command == "findings":
        return await command_findings(args)
    if args.command == "scope-check":
        return await command_scope_check(args)
    if args.command == "status":
        return await command_status(args)
    if args.command == "history":
        return await command_history(args)
    if args.command == "readiness-check":
        return await command_readiness_check(args)
    if args.command == "train":
        return await command_train(args)
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
    except (RuntimeError, PermissionError, httpx.HTTPError, OSError, json.JSONDecodeError) as exc:
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in {
            22, 32,
        }:
            # Downstream JSON/quiet consumers may intentionally close stdout.
            return 0
        console.print("[red]Error: {}[/red]".format(escape(str(exc))))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
