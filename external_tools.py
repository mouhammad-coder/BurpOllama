"""Safe adapters for optional bug-bounty command-line tools."""

from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: str
    description: str
    active: bool = False
    intensive: bool = False


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    skipped: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


TOOL_REGISTRY = {
    spec.name: spec for spec in (
        ToolSpec("subfinder", "recon", "Passive subdomain enumeration."),
        ToolSpec("httpx", "recon", "HTTP reachability and metadata probing."),
        ToolSpec("katana", "recon", "Application crawler."),
        ToolSpec("gau", "recon", "Historical URL collection."),
        ToolSpec("waybackurls", "recon", "Wayback URL collection."),
        ToolSpec("dnsx", "recon", "DNS resolution and record inspection."),
        ToolSpec("nuclei", "validation", "Template-based exposure checks.", True),
        ToolSpec("ffuf", "discovery", "Content and parameter discovery.", True, True),
        ToolSpec("arjun", "discovery", "HTTP parameter discovery.", True, True),
        ToolSpec("paramspider", "discovery", "Passive parameter collection."),
        ToolSpec("gitleaks", "secrets", "Repository secret scanning."),
        ToolSpec("trufflehog", "secrets", "Verified secret discovery.", True),
        ToolSpec("semgrep", "code", "Static source analysis."),
        ToolSpec("subjack", "takeover", "Subdomain takeover candidate checks.", True),
        ToolSpec("dnsreaper", "takeover", "DNS takeover candidate checks.", True),
        ToolSpec("cloud_enum", "cloud", "Public cloud asset discovery.", True),
        ToolSpec("wafw00f", "waf", "WAF fingerprinting."),
        ToolSpec("dalfox", "validation", "XSS parameter analysis.", True, True),
        ToolSpec("slither", "web3", "Solidity static analysis."),
        ToolSpec("myth", "web3", "EVM symbolic analysis.", True, True),
        ToolSpec("forge", "web3", "Foundry build and test runner."),
    )
}


def tool_status() -> list[dict]:
    return [
        {
            **asdict(spec),
            "available": bool(shutil.which(spec.name)),
            "path": shutil.which(spec.name) or "",
        }
        for spec in TOOL_REGISTRY.values()
    ]


def _bounded_text(data: bytes, limit: int) -> str:
    return data[:limit].decode("utf-8", errors="replace")


async def run_tool(
    name: str,
    arguments: Iterable[str],
    *,
    timeout: float = 120.0,
    authorized: bool = False,
    intensive_authorized: bool = False,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    output_limit: int = 2_000_000,
) -> ToolResult:
    """Execute a registered tool without a shell and with bounded resources."""
    spec = TOOL_REGISTRY.get(str(name or "").lower())
    args = [str(value) for value in arguments]
    if not spec:
        return ToolResult(name, [], None, skipped=True, reason="Unknown tool.")
    executable = shutil.which(spec.name)
    command = [executable or spec.name, *args]
    if not executable:
        return ToolResult(spec.name, command, None, skipped=True, reason="Tool is not installed.")
    if spec.active and not authorized:
        return ToolResult(
            spec.name, command, None, skipped=True,
            reason="Active tool requires explicit target authorization.",
        )
    if spec.intensive and not intensive_authorized:
        return ToolResult(
            spec.name, command, None, skipped=True,
            reason="Intensive tool requires explicit intensive-testing authorization.",
        )

    clean_env = os.environ.copy()
    if env:
        clean_env.update({str(key): str(value) for key, value in env.items()})
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd) if cwd else None,
        env=clean_env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=max(1.0, timeout))
    except asyncio.TimeoutError:
        process.kill()
        stdout, stderr = await process.communicate()
        return ToolResult(
            spec.name, command, process.returncode,
            _bounded_text(stdout, output_limit), _bounded_text(stderr, output_limit),
            timed_out=True, reason="Tool exceeded its time budget.",
        )
    return ToolResult(
        spec.name, command, process.returncode,
        _bounded_text(stdout, output_limit), _bounded_text(stderr, output_limit),
    )

