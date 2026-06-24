"""Katana URL collection wrapper."""

from __future__ import annotations

import subprocess
from pathlib import Path

from core.integrations.tool_checker import check_tool


def run_katana(target, scope, output_dir, depth=3):
    warnings = []
    if not check_tool("katana"):
        warnings.append("katana not found - skipping external URL collection")
        return []
    output_path = Path(output_dir) / "urls.txt"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "katana",
        "-u", str(target),
        "-jc",
        "-d", str(depth),
        "-silent",
        "-o", str(output_path),
    ]
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    urls = []
    if output_path.exists():
        urls.extend(line.strip() for line in output_path.read_text(encoding="utf-8", errors="ignore").splitlines())
    if result.stdout:
        urls.extend(line.strip() for line in result.stdout.splitlines())
    allowed = []
    seen = set()
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        if hasattr(scope, "allows") and scope.allows(url):
            allowed.append(url)
    return allowed
