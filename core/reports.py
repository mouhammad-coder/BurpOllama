"""Deprecated compatibility shim for older findings-export imports."""

from __future__ import annotations

from pathlib import Path


DEPRECATION_MESSAGE = "This command is deprecated. Use `burpollama findings --latest` instead."


def render_report(scan: dict, report_format: str) -> str:
    raise RuntimeError(DEPRECATION_MESSAGE)


def write_report_bundle(
    scan: dict,
    output_root: str | Path,
    *,
    formats: tuple[str, ...] = (),
) -> dict[str, str]:
    raise RuntimeError(DEPRECATION_MESSAGE)
