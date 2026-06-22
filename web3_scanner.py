"""Dependency-free static Solidity audit for candidate generation."""

from __future__ import annotations

import re
from pathlib import Path


RULES = (
    ("TX_ORIGIN_AUTH", "HIGH", r"\btx\.origin\b", "Avoid tx.origin authorization; use explicit role checks."),
    ("UNRESTRICTED_SELFDESTRUCT", "CRITICAL", r"\bselfdestruct\s*\(", "Restrict or remove contract destruction."),
    ("DELEGATECALL", "HIGH", r"\.delegatecall\s*\(", "Validate the delegate target and storage assumptions."),
    ("LOW_LEVEL_CALL", "MEDIUM", r"\.call\s*[\{\(]", "Check success and apply checks-effects-interactions."),
    ("UNCHECKED_SEND", "MEDIUM", r"\.(?:send|transfer)\s*\(", "Review payment failure and gas assumptions."),
    ("WEAK_RANDOMNESS", "HIGH", r"\b(?:block\.(?:timestamp|prevrandao|number)|blockhash)\b", "Do not use miner-controlled values as secure randomness."),
    ("ARBITRARY_ERC20_TRANSFER", "HIGH", r"\btransferFrom\s*\(", "Verify spender authorization and asset/account binding."),
    ("INLINE_ASSEMBLY", "MEDIUM", r"\bassembly\s*\{", "Review memory safety and access-control assumptions."),
    ("UNBOUNDED_LOOP", "MEDIUM", r"\bfor\s*\([^;]*;[^;]*\.length", "Bound loops to prevent gas-based denial of service."),
)


def scan_solidity_source(source: str, filename: str = "<memory>") -> list[dict]:
    findings = []
    lines = source.splitlines()
    for rule_id, severity, pattern, remediation in RULES:
        regex = re.compile(pattern)
        for number, line in enumerate(lines, 1):
            if regex.search(line):
                findings.append({
                    "rule_id": rule_id,
                    "severity": severity,
                    "file": filename,
                    "line": number,
                    "evidence": line.strip()[:300],
                    "remediation": remediation,
                    "exploitability_status": "candidate",
                    "requires_manual_validation": True,
                })
    return findings


def audit_solidity_path(path: str | Path) -> dict:
    root = Path(path).resolve()
    files = [root] if root.is_file() else sorted(root.rglob("*.sol"))
    findings = []
    for file_path in files:
        if file_path.suffix.lower() != ".sol":
            continue
        findings.extend(
            scan_solidity_source(file_path.read_text(encoding="utf-8", errors="replace"), str(file_path))
        )
    return {
        "path": str(root),
        "files_scanned": len(files),
        "findings": findings,
        "summary": {
            severity: sum(1 for item in findings if item["severity"] == severity)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
        "note": "Static candidates require manual validation or a dedicated analyzer such as Slither.",
    }

