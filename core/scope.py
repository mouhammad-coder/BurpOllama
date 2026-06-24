"""Per-scan scope locking independent of the optional dashboard."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


def _host(value: str) -> str:
    parsed = urlparse(value if "://" in value else "https://" + value)
    return (parsed.hostname or "").lower().strip(".")


def _normalize_url_prefix(value: str) -> str:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().strip(".")
    if not scheme or not host:
        return ""
    port = ":{}".format(parsed.port) if parsed.port else ""
    path = parsed.path or "/"
    return "{}://{}{}{}".format(scheme, host, port, path.rstrip("/") or "/")


@dataclass
class ScopeRule:
    raw: str
    kind: str
    value: str
    excluded: bool = False

    def matches(self, url: str) -> bool:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = (parsed.hostname or "").lower().strip(".")
        if not host:
            return False
        if self.kind == "wildcard":
            return host.endswith("." + self.value) and host != self.value
        if self.kind == "host":
            return host == self.value
        if self.kind == "url_prefix":
            normalized = _normalize_url_prefix(url)
            return normalized == self.value or normalized.startswith(
                self.value.rstrip("/") + "/"
            )
        return False


def parse_scope_entries(entries: list[str]) -> tuple[list[ScopeRule], list[str]]:
    rules: list[ScopeRule] = []
    warnings: list[str] = []
    for index, raw in enumerate(entries or [], start=1):
        text = str(raw or "").strip()
        if not text or text.startswith("#"):
            continue
        excluded = text.startswith("!")
        value = text[1:].strip() if excluded else text
        if not value or value.startswith("!"):
            warnings.append("line {} skipped: malformed scope entry".format(index))
            continue
        if "://" in value:
            prefix = _normalize_url_prefix(value)
            if not prefix:
                warnings.append("line {} skipped: malformed URL prefix".format(index))
                continue
            rules.append(ScopeRule(raw=text, kind="url_prefix", value=prefix, excluded=excluded))
            continue
        if value.startswith("*."):
            host = _host(value[2:])
            if not host:
                warnings.append("line {} skipped: malformed wildcard".format(index))
                continue
            rules.append(ScopeRule(raw=text, kind="wildcard", value=host, excluded=excluded))
            continue
        host = _host(value)
        if not host or "/" in value or "*" in value or any(ch.isspace() for ch in value):
            warnings.append("line {} skipped: malformed host".format(index))
            continue
        rules.append(ScopeRule(raw=text, kind="host", value=host, excluded=excluded))
    return rules, warnings


def load_scope_file(path: str | Path) -> tuple[list[str], list[str]]:
    scope_path = Path(path).expanduser()
    entries: list[str] = []
    warnings: list[str] = []
    for line_number, line in enumerate(
        scope_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        entries.append(text)
    _rules, parse_warnings = parse_scope_entries(entries)
    for warning in parse_warnings:
        warnings.append("{}: {}".format(scope_path, warning))
    return entries, warnings


def is_in_scope(url: str, entries: list[str]) -> tuple[bool, list[str]]:
    rules, warnings = parse_scope_entries(entries)
    if any(rule.excluded and rule.matches(url) for rule in rules):
        return False, warnings
    return any(not rule.excluded and rule.matches(url) for rule in rules), warnings


@dataclass
class ScanScope:
    target: str
    allowed_domains: list[str] = field(default_factory=list)
    include_subdomains: bool = field(init=False, default=False)
    warnings: list[str] = field(init=False, default_factory=list)
    rules: list[ScopeRule] = field(init=False, default_factory=list)

    def __post_init__(self):
        target_host = _host(self.target)
        entries = list(self.allowed_domains or [])
        if not entries and target_host:
            entries = [target_host]
        self.rules, self.warnings = parse_scope_entries(entries)
        self.allowed_domains = list(dict.fromkeys(
            rule.raw for rule in self.rules if not rule.excluded
        ))
        self.include_subdomains = any(
            rule.kind == "wildcard" and not rule.excluded for rule in self.rules
        )
        if target_host and not self.is_in_scope(self.target):
            raise PermissionError("Target is outside the configured scan scope.")

    def is_in_scope(self, url: str) -> bool:
        if any(rule.excluded and rule.matches(url) for rule in self.rules):
            return False
        return any(not rule.excluded and rule.matches(url) for rule in self.rules)

    def allows(self, url: str) -> bool:
        return self.is_in_scope(url)

    def filter(self, urls: list[str]) -> tuple[list[str], list[str]]:
        allowed, skipped = [], []
        for url in urls or []:
            (allowed if self.is_in_scope(url) else skipped).append(url)
        return allowed, skipped

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "allowed_domains": list(self.allowed_domains),
            "include_subdomains": self.include_subdomains,
            "warnings": list(self.warnings),
            "rules": [
                {
                    "raw": rule.raw,
                    "kind": rule.kind,
                    "value": rule.value,
                    "excluded": rule.excluded,
                }
                for rule in self.rules
            ],
        }
