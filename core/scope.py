"""Per-scan scope locking independent of the optional dashboard."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


def _host(value: str) -> str:
    parsed = urlparse(value if "://" in value else "https://" + value)
    return (parsed.hostname or "").lower().strip(".")


@dataclass
class ScanScope:
    target: str
    allowed_domains: list[str] = field(default_factory=list)
    include_subdomains: bool = field(init=False, default=False)

    def __post_init__(self):
        target_host = _host(self.target)
        requested = [_host(value) for value in self.allowed_domains if _host(value)]
        self.include_subdomains = bool(requested)
        self.allowed_domains = list(dict.fromkeys(requested or [target_host]))
        if target_host and not self.allows(self.target):
            raise PermissionError("Target is outside the configured scan scope.")

    def allows(self, url: str) -> bool:
        host = _host(url)
        if not host:
            return False
        if not self.include_subdomains:
            return host in self.allowed_domains
        return any(
            host == domain or host.endswith("." + domain)
            for domain in self.allowed_domains
        )

    def filter(self, urls: list[str]) -> tuple[list[str], list[str]]:
        allowed, skipped = [], []
        for url in urls or []:
            (allowed if self.allows(url) else skipped).append(url)
        return allowed, skipped

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "allowed_domains": list(self.allowed_domains),
            "include_subdomains": self.include_subdomains,
        }
