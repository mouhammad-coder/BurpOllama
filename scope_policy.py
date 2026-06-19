"""
scope_policy.py - central authorization, scan mode, and privacy controls.

This is intentionally dependency-light so every subsystem can import it without
creating framework coupling. Empty allow-lists mean "not configured"; once an
allow-list is configured, targets must match it. Block lists always win.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse


DB_DIR = os.path.expanduser("~/.burpollama")
POLICY_PATH = os.path.join(DB_DIR, "scope_policy.json")

SCAN_MODE_LABELS = {
    "Safe Passive Scan": "passive_only",
    "Bounty Scan": "conservative",
    "Deep Authorized Scan": "normal",
}
SCAN_MODES = {
    "passive_only",
    "conservative",
    "normal",
    "intensive_authorized",
    *SCAN_MODE_LABELS.keys(),
}


@dataclass
class ScopePolicyConfig:
    allowed_domains: list[str] = field(default_factory=list)
    blocked_domains: list[str] = field(default_factory=list)
    allowed_url_patterns: list[str] = field(default_factory=list)
    blocked_url_patterns: list[str] = field(default_factory=list)
    max_depth: int = 2
    max_requests_per_minute: int = 120
    max_total_requests: int = 5000
    passive_only_mode: bool = False
    active_testing_enabled: bool = True
    authenticated_testing_enabled: bool = False
    oob_testing_enabled: bool = False
    cloud_ai_enabled: bool = False
    allowed_vulnerability_classes: list[str] = field(default_factory=list)
    forbidden_vulnerability_classes: list[str] = field(default_factory=list)
    emergency_stop: bool = False
    scan_mode: str = "conservative"


class ScopePolicy:
    def __init__(self):
        self._cfg = ScopePolicyConfig()
        self._lock = threading.Lock()
        self._request_times: list[float] = []
        self._total_requests = 0
        self.load()

    @property
    def config(self) -> ScopePolicyConfig:
        return self._cfg

    def load(self):
        if not os.path.exists(POLICY_PATH):
            return
        try:
            with open(POLICY_PATH, "r", encoding="utf-8") as fh:
                self.update(json.load(fh), persist=False)
        except Exception:
            pass

    def save(self):
        os.makedirs(DB_DIR, exist_ok=True)
        with open(POLICY_PATH, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    def to_dict(self) -> dict:
        return asdict(self._cfg) | {
            "requests_used": self._total_requests,
            "scan_modes": sorted(SCAN_MODES),
        }

    def update(self, values: dict[str, Any], persist: bool = True) -> dict:
        data = asdict(self._cfg)
        for key, value in values.items():
            if key not in data:
                continue
            if isinstance(data[key], list):
                data[key] = [str(v).strip() for v in (value or []) if str(v).strip()]
            elif isinstance(data[key], bool):
                data[key] = bool(value)
            elif isinstance(data[key], int):
                data[key] = max(0, int(value))
            else:
                data[key] = str(value)
        data["scan_mode"] = self.normalize_scan_mode_label(data.get("scan_mode", ""))
        if data.get("scan_mode") not in SCAN_MODES:
            data["scan_mode"] = "conservative"
        if data["scan_mode"] == "passive_only":
            data["passive_only_mode"] = True
            data["active_testing_enabled"] = False
        with self._lock:
            self._cfg = ScopePolicyConfig(**data)
        if persist:
            self.save()
        return self.to_dict()

    def normalize_mode(self, mode: str) -> str:
        aliases = {
            "standard": "normal",
            "slow": "conservative",
        }
        normalized = self.normalize_scan_mode_label(mode)
        return aliases.get((mode or "").lower(), normalized if normalized in SCAN_MODES else self._cfg.scan_mode)

    def normalize_scan_mode_label(self, label: str) -> str:
        value = str(label or "").strip()
        if value in SCAN_MODE_LABELS:
            return SCAN_MODE_LABELS[value]
        lowered = value.lower()
        for display, internal in SCAN_MODE_LABELS.items():
            if lowered == display.lower():
                return internal
        return value

    @classmethod
    def get_display_label(cls, internal: str) -> str:
        value = str(internal or "").strip()
        reverse = {v: k for k, v in SCAN_MODE_LABELS.items()}
        return reverse.get(value, value)

    def _host(self, url_or_domain: str) -> str:
        value = (url_or_domain or "").strip()
        parsed = urlparse(value if "://" in value else "https://" + value)
        return (parsed.hostname or value).lower().strip(".")

    def _domain_match(self, host: str, pattern: str) -> bool:
        p = (pattern or "").lower().strip()
        if not p:
            return False
        if p.startswith("*."):
            suffix = p[1:]
            return host.endswith(suffix) or host == p[2:]
        return host == p or host.endswith("." + p) or fnmatch.fnmatch(host, p)

    def _pattern_match(self, url: str, pattern: str) -> bool:
        p = pattern or ""
        try:
            return bool(re.search(p, url))
        except re.error:
            return fnmatch.fnmatch(url, p)

    def validate_target(self, target: str, action: str = "scan") -> tuple[bool, str]:
        if self._cfg.emergency_stop:
            return False, "Emergency stop is enabled."
        host = self._host(target)
        if any(self._domain_match(host, p) for p in self._cfg.blocked_domains):
            return False, "Target host is blocked by ScopePolicy."
        if self._cfg.allowed_domains and not any(self._domain_match(host, p) for p in self._cfg.allowed_domains):
            return False, "Target host is outside allowed_domains."
        url = target if "://" in target else "https://" + target
        if any(self._pattern_match(url, p) for p in self._cfg.blocked_url_patterns):
            return False, "Target URL is blocked by ScopePolicy."
        if self._cfg.allowed_url_patterns and not any(self._pattern_match(url, p) for p in self._cfg.allowed_url_patterns):
            return False, "Target URL is outside allowed_url_patterns."
        if action in ("active", "oob", "authenticated") and self._cfg.passive_only_mode:
            return False, "Passive-only mode is enabled."
        if action == "active" and not self._cfg.active_testing_enabled:
            return False, "Active testing is disabled."
        if action == "oob" and not self._cfg.oob_testing_enabled:
            return False, "OOB testing is disabled."
        if action == "authenticated" and not self._cfg.authenticated_testing_enabled:
            return False, "Authenticated testing is disabled."
        return True, "Allowed by ScopePolicy."

    def filter_urls(self, urls: list[str], action: str = "active") -> list[str]:
        out = []
        for url in urls or []:
            ok, _ = self.validate_target(url, action=action)
            if ok:
                out.append(url)
        return out

    def vulnerability_allowed(self, vuln_class: str) -> tuple[bool, str]:
        name = (vuln_class or "").lower()
        forbidden = [v.lower() for v in self._cfg.forbidden_vulnerability_classes]
        allowed = [v.lower() for v in self._cfg.allowed_vulnerability_classes]
        if any(v and v in name for v in forbidden):
            return False, "Vulnerability class forbidden by ScopePolicy."
        if allowed and not any(v and v in name for v in allowed):
            return False, "Vulnerability class not in allowed_vulnerability_classes."
        return True, "Allowed vulnerability class."

    def record_request(self, url: str, action: str = "active") -> tuple[bool, str]:
        ok, reason = self.validate_target(url, action=action)
        if not ok:
            return False, reason
        now = time.time()
        with self._lock:
            self._request_times = [t for t in self._request_times if now - t < 60]
            if self._cfg.max_requests_per_minute and len(self._request_times) >= self._cfg.max_requests_per_minute:
                return False, "max_requests_per_minute exceeded."
            if self._cfg.max_total_requests and self._total_requests >= self._cfg.max_total_requests:
                return False, "max_total_requests exceeded."
            self._request_times.append(now)
            self._total_requests += 1
        return True, "Request allowed."


scope_policy = ScopePolicy()
