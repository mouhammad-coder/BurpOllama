"""Program profile parsing and scanner permission policy.

The parser intentionally supports a small YAML subset plus JSON so BurpOllama
can read the documented program.yml without adding a runtime dependency.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.scope import is_in_scope, parse_scope_entries


GOALS = (
    "recon",
    "bounty-hunt",
    "access-control",
    "api-hunt",
    "passive-analysis",
    "manual-check",
    "burp-import-analysis",
)
FINAL_OUTPUTS = ("chat", "terminal", "json")
SAFE_ALLOWED_MODES = {"passive", "bounty", "deep"}
FORBIDDEN_ALLOWED_MODES = {"dos", "brute_force", "brute-force", "waf_bypass", "evasion", "stealth"}


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "yes", "y", "1", "allowed"}:
        return True
    if text in {"false", "no", "n", "0", "forbidden"}:
        return False
    return None


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _scalar(value: str) -> Any:
    text = value.strip()
    if not text:
        return ""
    if (
        (text.startswith('"') and text.endswith('"'))
        or (text.startswith("'") and text.endswith("'"))
    ):
        return text[1:-1]
    lowered = text.lower()
    if lowered in {"true", "false", "yes", "no"}:
        return lowered in {"true", "yes"}
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return text


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    current_key = ""
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("-"):
            if not current_key:
                continue
            result.setdefault(current_key, [])
            if not isinstance(result[current_key], list):
                result[current_key] = [result[current_key]]
            value = stripped[1:].strip()
            if value:
                result[current_key].append(_scalar(value))
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        current_key = key
        if value == "":
            result[key] = []
        elif value.startswith("[") and value.endswith("]"):
            try:
                loaded = json.loads(value.replace("'", '"'))
                result[key] = loaded if isinstance(loaded, list) else [loaded]
            except json.JSONDecodeError:
                result[key] = [
                    item.strip()
                    for item in value.strip("[]").split(",")
                    if item.strip()
                ]
        else:
            result[key] = _scalar(value)
    return result


@dataclass
class ProgramProfile:
    path: str = ""
    program: str = ""
    platform: str = ""
    scanner_allowed: bool | None = None
    automated_testing_allowed: bool | None = None
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    forbidden_tests: list[str] = field(default_factory=list)
    allowed_modes: list[str] = field(default_factory=list)
    max_rps: float = 2.0
    max_concurrency: int = 5
    auth_testing_allowed: bool | None = None
    upload_testing_allowed: bool | None = None
    graphql_introspection_allowed: bool | None = None
    oob_testing_allowed: bool | None = None
    cloud_ai_allowed: bool | None = None
    notes: str = ""

    @property
    def name(self) -> str:
        return self.program or Path(self.path).stem or "unknown"

    @property
    def scanner_permission_label(self) -> str:
        if self.scanner_allowed is True and self.automated_testing_allowed is True:
            return "yes"
        if self.scanner_allowed is False or self.automated_testing_allowed is False:
            return "no"
        return "unknown"

    @property
    def scope_entries(self) -> list[str]:
        entries = list(self.in_scope)
        entries.extend("!" + item.lstrip("!") for item in self.out_of_scope)
        return entries

    def target_allowed(self, target: str) -> tuple[bool, str]:
        if not self.scope_entries:
            return False, "program profile has no in_scope entries"
        allowed, warnings = is_in_scope(target, self.scope_entries)
        if not allowed:
            return False, "target is outside program.yml scope"
        if warnings:
            return True, "; ".join(warnings)
        return True, ""

    def choose_mode(self, requested_mode: str, goal: str) -> tuple[str, list[str]]:
        warnings: list[str] = []
        mode = str(requested_mode or "passive").lower()
        if goal in {"recon", "passive-analysis", "manual-check", "burp-import-analysis"}:
            mode = "passive"
        if self.scanner_permission_label == "unknown":
            warnings.append(
                "Automated scanner permission is unknown. Running conservative passive checks only."
            )
            mode = "passive"
        elif self.scanner_permission_label == "no" and mode != "passive":
            warnings.append(
                "Automated scanning is not allowed by program.yml. Active scanning disabled."
            )
            mode = "passive"
        if self.allowed_modes and mode not in {item.lower() for item in self.allowed_modes}:
            warnings.append(
                "Requested mode is not listed in program.yml allowed_modes. Running passive mode."
            )
            mode = "passive"
        return mode, warnings

    def safe_limits(self, requested_rps: float, requested_concurrency: int) -> tuple[float, int]:
        rps = min(float(requested_rps or self.max_rps or 2.0), float(self.max_rps or 2.0))
        concurrency = min(
            int(requested_concurrency or self.max_concurrency or 5),
            int(self.max_concurrency or 5),
        )
        return max(0.1, rps), max(1, concurrency)

    def validation_errors(self) -> list[str]:
        errors: list[str] = []
        if not self.in_scope:
            errors.append("missing in_scope")
        else:
            rules, warnings = parse_scope_entries(self.in_scope)
            if warnings:
                errors.extend("invalid in_scope entry: {}".format(item) for item in warnings)
            if not any(not rule.excluded for rule in rules):
                errors.append("missing valid in_scope entries")
        for label, entries in (("out_of_scope", self.out_of_scope),):
            _rules, warnings = parse_scope_entries(entries)
            errors.extend("invalid {} entry: {}".format(label, item) for item in warnings)
        if self.scanner_allowed is None:
            errors.append("scanner_allowed missing")
        if self.automated_testing_allowed is None:
            errors.append("automated_testing_allowed missing")
        if self.upload_testing_allowed is None:
            errors.append("upload_testing_allowed missing")
        if self.auth_testing_allowed is None:
            errors.append("auth_testing_allowed missing")
        if self.cloud_ai_allowed is None:
            errors.append("cloud_ai_allowed missing")
        if self.max_rps <= 0 or self.max_rps > 50:
            errors.append("invalid max_rps")
        if self.max_concurrency <= 0 or self.max_concurrency > 20:
            errors.append("invalid max_concurrency")
        modes = {str(item).strip().lower() for item in self.allowed_modes if str(item).strip()}
        if modes & FORBIDDEN_ALLOWED_MODES:
            errors.append("conflicting allowed_modes")
        if any(mode not in SAFE_ALLOWED_MODES for mode in modes):
            errors.append("invalid allowed_modes")
        return list(dict.fromkeys(errors))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "program": self.name,
            "platform": self.platform,
            "scanner_allowed": self.scanner_allowed,
            "automated_testing_allowed": self.automated_testing_allowed,
            "automated_scanning_allowed": self.scanner_permission_label,
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
            "forbidden_tests": list(self.forbidden_tests),
            "allowed_modes": list(self.allowed_modes),
            "max_rps": self.max_rps,
            "max_concurrency": self.max_concurrency,
            "auth_testing_allowed": self.auth_testing_allowed,
            "upload_testing_allowed": self.upload_testing_allowed,
            "graphql_introspection_allowed": self.graphql_introspection_allowed,
            "oob_testing_allowed": self.oob_testing_allowed,
            "cloud_ai_allowed": self.cloud_ai_allowed,
            "notes": self.notes,
        }


def load_program_profile(path: str | Path) -> ProgramProfile:
    profile_path = Path(path).expanduser()
    text = profile_path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = _parse_simple_yaml(text)
    if not isinstance(data, dict):
        raise ValueError("program.yml must contain a mapping/object")
    try:
        max_rps = float(data.get("max_rps") or data.get("rate_limit") or 2.0)
    except (TypeError, ValueError):
        max_rps = -1.0
    try:
        max_concurrency = int(data.get("max_concurrency") or data.get("concurrency") or 5)
    except (TypeError, ValueError):
        max_concurrency = -1
    profile = ProgramProfile(
        path=str(profile_path),
        program=str(data.get("program") or data.get("name") or ""),
        platform=str(data.get("platform") or ""),
        scanner_allowed=_bool(data.get("scanner_allowed")),
        automated_testing_allowed=_bool(data.get("automated_testing_allowed")),
        in_scope=_list(data.get("in_scope")),
        out_of_scope=_list(data.get("out_of_scope")),
        forbidden_tests=_list(data.get("forbidden_tests")),
        allowed_modes=_list(data.get("allowed_modes")),
        max_rps=max_rps,
        max_concurrency=max_concurrency,
        auth_testing_allowed=_bool(data.get("auth_testing_allowed")),
        upload_testing_allowed=_bool(data.get("upload_testing_allowed")),
        graphql_introspection_allowed=_bool(data.get("graphql_introspection_allowed")),
        oob_testing_allowed=_bool(data.get("oob_testing_allowed")),
        cloud_ai_allowed=_bool(data.get("cloud_ai_allowed")),
        notes=str(data.get("notes") or ""),
    )
    errors = [item for item in profile.validation_errors() if not item.endswith(" missing")]
    if errors:
        raise ValueError("Invalid program.yml: {}".format("; ".join(errors)))
    return profile


def host_scope_entry(target: str) -> str:
    parsed = urlparse(target if "://" in target else "https://" + target)
    return (parsed.hostname or "").lower().strip(".")
