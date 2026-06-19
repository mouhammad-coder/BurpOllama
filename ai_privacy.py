"""
ai_privacy.py - privacy guard for local/cloud AI prompts.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from scope_policy import scope_policy


DB_DIR = os.path.expanduser("~/.burpollama")
PRIVACY_PATH = os.path.join(DB_DIR, "ai_privacy.json")
AUDIT_PATH = os.path.join(DB_DIR, "ai_audit.jsonl")


@dataclass
class AIPrivacyConfig:
    local_ollama_preferred: bool = True
    cloud_ai_enabled: bool = False
    allow_raw_http_to_cloud: bool = False
    max_cloud_prompt_chars: int = 6000
    audit_enabled: bool = True
    redaction_labels: list[str] = field(default_factory=lambda: [
        "cookies", "jwts", "api_keys", "session_ids", "auth_headers",
        "passwords", "emails", "phones", "access_tokens", "refresh_tokens",
        "secret_values",
    ])


class AIPrivacyGuard:
    def __init__(self):
        self._cfg = AIPrivacyConfig()
        self.load()

    @property
    def config(self) -> AIPrivacyConfig:
        return self._cfg

    def load(self):
        if not os.path.exists(PRIVACY_PATH):
            return
        try:
            with open(PRIVACY_PATH, "r", encoding="utf-8") as fh:
                self.update(json.load(fh), persist=False)
        except Exception:
            pass

    def save(self):
        os.makedirs(DB_DIR, exist_ok=True)
        with open(PRIVACY_PATH, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    def to_dict(self) -> dict:
        data = asdict(self._cfg)
        data["effective_cloud_ai_enabled"] = bool(self._cfg.cloud_ai_enabled and scope_policy.config.cloud_ai_enabled)
        return data

    def update(self, values: dict[str, Any], persist: bool = True) -> dict:
        data = asdict(self._cfg)
        for key, value in values.items():
            if key not in data:
                continue
            if isinstance(data[key], bool):
                data[key] = bool(value)
            elif isinstance(data[key], int):
                data[key] = max(0, int(value))
            elif isinstance(data[key], list):
                data[key] = [str(v) for v in (value or [])]
        self._cfg = AIPrivacyConfig(**data)
        if persist:
            self.save()
        return self.to_dict()

    def is_cloud_allowed(self) -> bool:
        return bool(self._cfg.cloud_ai_enabled and scope_policy.config.cloud_ai_enabled)

    def redact(self, text: str, cloud: bool = False) -> str:
        value = str(text or "")
        value = re.sub(r"(?im)^(authorization|proxy-authorization|cookie|set-cookie):\s*.+$", r"\1: [REDACTED]", value)
        value = re.sub(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}", "[REDACTED_JWT]", value)
        value = re.sub(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id|secret|password|passwd|pwd)(\s*[=:]\s*)['\"]?[^'\"\s&]{4,}", r"\1\2[REDACTED]", value)
        value = re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]", value)
        value = re.sub(r"gh[pousr]_[A-Za-z0-9_]{20,}", "[REDACTED_GITHUB_TOKEN]", value)
        value = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", value)
        value = re.sub(r"(?<!\w)(\+?\d[\d\s().-]{7,}\d)(?!\w)", "[REDACTED_PHONE]", value)
        value = re.sub(r"(?i)(session|sid|csrf|xsrf|auth)[A-Za-z0-9_.:-]{12,}", "[REDACTED_SESSION]", value)
        value = re.sub(r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{40,}(?![A-Za-z0-9])", "[REDACTED_SECRET]", value)
        if cloud and not self._cfg.allow_raw_http_to_cloud:
            value = self._strip_large_body_sections(value)
            value = value[: self._cfg.max_cloud_prompt_chars]
        return value

    def _strip_large_body_sections(self, text: str) -> str:
        labels = [
            "REQUEST BODY:", "RESPONSE BODY:", "raw_request_body",
            "raw_response_body", "=== RESPONSE", "=== REQUEST",
        ]
        out = text
        for label in labels:
            idx = out.lower().find(label.lower())
            if idx >= 0:
                keep = out[idx:idx + len(label) + 600]
                out = out[:idx] + keep + "\n[TRUNCATED_BY_AI_PRIVACY_GUARD]\n"
        return out

    def audit(self, provider: str, model: str, prompt_chars: int, cloud: bool, allowed: bool, reason: str):
        if not self._cfg.audit_enabled:
            return
        try:
            os.makedirs(DB_DIR, exist_ok=True)
            with open(AUDIT_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "timestamp": datetime.utcnow().isoformat(),
                    "provider": provider,
                    "model": model,
                    "prompt_chars": prompt_chars,
                    "cloud": cloud,
                    "allowed": allowed,
                    "reason": reason,
                }) + "\n")
        except Exception:
            pass

    def audit_log(self, limit: int = 200) -> list[dict]:
        if not os.path.exists(AUDIT_PATH):
            return []
        try:
            with open(AUDIT_PATH, "r", encoding="utf-8") as fh:
                lines = fh.readlines()[-limit:]
            return [json.loads(line) for line in lines if line.strip()]
        except Exception:
            return []


ai_privacy_guard = AIPrivacyGuard()
