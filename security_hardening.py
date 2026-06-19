"""
security_hardening.py - prompt/report safety and evidence handling helpers.
"""

from __future__ import annotations

import html
import re


SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA****************"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "gh*_****************"),
    (re.compile(r"(?i)(api[_-]?key|token|secret|password)(\s*[=:]\s*)['\"]?([^'\"\s]{8,})"),
     r"\1\2[REDACTED]"),
    (re.compile(r"-----BEGIN ([A-Z ]+)?PRIVATE KEY-----.*?-----END ([A-Z ]+)?PRIVATE KEY-----",
                re.DOTALL), "[REDACTED PRIVATE KEY]"),
]


def redact_secrets(value: str) -> str:
    out = value or ""
    for pattern, repl in SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def escape_markdown_table(value: str) -> str:
    value = redact_secrets(str(value or ""))
    return value.replace("|", "\\|").replace("\n", "<br>")


def safe_code_block(value: str) -> str:
    value = redact_secrets(str(value or ""))
    return value.replace("```", "` ` `")


def sanitize_prompt_input(value: str, limit: int = 4000) -> str:
    value = redact_secrets(str(value or ""))[:limit]
    # Delimit untrusted target content so prompt injection is treated as evidence.
    value = value.replace("</UNTRUSTED_TARGET_CONTENT>", "</UNTRUSTED_TARGET_CONTENT_ESCAPED>")
    return value


def html_escape(value: str) -> str:
    return html.escape(redact_secrets(str(value or "")), quote=True)
