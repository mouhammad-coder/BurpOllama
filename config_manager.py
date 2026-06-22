"""Project-local .env configuration used by the web settings page."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
ENV_PATH = PROJECT_ROOT / ".env"

SETTING_DEFAULTS: dict[str, str] = {
    "GEMINI_API_KEY": "",
    "OPENAI_API_KEY": "",
    "ANTHROPIC_API_KEY": "",
    "GROQ_API_KEY": "",
    "MISTRAL_API_KEY": "",
    "DEEPSEEK_API_KEY": "",
    "TOGETHER_API_KEY": "",
    "CUSTOM_AI_API_KEY": "",
    "GROQ_MODEL": "llama-3.1-8b-instant",
    "MISTRAL_MODEL": "mistral-small-latest",
    "DEEPSEEK_MODEL": "deepseek-chat",
    "TOGETHER_MODEL": "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
    "CUSTOM_AI_MODEL": "custom-model",
    "CUSTOM_AI_BASE_URL": "http://127.0.0.1:1234/v1/chat/completions",
    "CLOUD_AI_ENABLED": "0",
    "OLLAMA_ENABLED": "0",
    "OLLAMA_MODEL": "mistral",
    "OLLAMA_FAST_MODEL": "mistral",
    "OLLAMA_REASONING_MODEL": "llama3.1:8b",
    "AI_AUTO_REASONING": "1",
    "AI_REASONING_THRESHOLD": "5",
    "OLLAMA_NUM_THREADS": "8",
    "OLLAMA_MAX_LOADED_MODELS": "1",
    "OLLAMA_FAST_NUM_CTX": "4096",
    "OLLAMA_REASONING_NUM_CTX": "6144",
    "OLLAMA_REASONING_TIMEOUT": "180",
    "OLLAMA_REASONING_TEMPERATURE": "0.03",
    "OLLAMA_KEEP_ALIVE": "10m",
    "BURPOLLAMA_DATABASE_URL": "",
    "BURPOLLAMA_RETENTION_DAYS": "90",
    "BURPOLLAMA_OOB_SIGNING_KEY": "",
    "BURPOLLAMA_OOB_PROVIDER": "oast.fun",
}

SECRET_KEYS = {
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    "TOGETHER_API_KEY",
    "CUSTOM_AI_API_KEY",
    "BURPOLLAMA_DATABASE_URL",
    "BURPOLLAMA_OOB_SIGNING_KEY",
}
BOOLEAN_KEYS = {"CLOUD_AI_ENABLED", "OLLAMA_ENABLED", "AI_AUTO_REASONING"}
INTEGER_RANGES = {
    "AI_REASONING_THRESHOLD": (1, 100),
    "OLLAMA_NUM_THREADS": (1, 64),
    "OLLAMA_MAX_LOADED_MODELS": (1, 8),
    "OLLAMA_FAST_NUM_CTX": (1024, 131072),
    "OLLAMA_REASONING_NUM_CTX": (1024, 131072),
    "OLLAMA_REASONING_TIMEOUT": (30, 3600),
    "BURPOLLAMA_RETENTION_DAYS": (1, 3650),
}
MODEL_RE = re.compile(r"^[A-Za-z0-9._:/-]+$")
KEEP_ALIVE_RE = re.compile(r"^(?:0|-1|\d+(?:ms|s|m|h))$")
API_KEY_PATTERNS = {
    "GEMINI_API_KEY": re.compile(r"^AIza[A-Za-z0-9_-]{20,}$"),
    "OPENAI_API_KEY": re.compile(r"^sk-[A-Za-z0-9_-]{20,}$"),
    "ANTHROPIC_API_KEY": re.compile(r"^sk-ant-[A-Za-z0-9_-]{20,}$"),
    "GROQ_API_KEY": re.compile(r"^[A-Za-z0-9_-]{20,}$"),
    "MISTRAL_API_KEY": re.compile(r"^[A-Za-z0-9_-]{20,}$"),
    "DEEPSEEK_API_KEY": re.compile(r"^[A-Za-z0-9_-]{20,}$"),
    "TOGETHER_API_KEY": re.compile(r"^[A-Za-z0-9_-]{20,}$"),
    "CUSTOM_AI_API_KEY": re.compile(r"^.{8,}$"),
}


def _parse_env_file() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_PATH.exists():
        return values
    for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            quote = value[0]
            value = value[1:-1]
            if quote == '"':
                value = re.sub(r'\\(["\\$`])', r"\1", value)
        values[key] = value
    return values


def _serialize_env_value(value: str) -> str:
    """Quote values so sourcing .env in Bash cannot execute their contents."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
    )
    return f'"{escaped}"'


def load_project_env() -> dict[str, str]:
    """Create .env when missing and load supported values into this process."""
    if not ENV_PATH.exists():
        save_settings({})
    values = {**SETTING_DEFAULTS, **_parse_env_file()}
    for key, value in values.items():
        os.environ.setdefault(key, value)
    return values


def _mask(value: str) -> str:
    if not value:
        return ""
    return value[:4] + "****"


def public_settings() -> dict[str, Any]:
    values = {**SETTING_DEFAULTS, **_parse_env_file()}
    return {
        "env_exists": ENV_PATH.exists(),
        "settings": {
            key: (_mask(value) if key in SECRET_KEYS else value)
            for key, value in values.items()
            if key in SETTING_DEFAULTS
        },
        "configured": {
            key: bool(values.get(key, ""))
            for key in SECRET_KEYS
        },
    }


def _clean_value(key: str, value: Any) -> str:
    text = str(value if value is not None else "").strip()
    if "\n" in text or "\r" in text:
        raise ValueError(f"{key} must be a single-line value.")
    if key in BOOLEAN_KEYS:
        lowered = text.lower()
        if lowered in {"1", "true", "yes", "on"}:
            return "1"
        if lowered in {"0", "false", "no", "off"}:
            return "0"
        raise ValueError(f"{key} must be enabled or disabled.")
    if key in API_KEY_PATTERNS and text and not API_KEY_PATTERNS[key].fullmatch(text):
        raise ValueError(f"{key} does not look like a valid provider API key.")
    if key in INTEGER_RANGES:
        try:
            number = int(text)
        except ValueError as exc:
            raise ValueError(f"{key} must be a whole number.") from exc
        low, high = INTEGER_RANGES[key]
        if not low <= number <= high:
            raise ValueError(f"{key} must be between {low} and {high}.")
        return str(number)
    if key == "OLLAMA_REASONING_TEMPERATURE":
        try:
            number = float(text)
        except ValueError as exc:
            raise ValueError(f"{key} must be a number.") from exc
        if not 0 <= number <= 2:
            raise ValueError(f"{key} must be between 0 and 2.")
        return str(number)
    if key in {
        "OLLAMA_MODEL", "OLLAMA_FAST_MODEL", "OLLAMA_REASONING_MODEL",
        "GROQ_MODEL", "MISTRAL_MODEL", "DEEPSEEK_MODEL", "TOGETHER_MODEL",
        "CUSTOM_AI_MODEL",
    }:
        if not text or not MODEL_RE.fullmatch(text):
            raise ValueError(f"{key} contains an invalid model name.")
    if key == "OLLAMA_KEEP_ALIVE" and not KEEP_ALIVE_RE.fullmatch(text):
        raise ValueError("OLLAMA_KEEP_ALIVE must look like 10m, 30s, 1h, 0, or -1.")
    if key == "CUSTOM_AI_BASE_URL" and text and not re.match(r"^https?://", text):
        raise ValueError("CUSTOM_AI_BASE_URL must be an HTTP(S) URL.")
    return text


def save_settings(updates: dict[str, Any]) -> dict[str, Any]:
    existing = {**SETTING_DEFAULTS, **_parse_env_file()}
    errors: list[str] = []
    for key, incoming in (updates or {}).items():
        if key not in SETTING_DEFAULTS:
            continue
        text = str(incoming if incoming is not None else "")
        if key in SECRET_KEYS and (
            text == _mask(existing.get(key, ""))
            or "•" in text
            or text.startswith("********")
        ):
            continue
        try:
            existing[key] = _clean_value(key, incoming)
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        raise ValueError(" ".join(errors))

    ENV_PATH.write_text(
        "\n".join(
            f"{key}={_serialize_env_value(existing.get(key, ''))}"
            for key in SETTING_DEFAULTS
        )
        + "\n",
        encoding="utf-8",
    )
    for key in SETTING_DEFAULTS:
        os.environ[key] = existing.get(key, "")
    return public_settings()
