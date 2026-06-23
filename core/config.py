"""Local runtime configuration helpers."""

from __future__ import annotations

from config_manager import ENV_PATH, load_project_env, public_settings


def load_config() -> dict:
    return load_project_env()


def config_status() -> dict:
    data = public_settings()
    data["path"] = str(ENV_PATH)
    return data
