"""Local runtime configuration helpers."""

from __future__ import annotations

import os

import httpx

from config_manager import ENV_PATH, load_project_env, public_settings


def load_config() -> dict:
    return load_project_env()


def config_status() -> dict:
    data = public_settings()
    data["path"] = str(ENV_PATH)
    return data


def ollama_config() -> dict:
    load_project_env()
    return {
        "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/"),
        "model": os.getenv("OLLAMA_MODEL", "mistral:7b-instruct"),
        "timeout": float(os.getenv("OLLAMA_TIMEOUT", "30") or 30),
    }


def _model_ram_estimate(model: str) -> str:
    lowered = (model or "").lower()
    if "3b" in lowered or "mini" in lowered:
        return "~2-4 GB RAM"
    if "7b" in lowered or "8b" in lowered or "mistral" in lowered:
        return "~5-8 GB RAM with Q4 quantization"
    if "13b" in lowered:
        return "13B+ unquantized not recommended on 16GB RAM"
    return "depends on quantization"


def ollama_model_recommendation(model: str) -> str:
    lowered = (model or "").lower()
    if "13b" in lowered and not any(q in lowered for q in ("q4", "q5", "q6")):
        return "Not recommended: 13B+ unquantized can exhaust RAM."
    if "mistral" in lowered:
        return "Good choice for triage quality; prefer mistral:7b-instruct-q4_K_M on 16GB no-GPU."
    if "llama3.2:3b" in lowered:
        return "Fastest recommended local triage model."
    if "phi3:mini" in lowered:
        return "Good structured-output local model."
    return "Recommended 16GB no-GPU models: mistral:7b-instruct-q4_K_M, llama3.2:3b, phi3:mini."


async def ollama_health() -> dict:
    cfg = ollama_config()
    tags_url = cfg["base_url"] + "/api/tags"
    try:
        async with httpx.AsyncClient(timeout=min(cfg["timeout"], 5.0)) as client:
            response = await client.get(tags_url)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        return {
            "running": False,
            "base_url": cfg["base_url"],
            "model": cfg["model"],
            "models": [],
            "model_available": False,
            "error": str(exc),
            "setup": "Start Ollama, then run: ollama pull {}".format(cfg["model"]),
            "ram_estimate": _model_ram_estimate(cfg["model"]),
            "recommendation": ollama_model_recommendation(cfg["model"]),
        }
    models = [
        str(model.get("name") or model.get("model") or "")
        for model in payload.get("models", [])
        if model.get("name") or model.get("model")
    ]
    configured = cfg["model"]
    available = configured in models or any(
        name.split(":")[0] == configured.split(":")[0]
        and (":" not in configured or name in {configured, configured + ":latest"})
        for name in models
    )
    return {
        "running": True,
        "base_url": cfg["base_url"],
        "model": configured,
        "models": models,
        "model_available": available,
        "error": "",
        "setup": "" if available else "Model missing. Run: ollama pull {}".format(configured),
        "ram_estimate": _model_ram_estimate(configured),
        "recommendation": ollama_model_recommendation(configured),
    }
