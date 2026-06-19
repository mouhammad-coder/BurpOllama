"""
ai_provider.py - provider-agnostic AI routing with failover and cost controls.

The public API intentionally mirrors gemini_client.ask_gemini so existing code
can migrate without churn. Providers are selected by cost, availability, and
historical failures; local LLMs are preferred when configured for cheap analysis.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx
from ai_privacy import ai_privacy_guard


@dataclass
class AIProvider:
    name: str
    model: str
    base_url: str
    api_key_env: str = ""
    cost_per_1k_tokens: float = 0.0
    rpm: int = 30
    enabled: bool = True
    kind: str = "openai-compatible"
    failures: int = 0
    last_error: str = ""
    _last_call: float = field(default=0.0, repr=False)

    @property
    def api_key(self) -> str:
        return os.getenv(self.api_key_env, "") if self.api_key_env else ""

    @property
    def available(self) -> bool:
        return self.enabled and (self.kind == "local" or bool(self.api_key))

    async def wait(self):
        min_gap = 60.0 / max(self.rpm, 1)
        wait = min_gap - (time.monotonic() - self._last_call)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_call = time.monotonic()


class AIRouter:
    def __init__(self):
        self.providers: list[AIProvider] = [
            AIProvider("local", "llama3.1", "http://127.0.0.1:11434/api/chat",
                       kind="local", cost_per_1k_tokens=0.0, rpm=120,
                       enabled=os.getenv("OLLAMA_ENABLED", "1") != "0"),
            AIProvider("gemini", os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
                       "https://generativelanguage.googleapis.com/v1beta/models",
                       "GEMINI_API_KEY", 0.00015, 14, True, "gemini"),
            AIProvider("openai", os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
                       "https://api.openai.com/v1/chat/completions",
                       "OPENAI_API_KEY", 0.0004, 60, True, "openai-compatible"),
            AIProvider("anthropic", os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
                       "https://api.anthropic.com/v1/messages",
                       "ANTHROPIC_API_KEY", 0.0008, 50, True, "anthropic"),
        ]
        self._lock = asyncio.Lock()
        self.total_calls = 0
        self.estimated_cost = 0.0

    def configure_key(self, provider: str, key: str):
        env_name = {
            "gemini": "GEMINI_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }.get(provider.lower())
        if env_name:
            os.environ[env_name] = key

    def _estimate_tokens(self, prompt: str, system: str, max_tokens: int) -> int:
        return max(1, (len(prompt or "") + len(system or "")) // 4 + max_tokens)

    def _ranked(self, max_estimated_cost: Optional[float], estimated_tokens: int) -> list[AIProvider]:
        candidates = [p for p in self.providers if p.available]
        if max_estimated_cost is not None:
            candidates = [
                p for p in candidates
                if (estimated_tokens / 1000.0) * p.cost_per_1k_tokens <= max_estimated_cost
            ]
        if ai_privacy_guard.config.local_ollama_preferred:
            candidates.sort(key=lambda p: (p.name != "local", p.failures >= 3, p.cost_per_1k_tokens, p.failures))
            return candidates
        return sorted(candidates, key=lambda p: (p.failures >= 3, p.cost_per_1k_tokens, p.failures))

    async def complete(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.05,
        max_tokens: int = 2048,
        preferred_provider: str = "",
        max_estimated_cost: Optional[float] = None,
        api_key: str = "",
    ) -> str:
        estimated_tokens = self._estimate_tokens(prompt, system, max_tokens)
        providers = self._ranked(max_estimated_cost, estimated_tokens)
        if preferred_provider:
            providers.sort(key=lambda p: p.name != preferred_provider)
        if api_key:
            os.environ["GEMINI_API_KEY"] = api_key
            providers.sort(key=lambda p: p.name != "gemini")

        last_error = ""
        for provider in providers:
            is_cloud = provider.kind != "local"
            if is_cloud and not ai_privacy_guard.is_cloud_allowed():
                ai_privacy_guard.audit(provider.name, provider.model, len(prompt or ""), True, False,
                                       "cloud_ai_disabled")
                continue
            try:
                await provider.wait()
                safe_prompt = ai_privacy_guard.redact(prompt, cloud=is_cloud)
                safe_system = ai_privacy_guard.redact(system, cloud=is_cloud)
                ai_privacy_guard.audit(provider.name, provider.model, len(safe_prompt or ""), is_cloud, True,
                                       "allowed")
                text = await self._call_provider(provider, safe_prompt, safe_system, temperature, max_tokens)
                if text:
                    async with self._lock:
                        self.total_calls += 1
                        self.estimated_cost += (estimated_tokens / 1000.0) * provider.cost_per_1k_tokens
                    provider.failures = 0
                    provider.last_error = ""
                    return text
            except Exception as exc:
                provider.failures += 1
                provider.last_error = str(exc)[:200]
                last_error = "{}: {}".format(provider.name, provider.last_error)
                continue
        return ""

    async def _call_provider(self, provider: AIProvider, prompt: str, system: str,
                             temperature: float, max_tokens: int) -> str:
        if provider.kind == "gemini":
            key = provider.api_key
            url = "{}/{}:generateContent?key={}".format(provider.base_url, provider.model, key)
            contents = []
            if system:
                contents.append({"role": "user", "parts": [{"text": system}]})
                contents.append({"role": "model", "parts": [{"text": "Acknowledged."}]})
            contents.append({"role": "user", "parts": [{"text": prompt}]})
            body = {"contents": contents,
                    "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens}}
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(url, json=body)
                resp.raise_for_status()
                data = resp.json()
                return data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")

        if provider.kind == "anthropic":
            headers = {
                "x-api-key": provider.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            body = {
                "model": provider.model,
                "system": system,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(provider.base_url, json=body, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                return "".join(part.get("text", "") for part in data.get("content", []))

        if provider.kind == "local":
            body = {
                "model": provider.model,
                "stream": False,
                "messages": [
                    *([{"role": "system", "content": system}] if system else []),
                    {"role": "user", "content": prompt},
                ],
                "options": {"temperature": temperature, "num_predict": max_tokens},
            }
            async with httpx.AsyncClient(timeout=90) as client:
                resp = await client.post(provider.base_url, json=body)
                resp.raise_for_status()
                data = resp.json()
                return data.get("message", {}).get("content", "")

        headers = {"Authorization": "Bearer {}".format(provider.api_key)}
        body = {
            "model": provider.model,
            "messages": [
                *([{"role": "system", "content": system}] if system else []),
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(provider.base_url, json=body, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    async def complete_json(self, prompt: str, system: str = "", **kwargs) -> list | dict:
        raw = await self.complete(prompt, system=system, **kwargs)
        if not raw:
            return []
        clean = re.sub(r"```json\s*|```\s*", "", raw).strip()
        match = re.search(r"(\[.*\]|\{.*\})", clean, re.DOTALL)
        if not match:
            return []
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            return []

    def status(self) -> dict:
        return {
            "total_calls": self.total_calls,
            "estimated_cost_usd": round(self.estimated_cost, 4),
            "privacy": ai_privacy_guard.to_dict(),
            "providers": [
                {
                    "name": p.name,
                    "model": p.model,
                    "available": p.available,
                    "failures": p.failures,
                    "last_error": p.last_error,
                    "cost_per_1k_tokens": p.cost_per_1k_tokens,
                }
                for p in self.providers
            ],
        }


ai_router = AIRouter()
