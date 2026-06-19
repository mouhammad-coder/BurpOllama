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


REASONING_SECURITY_TERMS = {
    "idor": 5,
    "bola": 5,
    "auth bypass": 5,
    "authentication bypass": 5,
    "access control": 4,
    "authorization": 4,
    "jwt": 5,
    "oauth": 5,
    "session flaw": 5,
    "session fixation": 5,
    "session hijack": 5,
    "graphql authorization": 5,
    "payment": 5,
    "refund": 5,
    "order logic": 5,
    "business logic": 3,
    "race condition": 5,
    "request smuggling": 5,
    "http desync": 5,
    "ssrf": 5,
    "mass assignment": 4,
    "exploit chain": 5,
    "attack chain": 5,
    "account takeover": 5,
    "privilege escalation": 5,
}
RESOURCE_ERROR_TERMS = (
    "out of memory", "insufficient memory", "memory allocation", "resource exhausted",
    "not enough memory", "requires more system memory", "model requires more memory",
    "cuda out of memory", "failed to allocate", "cannot allocate memory",
    "timed out", "timeout",
)


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
        self.ollama_fast_model = os.getenv(
            "OLLAMA_FAST_MODEL",
            os.getenv("OLLAMA_MODEL", "mistral"),
        )
        self.ollama_reasoning_model = os.getenv(
            "OLLAMA_REASONING_MODEL", "llama3.1:8b"
        )
        self.auto_reasoning = os.getenv("AI_AUTO_REASONING", "1") != "0"
        self.reasoning_threshold = max(
            1, int(os.getenv("AI_REASONING_THRESHOLD", "5") or 5)
        )
        self.ollama_num_threads = max(
            1, int(os.getenv("OLLAMA_NUM_THREADS", "8") or 8)
        )
        self.ollama_fast_num_ctx = max(
            1024, int(os.getenv("OLLAMA_FAST_NUM_CTX", "4096") or 4096)
        )
        self.ollama_reasoning_num_ctx = max(
            1024, int(os.getenv("OLLAMA_REASONING_NUM_CTX", "6144") or 6144)
        )
        self.ollama_reasoning_timeout = max(
            30, int(os.getenv("OLLAMA_REASONING_TIMEOUT", "180") or 180)
        )
        self.ollama_reasoning_min_free_mb = max(
            512,
            int(os.getenv("OLLAMA_REASONING_MIN_FREE_MB", "3500") or 3500),
        )
        self.ollama_reasoning_temperature = float(
            os.getenv("OLLAMA_REASONING_TEMPERATURE", "0.03") or 0.03
        )
        self.ollama_keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "10m")
        self.providers: list[AIProvider] = [
            AIProvider("local", self.ollama_fast_model, "http://127.0.0.1:11434/api/chat",
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
        self._local_lock = asyncio.Lock()
        self._loaded_local_model = ""
        self.total_calls = 0
        self.estimated_cost = 0.0
        self.fast_calls = 0
        self.reasoning_calls = 0
        self.cloud_calls = 0
        self.reasoning_fallbacks = 0
        self.last_selected_provider = ""
        self.last_selected_model = ""
        self.last_routing_reason = "not_called"

    def configure_key(self, provider: str, key: str):
        env_name = {
            "gemini": "GEMINI_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }.get(provider.lower())
        if env_name:
            os.environ[env_name] = key

    def reload_from_env(self):
        """Apply web-saved settings without requiring an application restart."""
        self.ollama_fast_model = os.getenv(
            "OLLAMA_FAST_MODEL", os.getenv("OLLAMA_MODEL", "mistral")
        )
        self.ollama_reasoning_model = os.getenv(
            "OLLAMA_REASONING_MODEL", "llama3.1:8b"
        )
        self.auto_reasoning = os.getenv("AI_AUTO_REASONING", "1") != "0"
        self.reasoning_threshold = max(
            1, int(os.getenv("AI_REASONING_THRESHOLD", "5") or 5)
        )
        self.ollama_num_threads = max(
            1, int(os.getenv("OLLAMA_NUM_THREADS", "8") or 8)
        )
        self.ollama_fast_num_ctx = max(
            1024, int(os.getenv("OLLAMA_FAST_NUM_CTX", "4096") or 4096)
        )
        self.ollama_reasoning_num_ctx = max(
            1024, int(os.getenv("OLLAMA_REASONING_NUM_CTX", "6144") or 6144)
        )
        self.ollama_reasoning_timeout = max(
            30, int(os.getenv("OLLAMA_REASONING_TIMEOUT", "180") or 180)
        )
        self.ollama_reasoning_temperature = float(
            os.getenv("OLLAMA_REASONING_TEMPERATURE", "0.03") or 0.03
        )
        self.ollama_keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "10m")
        local = next((provider for provider in self.providers if provider.name == "local"), None)
        if local:
            local.model = self.ollama_fast_model
            local.enabled = os.getenv("OLLAMA_ENABLED", "1") != "0"
        self.last_routing_reason = "configuration_reloaded"

    def _estimate_tokens(self, prompt: str, system: str, max_tokens: int) -> int:
        return max(1, (len(prompt or "") + len(system or "")) // 4 + max_tokens)

    def _reasoning_score(self, prompt: str, system: str) -> tuple[int, list[str]]:
        text = "{}\n{}".format(system or "", prompt or "").lower()
        matches = []
        score = 0
        for term, weight in REASONING_SECURITY_TERMS.items():
            if term in text:
                matches.append(term)
                score += weight
        if any(token in text for token in (
            "high severity", "critical", "exploitability", "chain_of_thought",
            "seven gates", "7 gates",
        )):
            score += 1
        return score, matches

    def _select_local_route(
        self,
        prompt: str,
        system: str,
        preferred_provider: str,
    ) -> tuple[str, str, bool]:
        preferred = (preferred_provider or "").lower()
        if preferred in {"fast", "local_fast", "ollama_fast"}:
            return self.ollama_fast_model, "explicit_fast_model", False
        if preferred in {"reasoning", "local_reasoning", "ollama_reasoning"}:
            return self.ollama_reasoning_model, "explicit_reasoning_model", True
        score, matches = self._reasoning_score(prompt, system)
        if self.auto_reasoning and score >= self.reasoning_threshold:
            return (
                self.ollama_reasoning_model,
                "high_risk_security_reasoning:{}:{}".format(
                    score, ",".join(matches[:5])
                ),
                True,
            )
        return (
            self.ollama_fast_model,
            "fast_path_reasoning_score_{}".format(score),
            False,
        )

    @staticmethod
    def _is_resource_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return isinstance(
            exc, (MemoryError, asyncio.TimeoutError, httpx.TimeoutException)
        ) or any(
            term in text for term in RESOURCE_ERROR_TERMS
        )

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
                selected_model = provider.model
                routing_reason = "provider_ranked"
                reasoning_selected = False
                if provider.kind == "local":
                    selected_model, routing_reason, reasoning_selected = (
                        self._select_local_route(
                            safe_prompt, safe_system, preferred_provider
                        )
                    )
                ai_privacy_guard.audit(
                    provider.name,
                    selected_model,
                    len(safe_prompt or ""),
                    is_cloud,
                    True,
                    routing_reason,
                )
                async with self._lock:
                    if provider.kind == "local":
                        if reasoning_selected:
                            self.reasoning_calls += 1
                        else:
                            self.fast_calls += 1
                    else:
                        self.cloud_calls += 1
                    self.last_selected_provider = provider.name
                    self.last_selected_model = selected_model
                    self.last_routing_reason = routing_reason
                try:
                    text = await self._call_provider(
                        provider,
                        safe_prompt,
                        safe_system,
                        temperature,
                        max_tokens,
                        model_override=selected_model,
                        reasoning=reasoning_selected,
                    )
                except Exception as exc:
                    if provider.kind != "local" or not reasoning_selected:
                        raise
                    fallback_reason = (
                        "reasoning_fallback_due_to_resource_limit"
                        if self._is_resource_error(exc)
                        else "reasoning_fallback_due_to_model_error"
                    )
                    async with self._lock:
                        self.reasoning_fallbacks += 1
                        self.fast_calls += 1
                        self.last_routing_reason = fallback_reason
                    ai_privacy_guard.audit(
                        provider.name,
                        self.ollama_fast_model,
                        len(safe_prompt or ""),
                        False,
                        True,
                        fallback_reason,
                    )
                    text = await self._call_provider(
                        provider,
                        safe_prompt,
                        safe_system,
                        temperature,
                        max_tokens,
                        model_override=self.ollama_fast_model,
                        reasoning=False,
                    )
                    selected_model = self.ollama_fast_model
                    routing_reason = fallback_reason
                    reasoning_selected = False
                if text:
                    async with self._lock:
                        self.total_calls += 1
                        self.estimated_cost += (estimated_tokens / 1000.0) * provider.cost_per_1k_tokens
                        self.last_selected_provider = provider.name
                        self.last_selected_model = selected_model
                        self.last_routing_reason = routing_reason
                    provider.failures = 0
                    provider.last_error = ""
                    return text
            except Exception as exc:
                provider.failures += 1
                provider.last_error = str(exc)[:200]
                continue
        return ""

    async def _call_provider(self, provider: AIProvider, prompt: str, system: str,
                             temperature: float, max_tokens: int,
                             model_override: str = "",
                             reasoning: bool = False) -> str:
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
            model = model_override or self.ollama_fast_model
            num_ctx = (
                self.ollama_reasoning_num_ctx
                if reasoning else self.ollama_fast_num_ctx
            )
            selected_temperature = (
                self.ollama_reasoning_temperature
                if reasoning else temperature
            )
            timeout = self.ollama_reasoning_timeout if reasoning else 90
            body = {
                "model": model,
                "stream": False,
                "keep_alive": self.ollama_keep_alive,
                "messages": [
                    *([{"role": "system", "content": system}] if system else []),
                    {"role": "user", "content": prompt},
                ],
                "options": {
                    "temperature": selected_temperature,
                    "num_predict": max_tokens,
                    "num_ctx": num_ctx,
                    "num_thread": self.ollama_num_threads,
                },
            }
            async with self._local_lock:
                if self._loaded_local_model and self._loaded_local_model != model:
                    await self._unload_local_model(
                        provider.base_url, self._loaded_local_model
                    )
                    self._loaded_local_model = ""
                if reasoning:
                    available_mb = self._available_memory_mb()
                    if (
                        available_mb is not None
                        and available_mb < self.ollama_reasoning_min_free_mb
                    ):
                        raise MemoryError(
                            "reasoning model skipped: {} MB physical memory "
                            "available; {} MB required".format(
                                available_mb,
                                self.ollama_reasoning_min_free_mb,
                            )
                        )
                await self._ensure_local_model(provider.base_url, model)
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(float(timeout))
                ) as client:
                    resp = await client.post(provider.base_url, json=body)
                    if resp.status_code >= 400:
                        detail = (resp.text or "")[:500]
                        raise RuntimeError(
                            "Ollama HTTP {}: {}".format(
                                resp.status_code, detail
                            )
                        )
                    data = resp.json()
                    self._loaded_local_model = model
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

    async def _unload_local_model(self, chat_url: str, model: str):
        unload_url = chat_url.rsplit("/", 1)[0] + "/generate"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    unload_url,
                    json={
                        "model": model,
                        "prompt": "",
                        "stream": False,
                        "keep_alive": 0,
                    },
                )
        except Exception:
            pass

    @staticmethod
    def _available_memory_mb() -> Optional[int]:
        """Return physical memory currently available, excluding swap/page file."""
        try:
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", "r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.startswith("MemAvailable:"):
                            return int(line.split()[1]) // 1024
        except (OSError, ValueError, IndexError):
            pass
        if os.name == "nt":
            try:
                import ctypes

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                state = MEMORYSTATUSEX()
                state.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(
                    ctypes.byref(state)
                ):
                    return int(state.ullAvailPhys // (1024 * 1024))
            except (AttributeError, OSError, ValueError):
                pass
        return None

    async def _ensure_local_model(self, chat_url: str, model: str):
        api_root = chat_url.rsplit("/", 1)[0]
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(api_root + "/tags")
                response.raise_for_status()
                installed = {
                    str(item.get("name", ""))
                    for item in response.json().get("models", [])
                }
                installed.update(
                    str(item.get("model", ""))
                    for item in response.json().get("models", [])
                )
            if model in installed or any(
                name.split(":")[0] == model.split(":")[0]
                and (
                    ":" not in model
                    or name == model
                    or name == model + ":latest"
                )
                for name in installed
            ):
                return
            async with httpx.AsyncClient(timeout=900) as client:
                response = await client.post(
                    api_root + "/pull",
                    json={"name": model, "stream": False},
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError(
                "Ollama model preparation failed for {}: {}".format(
                    model, exc
                )
            ) from exc

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
            "fast_calls": self.fast_calls,
            "reasoning_calls": self.reasoning_calls,
            "cloud_calls": self.cloud_calls,
            "reasoning_fallbacks": self.reasoning_fallbacks,
            "last_selected_provider": self.last_selected_provider,
            "last_selected_model": self.last_selected_model,
            "last_routing_reason": self.last_routing_reason,
            "routing": {
                "auto_reasoning": self.auto_reasoning,
                "reasoning_threshold": self.reasoning_threshold,
                "fast_model": self.ollama_fast_model,
                "reasoning_model": self.ollama_reasoning_model,
                "num_threads": self.ollama_num_threads,
                "max_loaded_models": int(
                    os.getenv("OLLAMA_MAX_LOADED_MODELS", "1") or 1
                ),
                "fast_num_ctx": self.ollama_fast_num_ctx,
                "reasoning_num_ctx": self.ollama_reasoning_num_ctx,
                "reasoning_timeout": self.ollama_reasoning_timeout,
                "reasoning_min_free_mb": self.ollama_reasoning_min_free_mb,
                "reasoning_temperature": self.ollama_reasoning_temperature,
                "keep_alive": self.ollama_keep_alive,
            },
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
