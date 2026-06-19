"""
gemini_client.py — Rate-limited Gemini 2.0 Flash client
Free tier: 15 RPM / 1500 RPD
All calls go through the async queue so we never exceed limits.
"""

import asyncio
import time
import os
import json
import re
from ai_provider import ai_router

# ── Config ────────────────────────────────────────────────────────────────────
GEMINI_MODEL    = "gemini-2.0-flash"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
MAX_RPM         = 14        # stay under 15 to be safe
MIN_GAP_SECS    = 60 / MAX_RPM   # ~4.3 seconds between calls

# Load from env var or direct assignment
GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")


class GeminiRateLimiter:
    """Token-bucket style rate limiter — max 14 calls per 60 seconds."""

    def __init__(self, rpm: int = MAX_RPM):
        self._min_gap = 60.0 / rpm
        self._last_call: float = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            now   = time.monotonic()
            wait  = self._min_gap - (now - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


# Singleton limiter shared across all callers
_limiter = GeminiRateLimiter()


async def ask_gemini(
    prompt: str,
    system: str = "",
    temperature: float = 0.05,
    max_tokens: int = 2048,
    api_key: str = "",
) -> str:
    """
    Send a prompt to Gemini 2.0 Flash and return the text response.
    Automatically rate-limits, retries on 429, and returns "" on failure.
    """
    key = api_key or GEMINI_API_KEY
    if key:
        ai_router.configure_key("gemini", key)
    return await ai_router.complete(
        prompt,
        system=system,
        temperature=temperature,
        max_tokens=max_tokens,
        preferred_provider="gemini" if key else "",
        api_key=key,
    )


async def ask_gemini_json(
    prompt: str,
    system: str = "",
    api_key: str = "",
) -> list | dict:
    """
    Ask Gemini and parse the response as JSON.
    Returns [] or {} on failure.
    """
    raw = await ask_gemini(prompt, system=system, api_key=api_key)
    if not raw:
        return []
    try:
        # Strip markdown fences
        clean = re.sub(r"```json\s*|```\s*", "", raw).strip()
        # Extract JSON array or object
        match = re.search(r"(\[.*\]|\{.*\})", clean, re.DOTALL)
        if match:
            return json.loads(match.group(1))
    except json.JSONDecodeError as e:
        print("[Gemini] JSON parse error: {}".format(e))
    return []


def set_api_key(key: str):
    """Set the Gemini API key at runtime (called from /config endpoint)."""
    global GEMINI_API_KEY
    GEMINI_API_KEY = key
    ai_router.configure_key("gemini", key)
