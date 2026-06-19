"""Adaptive target profiling, module activation, and laptop-safe scan planning."""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Callable
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
try:
    import psutil
except ImportError:  # pragma: no cover - graceful fallback for minimal installs
    psutil = None


API_HINTS = ("/api/", "/v1/", "/v2/", "/v3/", "application/json", "openapi", "swagger")
AUTH_HINTS = ("login", "signin", "sign-in", "password", "oauth", "sso", "session", "account")
ADMIN_HINTS = ("admin", "administrator", "manage", "management", "dashboard", "console")
MOBILE_HINTS = ("mobile", "android", "ios", "device", "push-token", "app-version")
GRAPHQL_HINTS = ("graphql", "graphiql", "__schema")
STATIC_SUFFIXES = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map",
)


@dataclass
class TargetProfile:
    target: str
    profile_type: str = "General web application"
    recommended_scan: str = "BALANCED"
    confidence: int = 50
    endpoint_count: int = 0
    response_complexity: int = 0
    parameter_density: float = 0.0
    api_heavy: bool = False
    authentication_detected: bool = False
    js_heavy: bool = False
    mobile_backend: bool = False
    graphql_detected: bool = False
    admin_panels: bool = False
    reasons: list[str] = field(default_factory=list)
    observed_urls: list[str] = field(default_factory=list)
    response_time_ms: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AdaptivePlan:
    level: str
    reason: str
    enabled_modules: list[str]
    max_urls: int
    concurrency: int
    request_batch_size: int
    request_timeout: float
    run_nuclei: bool
    run_business_logic: bool
    run_deep_analysis: bool
    ai_mode: str
    cpu_limit_percent: int
    progress_messages: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


class ModuleEngine:
    """Explicit activation registry consumed by the hunt runner."""

    LIGHT_BASELINE = {
        "Security Headers", "CORS", "Sensitive Paths", "Subdomain Takeover",
    }
    BASELINE = LIGHT_BASELINE | {
        "Open Redirect", "Host Header Injection", "CRLF Injection",
    }
    PARAMETER_MODULES = {
        "Parameter Mining", "SQL Injection", "XSS", "Path Traversal and LFI",
        "SSTI", "SSRF",
    }
    API_MODULES = {
        "JWT Analysis", "JWT Key Confusion", "Mass Assignment",
        "Behavioral Anomaly", "Prototype Pollution", "NoSQL Injection",
        "XXE Candidates", "API Version", "API Version Testing",
    }
    AUTH_MODULES = {
        "IDOR", "Auth Bypass", "Rate Limiting", "CSRF", "OAuth Flow",
        "Default Credentials", "GraphQL Authorization", "Business Logic",
        "Race Conditions",
    }
    JS_MODULES = {"DOM XSS", "Stored XSS", "Blind XSS", "WebSocket Security"}
    DEEP_ONLY = {
        "HTTP Desync", "Request Smuggling", "Cache Poisoning", "Web Cache Deception",
        "File Upload Abuse", "OS Command Injection",
    }

    def __init__(self):
        self._enabled: set[str] = set()
        self._reasons: dict[str, str] = {}

    def enable(self, name: str, reason: str = ""):
        self._enabled.add(name)
        if reason:
            self._reasons[name] = reason

    def enable_many(self, names, reason: str = ""):
        for name in names:
            self.enable(name, reason)

    def enabled(self, name: str) -> bool:
        return name in self._enabled

    def snapshot(self) -> dict:
        return {
            "enabled": sorted(self._enabled),
            "reasons": dict(self._reasons),
        }

    @classmethod
    def for_profile(cls, profile: TargetProfile, level: str) -> "ModuleEngine":
        engine = cls()
        engine.enable_many(
            cls.LIGHT_BASELINE if level == "LIGHT" else cls.BASELINE,
            "baseline web safety checks",
        )
        if level == "LIGHT":
            return engine
        if level != "LIGHT":
            engine.enable_many(cls.PARAMETER_MODULES, "parameters or balanced scan")
        if profile.api_heavy or profile.mobile_backend or profile.graphql_detected:
            engine.enable_many(cls.API_MODULES, "API behavior detected")
        if profile.authentication_detected or profile.admin_panels:
            engine.enable_many(cls.AUTH_MODULES, "authentication boundary detected")
            engine.enable("idor_detector", "authentication boundary detected")
            engine.enable("auth_analyzer", "authentication boundary detected")
        if profile.graphql_detected:
            engine.enable("GraphQL", "GraphQL endpoint detected")
            engine.enable("GraphQL Authorization", "GraphQL endpoint detected")
        if profile.js_heavy:
            engine.enable_many(cls.JS_MODULES, "JavaScript-heavy frontend detected")
            engine.enable("js_endpoint_extractor", "JavaScript-heavy frontend detected")
        elif profile.api_heavy:
            engine.enable("js_endpoint_extractor", "API behavior detected")
        if level == "DEEP":
            engine.enable_many(cls.PARAMETER_MODULES | cls.API_MODULES | cls.AUTH_MODULES)
            engine.enable_many(cls.JS_MODULES | cls.DEEP_ONLY, "deep scan selected")
        return engine


class ResourceController:
    """Cooperative CPU/RAM guard used between request batches and phases."""

    def __init__(
        self,
        cpu_limit_percent: int = 60,
        min_free_memory_mb: int = 1200,
    ):
        self.cpu_limit_percent = max(20, min(90, int(cpu_limit_percent)))
        self.min_free_memory_mb = max(512, int(min_free_memory_mb))
        self.wait_count = 0
        self.last_reason = ""

    async def gate(self):
        if psutil is None:
            await asyncio.sleep(0)
            return
        for _ in range(12):
            cpu = float(psutil.cpu_percent(interval=0.05))
            free_mb = int(psutil.virtual_memory().available / (1024 * 1024))
            if cpu <= self.cpu_limit_percent and free_mb >= self.min_free_memory_mb:
                return
            self.wait_count += 1
            self.last_reason = (
                "cpu_{:.0f}_percent".format(cpu)
                if cpu > self.cpu_limit_percent
                else "low_memory_{}_mb".format(free_mb)
            )
            await asyncio.sleep(0.5)

    def status(self) -> dict:
        return {
            "cpu_limit_percent": self.cpu_limit_percent,
            "min_free_memory_mb": self.min_free_memory_mb,
            "wait_count": self.wait_count,
            "last_reason": self.last_reason,
            "psutil_available": psutil is not None,
        }


def _complexity_score(text: str, content_type: str) -> int:
    if "json" in content_type:
        return min(100, 20 + text.count("{") * 2 + text.count("["))
    tags = len(re.findall(r"<[a-zA-Z][^>]*>", text))
    scripts = len(re.findall(r"<script\b", text, re.I))
    forms = len(re.findall(r"<form\b", text, re.I))
    return min(100, tags // 4 + scripts * 5 + forms * 8)


def _profile_label(profile: TargetProfile) -> str:
    if profile.api_heavy and profile.authentication_detected:
        return "API-heavy SaaS"
    if profile.mobile_backend:
        return "Mobile application backend"
    if profile.graphql_detected:
        return "GraphQL application"
    if profile.js_heavy:
        return "JavaScript-heavy web application"
    if profile.admin_panels:
        return "Administrative web application"
    return "General web application"


def classify_profile(profile: TargetProfile) -> str:
    score = 0
    score += min(profile.endpoint_count, 80) // 8
    score += profile.response_complexity // 20
    score += min(int(profile.parameter_density * 5), 10)
    score += 5 if profile.api_heavy else 0
    score += 6 if profile.authentication_detected else 0
    score += 3 if profile.js_heavy else 0
    score += 4 if profile.mobile_backend else 0
    score += 4 if profile.graphql_detected else 0
    score += 3 if profile.admin_panels else 0
    if score >= 16:
        return "DEEP"
    if score <= 2 and not any((
        profile.api_heavy,
        profile.authentication_detected,
        profile.graphql_detected,
        profile.admin_panels,
    )):
        return "LIGHT"
    return "BALANCED"


async def profile_target(
    target: str,
    scope_policy,
    log: Callable | None = None,
) -> TargetProfile:
    """Bounded, read-only target profile: at most three GET requests."""
    allowed, reason = scope_policy.validate_target(target, action="scan")
    if not allowed:
        raise PermissionError(reason)

    profile = TargetProfile(target=target)
    candidates = [target, urljoin(target.rstrip("/") + "/", "robots.txt")]
    bodies: list[str] = []
    observed: set[str] = {target}
    response_times: list[int] = []

    timeout = httpx.Timeout(8.0)
    limits = httpx.Limits(max_connections=2, max_keepalive_connections=1)
    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        follow_redirects=True,
        verify=False,
        headers={"User-Agent": "BurpOllama-AdaptiveProfiler/1.0"},
    ) as client:
        for url in candidates:
            allowed, _ = scope_policy.record_request(url, action="scan")
            if not allowed:
                continue
            started = asyncio.get_running_loop().time()
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue
            response_times.append(int(
                (asyncio.get_running_loop().time() - started) * 1000
            ))
            text = (response.text or "")[:1_500_000]
            bodies.append(text)
            content_type = response.headers.get("content-type", "").lower()
            profile.response_complexity = max(
                profile.response_complexity,
                _complexity_score(text, content_type),
            )
            for match in re.findall(
                r"""(?:href|src|action)=["']([^"'#]+)|["'](\/(?:api|v\d+|graphql|admin|login)[^"']*)["']""",
                text,
                re.I,
            ):
                raw = next((part for part in match if part), "")
                if raw:
                    absolute = urljoin(str(response.url), raw)
                    if scope_policy.validate_target(absolute, action="scan")[0]:
                        observed.add(absolute)

    combined = "\n".join(bodies).lower()
    urls = sorted(observed)
    query_params = sum(len(parse_qs(urlparse(url).query)) for url in urls)
    profile.observed_urls = urls[:100]
    profile.endpoint_count = len(urls)
    profile.parameter_density = round(query_params / max(1, len(urls)), 2)
    profile.api_heavy = (
        sum(any(hint in url.lower() for hint in API_HINTS) for url in urls) >= 2
        or sum(combined.count(hint) for hint in API_HINTS) >= 4
    )
    profile.authentication_detected = any(hint in combined for hint in AUTH_HINTS) or any(
        any(hint in url.lower() for hint in AUTH_HINTS) for url in urls
    )
    script_count = combined.count("<script")
    profile.js_heavy = script_count >= 5 or combined.count(".js") >= 8
    profile.mobile_backend = any(hint in combined for hint in MOBILE_HINTS)
    profile.graphql_detected = any(hint in combined for hint in GRAPHQL_HINTS) or any(
        "graphql" in url.lower() for url in urls
    )
    profile.admin_panels = any(hint in combined for hint in ADMIN_HINTS) or any(
        any(hint in url.lower() for hint in ADMIN_HINTS) for url in urls
    )
    profile.response_time_ms = (
        sum(response_times) // len(response_times) if response_times else 0
    )
    profile.profile_type = _profile_label(profile)
    profile.recommended_scan = classify_profile(profile)
    profile.confidence = min(
        95,
        45 + min(25, profile.endpoint_count * 2)
        + (10 if bodies else 0)
        + (10 if profile.response_complexity else 0),
    )
    if profile.api_heavy:
        profile.reasons.append("API routes or JSON behavior detected")
    if profile.authentication_detected:
        profile.reasons.append("Login or account workflow detected")
    if profile.js_heavy:
        profile.reasons.append("JavaScript-heavy frontend detected")
    if profile.graphql_detected:
        profile.reasons.append("GraphQL usage detected")
    if profile.admin_panels:
        profile.reasons.append("Administrative interface detected")
    if not profile.reasons:
        profile.reasons.append("Small conventional web surface detected")
    if log:
        result = log(
            "Target Profile: {} | Recommended Scan: {} SCAN".format(
                profile.profile_type, profile.recommended_scan
            )
        )
        if asyncio.iscoroutine(result):
            await result
    return profile


def refine_profile(profile: TargetProfile, recon_data: dict, schema_data: dict | None = None) -> TargetProfile:
    schema_data = schema_data or {}
    urls = list(recon_data.get("urls", []) or [])
    tech = " ".join(recon_data.get("tech_stack", []) or []).lower()
    profile.endpoint_count = max(profile.endpoint_count, len(urls))
    query_params = sum(len(parse_qs(urlparse(url).query)) for url in urls)
    profile.parameter_density = round(query_params / max(1, len(urls)), 2)
    api_urls = [url for url in urls if any(hint in url.lower() for hint in API_HINTS)]
    profile.api_heavy = profile.api_heavy or len(api_urls) >= max(3, len(urls) // 4)
    profile.graphql_detected = profile.graphql_detected or bool(
        schema_data.get("graphql_endpoints")
    ) or "graphql" in tech
    profile.js_heavy = profile.js_heavy or sum(
        urlparse(url).path.lower().endswith(".js") for url in urls
    ) >= 5
    profile.authentication_detected = profile.authentication_detected or any(
        any(hint in url.lower() for hint in AUTH_HINTS) for url in urls
    )
    profile.admin_panels = profile.admin_panels or any(
        any(hint in url.lower() for hint in ADMIN_HINTS) for url in urls
    )
    profile.mobile_backend = profile.mobile_backend or any(
        any(hint in url.lower() for hint in MOBILE_HINTS) for url in urls
    )
    profile.profile_type = _profile_label(profile)
    profile.recommended_scan = classify_profile(profile)
    return profile


def build_adaptive_plan(profile: TargetProfile, requested_mode: str = "") -> AdaptivePlan:
    requested = str(requested_mode or "").lower()
    forced = {
        "passive_only": "LIGHT",
        "quick": "LIGHT",
        "normal": "DEEP",
        "intensive_authorized": "DEEP",
        "deep": "DEEP",
    }.get(requested)
    level = forced or classify_profile(profile)
    profile.recommended_scan = level
    engine = ModuleEngine.for_profile(profile, level)
    laptop_threads = max(1, int(os.getenv("OLLAMA_NUM_THREADS", "8") or 8))
    if level == "LIGHT":
        values = dict(
            max_urls=30, concurrency=2, request_batch_size=8,
            request_timeout=7.0, run_nuclei=False, run_business_logic=False,
            run_deep_analysis=False, ai_mode="fast_filter_only",
            cpu_limit_percent=45,
        )
    elif level == "DEEP":
        values = dict(
            max_urls=160, concurrency=min(6, laptop_threads),
            request_batch_size=16, request_timeout=12.0,
            run_nuclei=True, run_business_logic=True,
            run_deep_analysis=True, ai_mode="selective_reasoning",
            cpu_limit_percent=75,
        )
    else:
        values = dict(
            max_urls=80, concurrency=min(4, laptop_threads),
            request_batch_size=12, request_timeout=9.0,
            run_nuclei=False, run_business_logic=False,
            run_deep_analysis=False, ai_mode="selective_reasoning",
            cpu_limit_percent=60,
        )
    if profile.response_time_ms >= 2000:
        values["concurrency"] = max(1, values["concurrency"] - 1)
        values["request_timeout"] = min(
            20.0,
            max(values["request_timeout"], profile.response_time_ms / 1000 * 3),
        )
        values["request_batch_size"] = max(4, values["request_batch_size"] // 2)
    messages = ["Discovering endpoints (high confidence)"]
    if profile.api_heavy:
        messages.append("Expanding attack surface (API detected)")
    if profile.authentication_detected and level == "DEEP":
        messages.append("Switching to deep analysis (auth system found)")
    return AdaptivePlan(
        level=level,
        reason="; ".join(profile.reasons[:4]),
        enabled_modules=engine.snapshot()["enabled"],
        progress_messages=messages,
        **values,
    )
