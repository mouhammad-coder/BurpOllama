"""Secret-safe authenticated session profiles for authorized testing."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


SENSITIVE_HEADER_NAMES = {
    "authorization", "cookie", "proxy-authorization", "x-api-key", "api-key",
}


def _single_line(name: str, value: Any) -> str:
    text = str(value if value is not None else "").strip()
    if "\r" in text or "\n" in text:
        raise ValueError("{} must not contain CR or LF characters.".format(name))
    return text


def _decode_jwt_exp(token: str) -> int | None:
    """Read an unverified JWT expiry for operator-facing health information."""
    raw = token[7:].strip() if token.lower().startswith("bearer ") else token
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        expiry = decoded.get("exp")
        return int(expiry) if expiry is not None else None
    except Exception:
        return None


def _iso_timestamp(epoch: int | float | None) -> str | None:
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


@dataclass(frozen=True)
class SessionProfile:
    """Immutable credentials plus non-secret identity and expiry metadata."""

    role: str
    cookie: str = field(default="", repr=False)
    token: str = field(default="", repr=False)
    custom_headers: tuple[tuple[str, str], ...] = field(default_factory=tuple, repr=False)
    expires_at: int | None = None
    session_id: str = ""

    @classmethod
    def create(
        cls,
        role: str,
        *,
        cookie: str = "",
        token: str = "",
        custom_headers: dict[str, str] | None = None,
        expires_at: int | float | str | None = None,
    ) -> "SessionProfile":
        clean_role = _single_line("role", role) or "Unlabelled session"
        clean_cookie = _single_line("cookie", cookie)
        clean_token = _single_line("token", token)
        headers: list[tuple[str, str]] = []
        for name, value in (custom_headers or {}).items():
            clean_name = _single_line("header name", name)
            clean_value = _single_line("header value", value)
            if not clean_name or not clean_value:
                continue
            if clean_name.lower() in SENSITIVE_HEADER_NAMES:
                raise ValueError(
                    "Use the dedicated cookie or token field for {}.".format(clean_name)
                )
            headers.append((clean_name, clean_value))
        headers.sort(key=lambda item: item[0].lower())

        explicit_expiry = None
        if expires_at not in (None, ""):
            try:
                explicit_expiry = int(float(expires_at))
            except (TypeError, ValueError) as exc:
                raise ValueError("expires_at must be a Unix timestamp.") from exc
        expiry = explicit_expiry or _decode_jwt_exp(clean_token)

        identity_material = json.dumps({
            "cookie": clean_cookie,
            "token": clean_token,
            "headers": headers,
        }, sort_keys=True, separators=(",", ":"))
        identifier = (
            "SES-" + hashlib.sha256(identity_material.encode("utf-8")).hexdigest()[:12]
            if clean_cookie or clean_token or headers
            else ""
        )
        return cls(
            role=clean_role,
            cookie=clean_cookie,
            token=clean_token,
            custom_headers=tuple(headers),
            expires_at=expiry,
            session_id=identifier,
        )

    @property
    def configured(self) -> bool:
        return bool(self.cookie or self.token or self.custom_headers)

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= int(time.time())

    @property
    def expiring_soon(self) -> bool:
        return (
            self.expires_at is not None
            and not self.expired
            and self.expires_at <= int(time.time()) + 300
        )

    def headers(self, base_headers: dict[str, str] | None = None) -> dict[str, str]:
        result = dict(base_headers or {})
        result.update(dict(self.custom_headers))
        if self.cookie:
            result["Cookie"] = self.cookie
        if self.token:
            result["Authorization"] = (
                self.token
                if self.token.lower().startswith("bearer ")
                else "Bearer {}".format(self.token)
            )
        return result

    def public_status(self) -> dict[str, Any]:
        auth_types = []
        if self.cookie:
            auth_types.append("cookie")
        if self.token:
            auth_types.append("bearer")
        if self.custom_headers:
            auth_types.append("custom_headers")
        return {
            "configured": self.configured,
            "role": self.role,
            "session_id": self.session_id,
            "auth_types": auth_types,
            "expires_at": _iso_timestamp(self.expires_at),
            "expired": self.expired,
            "expiring_soon": self.expiring_soon,
        }

    def __str__(self) -> str:
        status = self.public_status()
        return "SessionProfile(role={!r}, session_id={!r}, auth_types={!r})".format(
            status["role"], status["session_id"], status["auth_types"]
        )
