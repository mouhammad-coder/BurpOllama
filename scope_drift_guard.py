"""Detect authorization-policy drift during long-running scans."""

from __future__ import annotations

import hashlib
import json
from typing import Any


RELEVANT_FIELDS = (
    "allowed_domains",
    "blocked_domains",
    "allowed_url_patterns",
    "blocked_url_patterns",
    "passive_only_mode",
    "active_testing_enabled",
    "authenticated_testing_enabled",
    "oob_testing_enabled",
    "allowed_vulnerability_classes",
    "forbidden_vulnerability_classes",
    "emergency_stop",
    "scan_mode",
)


def scope_snapshot(policy: dict[str, Any]) -> dict[str, Any]:
    snapshot = {key: policy.get(key) for key in RELEVANT_FIELDS}
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return {
        "fingerprint": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "policy": snapshot,
    }


def scope_drift(previous: dict | None, current_policy: dict) -> dict:
    current = scope_snapshot(current_policy)
    previous = previous if isinstance(previous, dict) else {}
    old_policy = previous.get("policy", {}) if isinstance(previous.get("policy"), dict) else {}
    changed = {
        key: {"before": old_policy.get(key), "after": current["policy"].get(key)}
        for key in RELEVANT_FIELDS
        if old_policy.get(key) != current["policy"].get(key)
    }
    return {
        "changed": bool(changed),
        "changes": changed,
        "previous_fingerprint": previous.get("fingerprint", ""),
        "current_fingerprint": current["fingerprint"],
        "snapshot": current,
    }
