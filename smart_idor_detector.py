"""smart_idor_detector.py

Commercial-grade IDOR / BOLA (Broken Object Level Authorization) detection module.

Pipeline:
    1. analyze_object_references(url, response)  -> candidate object refs to test
    2. generate_id_variants(original_id, id_type) -> 8 intelligent test IDs
    3. compare_responses(baseline, variant)       -> did unauthorized access occur?
    4. generate_poc_curl(...)                      -> reproducible PoC command
    5. detect_idor(...)                            -> orchestrates 1-4 with scope gating

Design principles (low false-positive, scanner-safe):
    * NOTHING is requested unless `scope_policy` authorises the exact URL/host.
    * Every function is async, None-safe, and returns a structured dict.
    * Differential analysis (baseline vs variant) decides vulnerability, never a
      single response in isolation.
    * Proof strength is graded so triage can trust CONFIRMED and de-prioritise
      CANDIDATE noise.

`scope_policy` contract (duck-typed; pass any object implementing one of these):
    - async def is_in_scope(url: str) -> bool
    - def is_in_scope(url: str) -> bool
    - a callable returning bool / awaitable bool
    - a dict: {"allowed_hosts": [...], "denied_hosts": [...], "allow_all": bool}
A None scope_policy is treated as FAIL-CLOSED (nothing is in scope).

`response` objects are duck-typed. We read, when present:
    .status_code (int) | .status (int)
    .headers (mapping)
    async .json() / .json() / .text / .text() / .body  (any subset)
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import inspect
import json
import random
import re
import shlex
import uuid
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union


# ===========================================================================
# 5. PROOF STRENGTH ENUM
# ===========================================================================
class ProofStrength(str, Enum):
    """Graded confidence that an authorization bypass actually occurred."""

    CONFIRMED = "CONFIRMED"          # cross-user sensitive data returned, 200, structurally matched
    PROBABLE = "PROBABLE"            # strong differential signal, minor ambiguity
    CANDIDATE = "CANDIDATE"          # worth testing, no confirmed cross-boundary access yet
    NOT_VULNERABLE = "NOT_VULNERABLE"  # access correctly denied / no signal

    def score(self) -> int:
        """Numeric confidence band for downstream rubrics (0-100)."""
        return {
            ProofStrength.CONFIRMED: 95,
            ProofStrength.PROBABLE: 75,
            ProofStrength.CANDIDATE: 40,
            ProofStrength.NOT_VULNERABLE: 0,
        }[self]


# Sensitive field names whose cross-user disclosure indicates real impact.
SENSITIVE_FIELDS = {
    "email", "e-mail", "mail",
    "phone", "phone_number", "mobile", "msisdn",
    "name", "full_name", "first_name", "last_name", "username",
    "address", "street", "city", "zip", "zipcode", "postal_code",
    "payment", "card", "card_number", "cc", "ccnumber", "iban", "account_number",
    "ssn", "national_id", "passport", "tax_id",
    "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
    "password", "pwd", "hash", "dob", "birthdate", "salary",
}

# Regexes for reference discovery.
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_NUMERIC_PATH_RE = re.compile(r"/(\d{1,19})(?=/|$|\?)")
# Base64-ish tokens (min length 8, valid alphabet, optional padding).
_B64_RE = re.compile(r"\b([A-Za-z0-9+/]{8,}={0,2})\b")
_B64URL_RE = re.compile(r"\b([A-Za-z0-9_-]{8,})\b")


# ===========================================================================
# SCOPE POLICY ENFORCEMENT (fail-closed)
# ===========================================================================
async def _check_scope(scope_policy: Any, url: str) -> bool:
    """Return True only if scope_policy explicitly authorises `url`.

    Fail-closed: any error, ambiguity, or missing policy -> False.
    """
    if scope_policy is None or not url:
        return False
    try:
        # Object with is_in_scope (sync or async).
        method = getattr(scope_policy, "is_in_scope", None)
        if callable(method):
            result = method(url)
            if inspect.isawaitable(result):
                result = await result
            return bool(result)

        # Plain callable.
        if callable(scope_policy):
            result = scope_policy(url)
            if inspect.isawaitable(result):
                result = await result
            return bool(result)

        # Dict-based policy.
        if isinstance(scope_policy, dict):
            if scope_policy.get("allow_all") is True:
                host = _host_of(url)
                denied = scope_policy.get("denied_hosts") or []
                return host not in set(denied)
            host = _host_of(url)
            allowed = set(scope_policy.get("allowed_hosts") or [])
            denied = set(scope_policy.get("denied_hosts") or [])
            if host in denied:
                return False
            return host in allowed
    except Exception:
        return False
    return False


def _host_of(url: str) -> str:
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/:?#]+)", url or "")
    if m:
        return m.group(1).lower()
    # Bare host or path; best-effort.
    return (url or "").split("/")[0].split("?")[0].lower()


# ===========================================================================
# RESPONSE NORMALISATION (None-safe, duck-typed)
# ===========================================================================
async def _extract(response: Any) -> Dict[str, Any]:
    """Normalise an arbitrary response object into a dict. None-safe.

    Returns: {"status": int|None, "headers": dict, "json": obj|None, "text": str|None}
    """
    out: Dict[str, Any] = {"status": None, "headers": {}, "json": None, "text": None}
    if response is None:
        return out

    # Status code.
    for attr in ("status_code", "status"):
        val = getattr(response, attr, None)
        if isinstance(val, int):
            out["status"] = val
            break

    # Headers.
    headers = getattr(response, "headers", None)
    if headers:
        try:
            out["headers"] = {str(k).lower(): str(v) for k, v in dict(headers).items()}
        except Exception:
            out["headers"] = {}

    # Body as text.
    text: Optional[str] = None
    text_attr = getattr(response, "text", None)
    try:
        if callable(text_attr):
            maybe = text_attr()
            text = await maybe if inspect.isawaitable(maybe) else maybe
        elif isinstance(text_attr, str):
            text = text_attr
    except Exception:
        text = None
    if text is None:
        body = getattr(response, "body", None) or getattr(response, "content", None)
        if isinstance(body, (bytes, bytearray)):
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = None
        elif isinstance(body, str):
            text = body
    out["text"] = text

    # JSON body.
    parsed = None
    json_attr = getattr(response, "json", None)
    try:
        if callable(json_attr):
            maybe = json_attr()
            parsed = await maybe if inspect.isawaitable(maybe) else maybe
    except Exception:
        parsed = None
    if parsed is None and text:
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
    out["json"] = parsed
    return out


# ===========================================================================
# 1. OBJECT REFERENCE ANALYSIS
# ===========================================================================
def _classify_token(token: str) -> Optional[str]:
    """Best-effort classification of a single token into an id_type."""
    if token is None:
        return None
    t = token.strip()
    if not t:
        return None
    if _UUID_RE.fullmatch(t):
        return "uuid"
    if t.lstrip("-").isdigit():
        return "numeric"
    # base64 / base64url: must decode to something and not be plain text.
    if re.fullmatch(r"[A-Za-z0-9+/]{8,}={0,2}", t) or re.fullmatch(r"[A-Za-z0-9_-]{8,}", t):
        decoded = _try_b64_decode(t)
        if decoded is not None:
            return "base64"
    return None


def _try_b64_decode(token: str) -> Optional[bytes]:
    """Attempt URL-safe and standard base64 decode. Return bytes or None."""
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            padded = token + "=" * (-len(token) % 4)
            raw = decoder(padded)
            # Reject tokens that decode to almost-all unprintable noise unless
            # they decode to a clean int / uuid / short ascii (typical ref).
            if raw:
                return raw
        except (binascii.Error, ValueError):
            continue
    return None


async def analyze_object_references(
    url: str,
    response: Any = None,
) -> Dict[str, Any]:
    """Analyse a URL (and optional response) for testable object references.

    Detects: numeric IDs in paths, UUIDs in paths, base64-encoded references,
    sequential query parameters, and user-correlated fields in JSON bodies.

    Returns a structured dict:
        {
          "url": str,
          "testable": bool,
          "path_references": [ {value, id_type, location, segment_index} ],
          "param_references": [ {param, value, id_type, sequential: bool} ],
          "json_references": [ {key_path, value, id_type} ],
          "user_correlated_fields": [ key_path, ... ],
          "summary": str,
        }
    """
    result: Dict[str, Any] = {
        "url": url or "",
        "testable": False,
        "path_references": [],
        "param_references": [],
        "json_references": [],
        "user_correlated_fields": [],
        "summary": "",
    }
    if not url:
        result["summary"] = "Empty URL; nothing to analyse."
        return result

    # --- Split URL into path + query ----------------------------------------
    path_part, _, query_part = url.partition("?")

    # --- Path references: numeric + uuid + base64 ---------------------------
    segments = [s for s in path_part.split("/") if s]
    for idx, seg in enumerate(segments):
        # UUID
        if _UUID_RE.fullmatch(seg):
            result["path_references"].append(
                {"value": seg, "id_type": "uuid", "location": "path", "segment_index": idx}
            )
            continue
        # numeric
        if seg.isdigit():
            result["path_references"].append(
                {"value": seg, "id_type": "numeric", "location": "path", "segment_index": idx}
            )
            continue
        # base64
        cls = _classify_token(seg)
        if cls == "base64":
            result["path_references"].append(
                {"value": seg, "id_type": "base64", "location": "path", "segment_index": idx}
            )

    # --- Query parameter references -----------------------------------------
    if query_part:
        pairs = [p for p in query_part.split("&") if p]
        for pair in pairs:
            key, _, value = pair.partition("=")
            if not value:
                continue
            id_type = _classify_token(value)
            if id_type is None:
                continue
            # "sequential" heuristic: id-like param names with numeric values.
            sequential = bool(
                id_type == "numeric"
                and re.search(r"(^|_)(id|uid|user|account|order|invoice|doc|num|seq|page|offset)$", key, re.I)
            )
            result["param_references"].append(
                {"param": key, "value": value, "id_type": id_type, "sequential": sequential}
            )

    # --- JSON body references + user-correlated fields ----------------------
    extracted = await _extract(response)
    body = extracted.get("json")
    if body is not None:
        _walk_json_for_refs(body, "", result)

    # --- Decide testability -------------------------------------------------
    result["testable"] = bool(
        result["path_references"]
        or result["param_references"]
        or result["json_references"]
    )
    counts = (
        f"{len(result['path_references'])} path, "
        f"{len(result['param_references'])} param, "
        f"{len(result['json_references'])} json refs; "
        f"{len(result['user_correlated_fields'])} user-correlated fields"
    )
    result["summary"] = (
        f"Testable object references found ({counts})."
        if result["testable"]
        else f"No directly testable object references ({counts})."
    )
    return result


def _walk_json_for_refs(node: Any, key_path: str, result: Dict[str, Any]) -> None:
    """Recursively collect id-like references and user-correlated fields."""
    if isinstance(node, dict):
        for k, v in node.items():
            kp = f"{key_path}.{k}" if key_path else str(k)
            klow = str(k).lower()
            # User-correlated / sensitive field present in the body.
            if any(s == klow or s in klow for s in SENSITIVE_FIELDS):
                result["user_correlated_fields"].append(kp)
            # id-like keys with id-like values.
            if re.search(r"(^|_)(id|uuid|guid|ref|key)$", klow) and isinstance(v, (str, int)):
                id_type = _classify_token(str(v))
                if id_type:
                    result["json_references"].append(
                        {"key_path": kp, "value": str(v), "id_type": id_type}
                    )
            _walk_json_for_refs(v, kp, result)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _walk_json_for_refs(item, f"{key_path}[{i}]", result)


# ===========================================================================
# 2. ID VARIANT GENERATION (8 intelligent variants)
# ===========================================================================
async def generate_id_variants(
    original_id: Any,
    id_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate 8 intelligent ID variants based on the original ID type.

    numeric -> id-1, id+1, id*2, 0, -1, 999999, random_nearby, id+10
    uuid    -> 8 valid UUIDs in the same format (canonical / hyphenless / case)
    base64  -> decode, mutate (numeric +/-, bit flip, re-encode) -> 8 variants

    Returns: {"original": str, "id_type": str, "variants": [ {value, strategy} ], "count": int}
    """
    out: Dict[str, Any] = {
        "original": "" if original_id is None else str(original_id),
        "id_type": id_type,
        "variants": [],
        "count": 0,
    }
    if original_id is None:
        return out

    original = str(original_id)
    if id_type is None:
        id_type = _classify_token(original) or "numeric"
        out["id_type"] = id_type

    variants: List[Dict[str, str]] = []

    if id_type == "numeric":
        try:
            n = int(original)
        except ValueError:
            n = 0
        rnd = n + random.choice([-5, -3, -2, 2, 3, 5]) if n else random.randint(1, 50)
        candidates = [
            (str(n - 1), "id-1 (previous object)"),
            (str(n + 1), "id+1 (next object)"),
            (str(n * 2 if n else 2), "id*2 (multiplicative)"),
            ("0", "0 (boundary / first object)"),
            ("-1", "-1 (negative boundary)"),
            ("999999", "999999 (high enumeration probe)"),
            (str(rnd), "random_nearby (sequential neighbour)"),
            (str(n + 10), "id+10 (range hop)"),
        ]
        variants = [{"value": v, "strategy": s} for v, s in candidates]

    elif id_type == "uuid":
        # Preserve the formatting style of the original (case + hyphenation).
        has_hyphens = "-" in original
        is_upper = original.isupper()

        def _fmt(u: uuid.UUID) -> str:
            s = str(u)
            if not has_hyphens:
                s = s.replace("-", "")
            return s.upper() if is_upper else s

        # 6 random v4 + 2 structured neighbours (incremented int form).
        for _ in range(6):
            variants.append({"value": _fmt(uuid.uuid4()), "strategy": "random valid UUIDv4 (same format)"})
        try:
            base_int = uuid.UUID(original.replace("-", "")) if not has_hyphens else uuid.UUID(original)
            n = base_int.int
            variants.append({"value": _fmt(uuid.UUID(int=(n + 1) % (1 << 128))), "strategy": "UUID int +1 (adjacent)"})
            variants.append({"value": _fmt(uuid.UUID(int=(n - 1) % (1 << 128))), "strategy": "UUID int -1 (adjacent)"})
        except (ValueError, AttributeError):
            variants.append({"value": _fmt(uuid.uuid4()), "strategy": "random valid UUIDv4 (fallback)"})
            variants.append({"value": _fmt(uuid.uuid4()), "strategy": "random valid UUIDv4 (fallback)"})

    elif id_type == "base64":
        raw = _try_b64_decode(original) or b""
        is_urlsafe = "-" in original or "_" in original
        encoder = base64.urlsafe_b64encode if is_urlsafe else base64.b64encode
        had_padding = original.endswith("=")

        def _enc(data: bytes) -> str:
            s = encoder(data).decode("ascii")
            return s if had_padding else s.rstrip("=")

        decoded_text = raw.decode("utf-8", errors="replace")
        # If the decoded value is itself numeric, mutate it numerically.
        if decoded_text.strip().lstrip("-").isdigit():
            base_n = int(decoded_text.strip())
            for delta, label in [(-1, "decoded id-1"), (1, "decoded id+1"),
                                 (2, "decoded id+2"), (10, "decoded id+10"),
                                 (-base_n, "decoded -> 0"), (999999 - base_n, "decoded -> 999999")]:
                variants.append({"value": _enc(str(base_n + delta).encode()), "strategy": f"base64({label})"})
            variants.append({"value": _enc(b"-1"), "strategy": "base64(-1 boundary)"})
            variants.append({"value": _enc(str(base_n + random.randint(2, 20)).encode()), "strategy": "base64(random nearby)"})
        else:
            # Non-numeric payload: byte-level mutations + re-encode.
            mutations: List[Tuple[bytes, str]] = []
            if raw:
                b = bytearray(raw)
                last = bytearray(raw); last[-1] = (last[-1] + 1) % 256
                mutations.append((bytes(last), "last byte +1"))
                first = bytearray(raw); first[0] = (first[0] + 1) % 256
                mutations.append((bytes(first), "first byte +1"))
                flip = bytearray(raw); flip[-1] ^= 0x01
                mutations.append((bytes(flip), "last byte bit-flip"))
                dec = bytearray(raw); dec[-1] = (dec[-1] - 1) % 256
                mutations.append((bytes(dec), "last byte -1"))
            mutations.append((raw + b"1", "append digit"))
            mutations.append((raw[:-1] if len(raw) > 1 else raw, "truncate 1 byte"))
            mutations.append((b"0", "decode->0"))
            mutations.append((b"1", "decode->1"))
            for data, label in mutations[:8]:
                variants.append({"value": _enc(data), "strategy": f"base64({label})"})

    else:
        # Unknown type: conservative string mutations.
        variants = [
            {"value": original + "1", "strategy": "append digit"},
            {"value": original[:-1] or original, "strategy": "truncate"},
            {"value": original.upper(), "strategy": "uppercase"},
            {"value": original.lower(), "strategy": "lowercase"},
            {"value": "0", "strategy": "zero"},
            {"value": "1", "strategy": "one"},
            {"value": "admin", "strategy": "privileged keyword"},
            {"value": original + original[-1:], "strategy": "duplicate last char"},
        ]

    # Guarantee exactly 8 unique variants where possible.
    seen = set()
    unique: List[Dict[str, str]] = []
    for v in variants:
        if v["value"] not in seen and v["value"] != original:
            seen.add(v["value"])
            unique.append(v)
    while len(unique) < 8:
        filler = str(random.randint(2, 999999))
        if filler not in seen:
            seen.add(filler)
            unique.append({"value": filler, "strategy": "random filler"})
    out["variants"] = unique[:8]
    out["count"] = len(out["variants"])
    return out


# ===========================================================================
# 3. RESPONSE COMPARISON (differential authorization analysis)
# ===========================================================================
def _collect_fields(node: Any, prefix: str, acc: Dict[str, Any]) -> None:
    """Flatten a JSON structure into {dotted_key_path: scalar_value}."""
    if isinstance(node, dict):
        for k, v in node.items():
            _collect_fields(v, f"{prefix}.{k}" if prefix else str(k), acc)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _collect_fields(item, f"{prefix}[{i}]", acc)
    else:
        acc[prefix] = node


def _is_sensitive(key_path: str) -> bool:
    leaf = key_path.split(".")[-1].split("[")[0].lower()
    return any(s == leaf or s in leaf for s in SENSITIVE_FIELDS)


async def compare_responses(
    baseline_response: Any,
    variant_response: Any,
) -> Dict[str, Any]:
    """Compare two responses to decide if unauthorized data access occurred.

    Checks:
      - same JSON keys but different personal/sensitive data values
      - presence of sensitive fields (email, phone, name, address, payment, token)
      - status-code differences (e.g. 200 where 403/404 expected)
      - empty vs populated responses
      - structural differences indicating a different user context

    Returns a structured dict including a ProofStrength verdict.
    """
    base = await _extract(baseline_response)
    var = await _extract(variant_response)

    findings: Dict[str, Any] = {
        "proof_strength": ProofStrength.NOT_VULNERABLE.value,
        "confidence": 0,
        "status_baseline": base["status"],
        "status_variant": var["status"],
        "signals": [],
        "sensitive_fields_exposed": [],
        "changed_sensitive_values": [],
        "shared_keys": 0,
        "notes": "",
    }
    signals: List[str] = findings["signals"]
    signals_ref = signals

    # --- Hard negatives: variant access was denied -> not vulnerable --------
    if var["status"] in (401, 403):
        findings["notes"] = f"Variant returned {var['status']} (access denied) -> authorization enforced."
        findings["proof_strength"] = ProofStrength.NOT_VULNERABLE.value
        return findings
    if var["status"] == 404 and base["status"] == 200:
        findings["notes"] = "Variant object not found (404) while baseline exists -> no cross-access demonstrated."
        findings["proof_strength"] = ProofStrength.NOT_VULNERABLE.value
        return findings

    base_json, var_json = base["json"], var["json"]

    # --- Empty vs populated -------------------------------------------------
    base_empty = _is_empty_body(base, base_json)
    var_empty = _is_empty_body(var, var_json)
    if var_empty:
        findings["notes"] = "Variant returned empty/no body -> no data disclosed."
        findings["proof_strength"] = ProofStrength.NOT_VULNERABLE.value
        return findings

    # --- Status signal ------------------------------------------------------
    if var["status"] == 200:
        signals.append("variant returned HTTP 200")
    if base["status"] is not None and var["status"] is not None and base["status"] != var["status"]:
        signals.append(f"status differs (baseline {base['status']} vs variant {var['status']})")

    # --- JSON structural + value diff --------------------------------------
    shared_keys = 0
    changed_sensitive: List[Dict[str, Any]] = []
    sensitive_present: List[str] = []
    structural_match = False

    if isinstance(base_json, (dict, list)) and isinstance(var_json, (dict, list)):
        base_fields: Dict[str, Any] = {}
        var_fields: Dict[str, Any] = {}
        _collect_fields(base_json, "", base_fields)
        _collect_fields(var_json, "", var_fields)

        base_keys = set(base_fields.keys())
        var_keys = set(var_fields.keys())
        common = base_keys & var_keys
        shared_keys = len(common)

        # Structural similarity: same shape strongly implies "same endpoint,
        # different object owner" -> classic IDOR signature.
        if base_keys and var_keys:
            jaccard = len(common) / len(base_keys | var_keys)
            if jaccard >= 0.7:
                structural_match = True
                signals.append(f"structurally identical response shape (key overlap {jaccard:.0%})")
            elif jaccard <= 0.3:
                signals.append(f"structurally different response (key overlap {jaccard:.0%}) -> possibly different context")

        # Same keys, different sensitive values -> different user's data.
        for kp in common:
            if _is_sensitive(kp):
                sensitive_present.append(kp)
                bv, vv = base_fields[kp], var_fields[kp]
                if bv != vv and vv not in (None, "", []):
                    changed_sensitive.append({"field": kp, "baseline": _redact(bv), "variant": _redact(vv)})

        # Sensitive fields present only in variant also count as exposure.
        for kp in var_keys:
            if _is_sensitive(kp) and var_fields.get(kp) not in (None, "", []):
                if kp not in sensitive_present:
                    sensitive_present.append(kp)

    elif isinstance(var_json, (dict, list)):
        # No baseline JSON to diff against; record raw exposure of sensitive keys.
        var_fields = {}
        _collect_fields(var_json, "", var_fields)
        for kp in var_fields:
            if _is_sensitive(kp) and var_fields[kp] not in (None, "", []):
                sensitive_present.append(kp)

    findings["shared_keys"] = shared_keys
    findings["sensitive_fields_exposed"] = sorted(set(sensitive_present))
    findings["changed_sensitive_values"] = changed_sensitive

    if changed_sensitive:
        signals.append(
            f"{len(changed_sensitive)} sensitive field(s) hold DIFFERENT values than baseline "
            "(distinct user's data)"
        )
    elif sensitive_present:
        signals.append(f"{len(sensitive_present)} sensitive field(s) disclosed in variant response")

    # --- Verdict logic ------------------------------------------------------
    strength = _grade(
        var_status=var["status"],
        structural_match=structural_match,
        changed_sensitive=changed_sensitive,
        sensitive_present=sensitive_present,
    )
    findings["proof_strength"] = strength.value
    findings["confidence"] = strength.score()
    findings["notes"] = "; ".join(signals_ref) if signals_ref else "No authorization-bypass signal detected."
    return findings


def _grade(
    *,
    var_status: Optional[int],
    structural_match: bool,
    changed_sensitive: List[Dict[str, Any]],
    sensitive_present: List[str],
) -> ProofStrength:
    """Map differential signals to a ProofStrength verdict (low FP)."""
    ok_status = var_status == 200 or (var_status is not None and 200 <= var_status < 300)

    # CONFIRMED: accessible + structurally same endpoint + a different user's
    # sensitive value came back. This is the textbook IDOR proof.
    if ok_status and structural_match and changed_sensitive:
        return ProofStrength.CONFIRMED

    # PROBABLE: accessible + sensitive data disclosed, but either structure
    # didn't match cleanly or we couldn't prove the value differs from baseline.
    if ok_status and (changed_sensitive or (structural_match and sensitive_present)):
        return ProofStrength.PROBABLE
    if ok_status and sensitive_present:
        return ProofStrength.PROBABLE

    # CANDIDATE: accessible and structurally similar but no sensitive data seen.
    if ok_status and structural_match:
        return ProofStrength.CANDIDATE
    if ok_status:
        return ProofStrength.CANDIDATE

    return ProofStrength.NOT_VULNERABLE


def _is_empty_body(extracted: Dict[str, Any], parsed: Any) -> bool:
    if parsed in (None, {}, []):
        text = extracted.get("text")
        return not (text and text.strip())
    if isinstance(parsed, (dict, list)) and len(parsed) == 0:
        return True
    return False


def _redact(value: Any) -> str:
    """Partially redact a sensitive value for safe inclusion in reports."""
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


# ===========================================================================
# 4. PROOF-OF-CONCEPT CURL GENERATION
# ===========================================================================
async def generate_poc_curl(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Union[Dict[str, str], str]] = None,
    body: Optional[Any] = None,
    attacker_label: str = "attacker session",
    victim_object_note: str = "victim-owned object",
) -> Dict[str, Any]:
    """Build a reproducible curl PoC demonstrating the unauthorized access.

    Session cookies are shown explicitly (this is the whole point of an IDOR
    PoC: prove that ATTACKER's session reached the VICTIM's object).

    Returns: {"curl": str, "method": str, "url": str, "explanation": str}
    """
    method = (method or "GET").upper()
    parts: List[str] = ["curl", "-i", "-sS", "-X", method]

    # Headers.
    hdrs = dict(headers or {})
    for k, v in hdrs.items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]

    # Cookies (explicit -> proves which session was used).
    cookie_str = ""
    if isinstance(cookies, dict) and cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
    elif isinstance(cookies, str) and cookies.strip():
        cookie_str = cookies.strip()
    if cookie_str:
        parts += ["-b", shlex.quote(cookie_str)]

    # Body for non-GET.
    if body is not None and method in {"POST", "PUT", "PATCH", "DELETE"}:
        if isinstance(body, (dict, list)):
            payload = json.dumps(body)
            if not any(k.lower() == "content-type" for k in hdrs):
                parts += ["-H", shlex.quote("Content-Type: application/json")]
        else:
            payload = str(body)
        parts += ["--data", shlex.quote(payload)]

    parts.append(shlex.quote(url or ""))
    curl = " ".join(parts)

    explanation = (
        f"This request uses the {attacker_label} (cookies shown via -b) to request "
        f"{victim_object_note} at {url}. A successful (HTTP 2xx) response containing "
        "the victim's data proves Broken Object Level Authorization (IDOR/BOLA): the "
        "server returned an object the authenticated principal is not entitled to."
    )
    return {"curl": curl, "method": method, "url": url or "", "explanation": explanation}


# ===========================================================================
# ORCHESTRATOR
# ===========================================================================
async def detect_idor(
    *,
    fetch: Callable[[str], Awaitable[Any]],
    url: str,
    scope_policy: Any,
    baseline_response: Any = None,
    method: str = "GET",
    attacker_cookies: Optional[Union[Dict[str, str], str]] = None,
    headers: Optional[Dict[str, str]] = None,
    max_variants: int = 8,
) -> Dict[str, Any]:
    """End-to-end IDOR detection for a single URL, with scope gating.

    Args:
        fetch: async callable fetch(url)->response, using the ATTACKER session.
        url: target URL to analyse and fuzz.
        scope_policy: authorisation policy (see module docstring). FAIL-CLOSED.
        baseline_response: optional pre-fetched baseline for `url`.
        method/headers/attacker_cookies: used for PoC + (optionally) requests.

    Returns a structured report dict; never raises.
    """
    report: Dict[str, Any] = {
        "url": url,
        "in_scope": False,
        "analysis": None,
        "tests": [],
        "best_proof": ProofStrength.NOT_VULNERABLE.value,
        "poc": None,
        "error": None,
    }
    try:
        # --- Scope gate (fail-closed) before ANY request -------------------
        if not await _check_scope(scope_policy, url):
            report["error"] = "URL is out of scope per scope_policy; no requests made."
            return report
        report["in_scope"] = True

        # --- Baseline ------------------------------------------------------
        if baseline_response is None:
            baseline_response = await fetch(url)

        # --- 1. Analyse references -----------------------------------------
        analysis = await analyze_object_references(url, baseline_response)
        report["analysis"] = analysis
        if not analysis["testable"]:
            report["error"] = "No testable object references found."
            return report

        # --- Pick the highest-value reference to fuzz first ----------------
        ref = _pick_reference(analysis)
        if ref is None:
            report["error"] = "No fuzzable reference selected."
            return report

        variants = await generate_id_variants(ref["value"], ref["id_type"])

        best = ProofStrength.NOT_VULNERABLE
        for v in variants["variants"][:max_variants]:
            variant_url = _replace_reference(url, ref, v["value"])
            if not await _check_scope(scope_policy, variant_url):
                continue  # never step outside scope, even for a variant
            try:
                variant_response = await fetch(variant_url)
            except Exception as exc:
                report["tests"].append({"variant_url": variant_url, "error": str(exc)})
                continue

            cmp = await compare_responses(baseline_response, variant_response)
            test_entry = {
                "variant_url": variant_url,
                "variant_id": v["value"],
                "strategy": v["strategy"],
                "result": cmp,
            }
            report["tests"].append(test_entry)

            strength = ProofStrength(cmp["proof_strength"])
            if strength.score() > best.score():
                best = strength
                # Build PoC for the strongest finding so far.
                report["poc"] = await generate_poc_curl(
                    method, variant_url,
                    headers=headers, cookies=attacker_cookies,
                    victim_object_note=f"object referenced by {ref['id_type']} '{v['value']}'",
                )

        report["best_proof"] = best.value
        return report

    except Exception as exc:  # absolute backstop
        report["error"] = f"unexpected: {exc}"
        return report


def _pick_reference(analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Choose the most promising reference: sequential params > path > json."""
    for ref in analysis.get("param_references", []):
        if ref.get("sequential"):
            return {"value": ref["value"], "id_type": ref["id_type"],
                    "location": "param", "param": ref["param"]}
    if analysis.get("path_references"):
        r = analysis["path_references"][0]
        return {"value": r["value"], "id_type": r["id_type"],
                "location": "path", "segment_index": r["segment_index"]}
    if analysis.get("param_references"):
        r = analysis["param_references"][0]
        return {"value": r["value"], "id_type": r["id_type"],
                "location": "param", "param": r["param"]}
    return None


def _replace_reference(url: str, ref: Dict[str, Any], new_value: str) -> str:
    """Return `url` with the chosen reference swapped for `new_value`."""
    if ref["location"] == "path":
        path_part, sep, query_part = url.partition("?")
        segs = path_part.split("/")
        # find nth non-empty segment
        non_empty_indices = [i for i, s in enumerate(segs) if s]
        idx = ref.get("segment_index", 0)
        if idx < len(non_empty_indices):
            segs[non_empty_indices[idx]] = new_value
        return "/".join(segs) + (sep + query_part if sep else "")
    if ref["location"] == "param":
        path_part, sep, query_part = url.partition("?")
        pairs = query_part.split("&") if query_part else []
        out = []
        for p in pairs:
            k, eq, _ = p.partition("=")
            if k == ref.get("param"):
                out.append(f"{k}={new_value}")
            else:
                out.append(p)
        return path_part + "?" + "&".join(out)
    return url


# ===========================================================================
# SELF-TEST (offline; no real network)
# ===========================================================================
if __name__ == "__main__":

    class _Resp:
        def __init__(self, status, payload=None, text=None):
            self.status_code = status
            self._payload = payload
            self._text = text if text is not None else (json.dumps(payload) if payload is not None else "")
            self.headers = {"content-type": "application/json"}

        def json(self):
            if self._payload is None:
                raise ValueError("no json")
            return self._payload

        @property
        def text(self):
            return self._text

    async def _main():
        # --- analyze_object_references ---
        a = await analyze_object_references(
            "https://api.example.com/v2/users/1001/invoices/55?account_id=1001",
            _Resp(200, {"id": 1001, "email": "alice@example.com", "name": "Alice"}),
        )
        print("ANALYZE:", a["testable"], "| user-correlated:", a["user_correlated_fields"])
        assert a["testable"] and "email" in a["user_correlated_fields"]

        # --- generate_id_variants ---
        for t, val in [("numeric", "1001"),
                       ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
                       ("base64", base64.b64encode(b"1001").decode())]:
            gv = await generate_id_variants(val, t)
            print(f"VARIANTS[{t}]: count={gv['count']} ->", [x['value'] for x in gv['variants']][:4], "...")
            assert gv["count"] == 8

        # --- compare_responses: CONFIRMED IDOR ---
        base = _Resp(200, {"id": 1001, "email": "alice@example.com", "name": "Alice", "phone": "111"})
        victim = _Resp(200, {"id": 1002, "email": "bob@example.com", "name": "Bob", "phone": "222"})
        cmp = await compare_responses(base, victim)
        print("COMPARE confirmed:", cmp["proof_strength"], "| changed:", [c["field"] for c in cmp["changed_sensitive_values"]])
        assert cmp["proof_strength"] == ProofStrength.CONFIRMED.value

        # --- compare_responses: access denied -> NOT_VULNERABLE ---
        denied = await compare_responses(base, _Resp(403, {"error": "forbidden"}))
        print("COMPARE denied:", denied["proof_strength"])
        assert denied["proof_strength"] == ProofStrength.NOT_VULNERABLE.value

        # --- None safety ---
        none_cmp = await compare_responses(None, None)
        print("COMPARE none:", none_cmp["proof_strength"])
        assert none_cmp["proof_strength"] == ProofStrength.NOT_VULNERABLE.value

        # --- generate_poc_curl ---
        poc = await generate_poc_curl(
            "GET", "https://api.example.com/v2/users/1002",
            headers={"Authorization": "Bearer ATTACKER_TOKEN"},
            cookies={"session": "attacker-cookie-123"},
        )
        print("POC:", poc["curl"])
        assert "-b" in poc["curl"] and "users/1002" in poc["curl"]

        # --- orchestrator with scope gating + fake fetch ---
        store = {
            "https://api.example.com/v2/users/1001": _Resp(200, {"id": 1001, "email": "alice@example.com", "name": "Alice"}),
            "https://api.example.com/v2/users/1002": _Resp(200, {"id": 1002, "email": "bob@example.com", "name": "Bob"}),
            "https://api.example.com/v2/users/1000": _Resp(200, {"id": 1000, "email": "carol@example.com", "name": "Carol"}),
        }

        async def fake_fetch(u):
            return store.get(u, _Resp(404, {"error": "not found"}))

        scope = {"allowed_hosts": ["api.example.com"]}
        rep = await detect_idor(
            fetch=fake_fetch,
            url="https://api.example.com/v2/users/1001",
            scope_policy=scope,
            attacker_cookies={"session": "attacker-cookie-123"},
        )
        print("ORCHESTRATOR best_proof:", rep["best_proof"], "| tests:", len(rep["tests"]))
        assert rep["in_scope"] and rep["best_proof"] in {ProofStrength.CONFIRMED.value, ProofStrength.PROBABLE.value}

        # --- out-of-scope must make ZERO requests ---
        oos = await detect_idor(fetch=fake_fetch, url="https://evil.com/users/1", scope_policy=scope)
        print("OUT-OF-SCOPE:", oos["in_scope"], "|", oos["error"])
        assert oos["in_scope"] is False

        print("\n[ALL SELF-TESTS PASSED]")

    asyncio.run(_main())
