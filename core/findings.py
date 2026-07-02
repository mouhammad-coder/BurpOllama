"""Final findings schema, proof classification, redaction, and table rendering."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.bug_registry import RATES, STATUSES, bug_type_for


GREAT = "Great Finding"
MANUAL = "Needs Manual Check"
INFO = "Informational"
REJECTED = "Rejected"
RATE_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
MIN_RATE_ALIASES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}

SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*)(bearer\s+)?[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)(cookie\s*:\s*)[^\r\n;]+(?:;[^\r\n]+)?"),
    re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n;]+(?:;[^\r\n]+)?"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|session[_-]?id|csrf)[\"'\s:=]+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"),
)


MANUAL_REASON_RULES = (
    ("two_authorized_accounts", ("idor", "bola", "horizontal", "order ownership", "role comparison", "two authorized")),
    ("authenticated_cookies_required", ("authenticated", "cookie", "session", "login")),
    ("program_permission_required", ("permission", "program", "introspection", "upload", "rate-limit", "rate limit", "ssrf")),
    ("active_testing_required", ("active", "upload", "mutation", "workflow", "payment", "order", "coupon")),
    ("impact_confirmation_required", ("impact", "business logic", "sensitive", "admin", "exposure")),
    ("partial_evidence", ("candidate", "possible", "pattern", "observed", "surface", "headers")),
    ("unsafe_to_verify_automatically", ("metadata", "command injection", "destructive", "dos", "brute")),
)


@dataclass
class FinalFinding:
    id: str
    title: str
    status: str
    rate: str
    confidence: int
    affected_asset: str
    evidence: str
    why_it_matters: str
    next_step: str
    missing_proof: str = ""
    manual_check_needed: str = ""
    observed: str = ""
    safety_warning: str = ""
    bug_type_id: str = ""
    bug_type_name: str = ""
    source: str = ""
    raw_status_reason: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def redact_text(value: Any) -> str:
    text = str(value or "")
    for pattern in SECRET_PATTERNS:
        def repl(match: re.Match) -> str:
            prefix = match.group(1) if match.groups() else ""
            return f"{prefix}[REDACTED]"

        text = pattern.sub(repl, text)
    return text


def _text(value: Any, fallback: str = "") -> str:
    text = redact_text(value).strip()
    return text or fallback


def _clip(value: Any, limit: int = 96) -> str:
    text = _text(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def normalize_rate(value: Any, fallback: str = "Info") -> str:
    text = str(value or fallback).strip().lower()
    if text == "informational":
        text = "info"
    return MIN_RATE_ALIASES.get(text, fallback if fallback in RATES else "Info")


def confidence_value(value: Any, default: int = 0) -> int:
    try:
        return max(0, min(100, int(float(value))))
    except (TypeError, ValueError):
        return default


def _artifact(finding: dict) -> dict:
    artifact = finding.get("evidence_artifact") or {}
    return artifact if isinstance(artifact, dict) else {}


def _artifact_field(finding: dict, key: str, fallback: str = "") -> str:
    artifact = _artifact(finding)
    value = artifact.get(key)
    if value is None and isinstance(artifact.get("metadata"), dict):
        value = artifact["metadata"].get(key)
    if value is None:
        value = finding.get(key, fallback)
    return _text(value, fallback)


def _has_complete_evidence(finding: dict) -> bool:
    artifact = _artifact(finding)
    if artifact and (
        artifact.get("confirmed") is True
        or (
            _text(artifact.get("raw_request"))
            and _text(artifact.get("raw_response"))
            and _text(artifact.get("matched_indicator"))
        )
    ):
        return True
    if finding.get("evidence_complete") is True:
        return True
    strength = str(finding.get("evidence_strength") or "").lower()
    status = str(finding.get("exploitability_status") or "").lower()
    evidence = _text(finding.get("evidence"))
    return bool(
        evidence
        and strength in {"strong", "moderate"}
        and status in {"confirmed", "probable"}
    )


def _has_impact(finding: dict) -> bool:
    return bool(
        _text(finding.get("business_impact"))
        or _text(finding.get("impact"))
        or _artifact_field(finding, "impact")
    )


def _is_missing_header_only(finding: dict) -> bool:
    label = " ".join(
        str(finding.get(key, ""))
        for key in ("title", "vuln_type", "vulnerability_class", "evidence")
    ).lower()
    return (
        "missing" in label
        and "header" in label
        and not _has_impact(finding)
    )


def _source_is_ai_only(finding: dict) -> bool:
    source = str(finding.get("source") or finding.get("agent") or "").lower()
    evidence_source = str(finding.get("evidence_source") or "").lower()
    if "ai" not in source and evidence_source != "ai":
        return False
    artifact = _artifact(finding)
    return not bool(artifact and artifact.get("artifact_path"))


def _manual_reasons(finding: dict) -> list[str]:
    text = " ".join(
        str(finding.get(key, ""))
        for key in (
            "title",
            "vuln_type",
            "vulnerability_class",
            "description",
            "evidence",
            "zero_fp_failed_checks",
            "rejection_reason_codes",
        )
    ).lower()
    reasons: list[str] = []
    for reason, terms in MANUAL_REASON_RULES:
        if any(term in text for term in terms):
            reasons.append(reason)
    if not _has_complete_evidence(finding):
        reasons.append("proof_missing")
    if not _has_impact(finding):
        reasons.append("impact_not_confirmed")
    return list(dict.fromkeys(reasons))


def _manual_step(finding: dict, bug_manual: tuple[str, ...] = ()) -> str:
    title = " ".join(str(finding.get(key, "")) for key in ("title", "vuln_type")).lower()
    if any(term in title for term in ("idor", "bola", "order ownership", "access control")):
        return "Test with two authorized accounts: verify whether User A can access User B's object response for the same endpoint shape."
    if "rate" in title:
        return "Check program rules before any low-volume manual rate-limit validation; stop on 429 or blocking."
    if "upload" in title:
        return "If upload testing is allowed, upload a benign file and verify type, storage path, and access controls on owned data."
    if "graphql" in title or "introspection" in title:
        return "Confirm GraphQL permission, then test introspection and object authorization with authorized accounts."
    if "payment" in title or "order" in title or "workflow" in title:
        return "Use an approved sandbox or owned test account to check order/payment state changes without completing real purchases."
    if "business logic" in title:
        return "Map the intended workflow, then test one low-risk owned-account step for missing server-side state validation."
    if "enumeration" in title:
        return "Compare responses for an existing owned account and a non-existing account, checking status, body, timing, and reset messaging."
    if "password reset" in title:
        return "Use owned accounts to verify reset token scope, expiry, reuse, and whether account existence is revealed."
    if "mfa" in title:
        return "With an owned account, verify MFA cannot be skipped during login, reset, backup-code, or session refresh flows."
    if "cors" in title:
        return "Send an Origin header from an untrusted domain and verify whether credentials or sensitive data are allowed."
    if "missing" in title and "header" in title:
        return "Confirm whether the missing header affects a sensitive page; missing headers alone are usually informational."
    if "admin" in title:
        return "Check whether the admin route is only a login page or exposes sensitive functions to the current authorized role."
    existing = finding.get("manual_check_needed") or finding.get("manual_next_step")
    if existing:
        return _clip(existing, 120)
    steps = finding.get("safe_manual_validation_steps") or finding.get("reproduction_steps")
    if isinstance(steps, list):
        for step in steps:
            if _text(step):
                return _clip(step, 120)
    if bug_manual:
        return _clip(bug_manual[0], 120)
    return "Validate manually within authorized scope using low-rate controlled test data."


def _missing_proof(finding: dict, reasons: list[str]) -> str:
    if finding.get("missing_proof"):
        return _clip(finding["missing_proof"], 96)
    if "two_authorized_accounts" in reasons:
        return "No second-user proof yet"
    if "authenticated_cookies_required" in reasons:
        return "No authenticated session proof"
    if "program_permission_required" in reasons:
        return "Program permission not confirmed"
    if "impact_not_confirmed" in reasons:
        return "Impact not confirmed"
    if "proof_missing" in reasons:
        return "Evidence is partial"
    return "Manual validation required"


def _asset(finding: dict, target: str = "") -> str:
    value = (
        finding.get("affected_asset")
        or finding.get("asset")
        or finding.get("affected_url")
        or finding.get("url")
        or target
    )
    text = _text(value, target)
    parsed = urlparse(text)
    if parsed.hostname and parsed.path in {"", "/"}:
        return parsed.hostname
    return text


def _evidence_summary(finding: dict) -> str:
    indicator = _artifact_field(finding, "matched_indicator")
    location = _artifact_field(finding, "indicator_location")
    if indicator and location:
        return _clip(f"{indicator} in {location}", 96)
    for key in ("evidence_summary", "evidence", "description"):
        if _text(finding.get(key)):
            return _clip(finding.get(key), 96)
    return "Observed by scanner"


def _why_it_matters(finding: dict, bug_impact: str = "") -> str:
    return _clip(
        finding.get("why_it_matters")
        or finding.get("business_impact")
        or finding.get("impact")
        or _artifact_field(finding, "impact")
        or bug_impact
        or "Potential security impact requires validation.",
        120,
    )


def _next_step(finding: dict, bug_manual: tuple[str, ...] = ()) -> str:
    return _clip(
        finding.get("next_step")
        or finding.get("recommended_next_step")
        or _manual_step(finding, bug_manual),
        120,
    )


def classify_finding(finding: dict, *, target: str = "") -> FinalFinding:
    bug = bug_type_for(finding)
    rate = normalize_rate(
        finding.get("rate") or finding.get("severity"),
        bug.default_rate if bug else "Info",
    )
    confidence = confidence_value(finding.get("confidence"), 50)
    title = _clip(finding.get("title") or finding.get("vuln_type") or "Finding", 80)
    reasons: list[str] = []
    status = str(finding.get("finding_status") or finding.get("status") or "").strip()
    if status not in STATUSES:
        status = ""

    if _source_is_ai_only(finding):
        status = REJECTED
        reasons.append("ai_only_assumption")
    elif str(finding.get("zero_fp_label") or "").upper() in {"REMOVED", "SKIPPED"}:
        status = REJECTED
        reasons.append("false_positive_killer_or_scope_veto")
    elif _is_missing_header_only(finding):
        status = INFO
        reasons.append("missing_header_only")
    elif not _has_impact(finding) and rate != "Info":
        status = INFO
        reasons.append("missing_impact")

    manual_reasons = _manual_reasons(finding)
    complete_evidence = _has_complete_evidence(finding)
    if not status:
        if confidence >= 80 and complete_evidence and _has_impact(finding):
            status = GREAT
        elif confidence >= 45 and (manual_reasons or rate in {"Critical", "High", "Medium"}):
            status = MANUAL
        elif rate == "Info" or confidence >= 30:
            status = INFO
        else:
            status = REJECTED
            reasons.append("low_confidence_or_no_impact")

    if status == GREAT and (confidence < 80 or not complete_evidence or not _has_impact(finding)):
        status = MANUAL if confidence >= 45 else INFO
        reasons.append("great_requires_confidence_evidence_and_impact")
    if status == MANUAL:
        reasons.extend(manual_reasons or ["manual_validation_required"])
    if status == REJECTED:
        reasons.extend(str(item) for item in finding.get("zero_fp_failed_checks", []) or [])

    missing = _missing_proof(finding, manual_reasons)
    manual_step = _manual_step(
        finding,
        bug.required_manual_verification if bug else (),
    )
    return FinalFinding(
        id=_text(finding.get("id"), "finding"),
        title=title,
        status=status,
        rate=rate,
        confidence=confidence,
        affected_asset=_clip(_asset(finding, target), 96),
        evidence=_evidence_summary(finding),
        why_it_matters=_why_it_matters(finding, bug.impact_template if bug else ""),
        next_step=_next_step(finding, bug.required_manual_verification if bug else ()),
        missing_proof=missing if status == MANUAL else "",
        manual_check_needed=manual_step if status == MANUAL else "",
        observed=_evidence_summary(finding),
        safety_warning=(
            "Do not perform active testing unless the program explicitly allows it."
            if any(reason in manual_reasons for reason in ("program_permission_required", "active_testing_required"))
            else ""
        ),
        bug_type_id=bug.id if bug else "",
        bug_type_name=bug.name if bug else "",
        source=_text(finding.get("source") or finding.get("agent")),
        raw_status_reason=list(dict.fromkeys(reasons)),
    )


def _candidate_findings(scan: dict) -> list[dict]:
    final = scan.get("final_findings")
    if isinstance(final, dict) and isinstance(final.get("all"), list):
        return list(final["all"])
    gate = (scan.get("analysis") or {}).get("zero_fp_gate") if isinstance(scan.get("analysis"), dict) else {}
    if isinstance(gate, dict) and gate:
        items: list[dict] = []
        for key in ("valid_bugs", "needs_more_proof", "candidates", "informational", "false_positives_removed", "skipped_out_of_scope"):
            for finding in gate.get(key, []) or []:
                item = dict(finding)
                if key == "valid_bugs":
                    item.setdefault("finding_status", GREAT)
                elif key in {"needs_more_proof", "candidates"}:
                    item.setdefault("finding_status", MANUAL)
                elif key == "informational":
                    item.setdefault("finding_status", INFO)
                else:
                    item.setdefault("finding_status", REJECTED)
                items.append(item)
        if items:
            return items
    return list(
        scan.get("triaged_findings")
        or scan.get("findings")
        or scan.get("raw_findings")
        or []
    )


def final_findings(scan: dict) -> dict[str, Any]:
    existing = scan.get("final_findings")
    if isinstance(existing, dict) and {"great", "manual", "informational", "rejected", "counts"} <= set(existing):
        return existing
    target = str(scan.get("target") or "")
    classified = [
        classify_finding(finding, target=target).to_dict()
        for finding in _candidate_findings(scan)
        if isinstance(finding, dict)
    ]
    classified = _dedupe_final(classified)
    classified.sort(key=_sort_key)
    buckets = {
        "great": [item for item in classified if item["status"] == GREAT],
        "manual": [item for item in classified if item["status"] == MANUAL],
        "informational": [item for item in classified if item["status"] == INFO],
        "rejected": [item for item in classified if item["status"] == REJECTED],
    }
    return {
        "schema_version": 1,
        "target": target,
        "all": classified,
        **buckets,
        "counts": {
            "great": len(buckets["great"]),
            "manual": len(buckets["manual"]),
            "informational": len(buckets["informational"]),
            "rejected": len(buckets["rejected"]),
        },
    }


def _dedupe_final(items: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict] = []
    for item in items:
        key = (
            str(item.get("title", "")).lower(),
            str(item.get("affected_asset", "")).lower(),
            str(item.get("evidence", "")).lower(),
        )
        if key in seen:
            item["status"] = REJECTED
            item.setdefault("raw_status_reason", []).append("duplicate")
            unique.append(item)
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _sort_key(item: dict) -> tuple[int, int, str]:
    return (
        RATE_ORDER.get(str(item.get("rate")), 99),
        -confidence_value(item.get("confidence")),
        str(item.get("title") or ""),
    )


def filter_final_findings(
    findings: dict[str, Any],
    *,
    show_info: bool = False,
    show_rejected: bool = False,
    show_all: bool = False,
    min_rate: str = "",
    min_confidence: int = 0,
) -> list[dict]:
    if show_all:
        items = list(findings.get("all", []))
    else:
        items = list(findings.get("great", [])) + list(findings.get("manual", []))
        if show_info:
            items.extend(findings.get("informational", []))
        if show_rejected:
            items.extend(findings.get("rejected", []))
    if min_rate:
        rate = normalize_rate(min_rate, "Info")
        max_order = RATE_ORDER[rate]
        items = [
            item for item in items
            if RATE_ORDER.get(str(item.get("rate")), 99) <= max_order
        ]
    if min_confidence:
        items = [
            item for item in items
            if confidence_value(item.get("confidence")) >= int(min_confidence)
        ]
    return sorted(items, key=_sort_key)


def write_scan_artifacts(scan: dict, output_root: str | Path) -> dict[str, str]:
    scan_id = str(scan.get("id") or "scan")
    directory = Path(output_root).expanduser() / scan_id
    directory.mkdir(parents=True, exist_ok=True)
    findings = scan.get("final_findings")
    if not isinstance(findings, dict):
        findings = final_findings(scan)
        scan["final_findings"] = findings
    payloads = {
        "findings.json": findings,
        "evidence-board.json": scan.get("analysis", {}),
        "agent-messages.jsonl": scan.get("blackboard", []),
        "agent-decisions.jsonl": scan.get("agent_decisions", []),
        "agent-graph.json": scan.get("analysis", {}).get("attack_graph", {}),
        "scan-log.jsonl": scan.get("logs", []),
    }
    paths: dict[str, str] = {}
    for filename, payload in payloads.items():
        path = directory / filename
        if filename.endswith(".jsonl"):
            rows = payload if isinstance(payload, list) else []
            path.write_text(
                "".join(json.dumps(redact_json(row), ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
        else:
            path.write_text(
                json.dumps(redact_json(payload), ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        paths[filename] = str(path)
    return paths


def redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): redact_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [
        max(len(str(header)), *(len(str(row[index])) for row in rows)) if rows else len(str(header))
        for index, header in enumerate(headers)
    ]
    header_line = "| " + " | ".join(str(header).ljust(widths[index]) for index, header in enumerate(headers)) + " |"
    sep_line = "| " + " | ".join("-" * widths[index] for index in range(len(headers))) + " |"
    body = [
        "| " + " | ".join(str(cell).ljust(widths[index]) for index, cell in enumerate(row)) + " |"
        for row in rows
    ]
    return "\n".join([header_line, sep_line, *body])


def render_final_tables(scan: dict, findings: dict[str, Any] | None = None) -> str:
    findings = findings or final_findings(scan)
    counts = findings.get("counts", {})
    recon = scan.get("recon", {}) if isinstance(scan.get("recon"), dict) else {}
    agents = _agents_used(scan)
    program = scan.get("program_profile") if isinstance(scan.get("program_profile"), dict) else {}
    goal = str(scan.get("goal") or "")
    automated = str(
        scan.get("automated_scanning_allowed")
        or program.get("automated_scanning_allowed")
        or "unknown"
    )
    lines = [
        "Scan Finished",
        "",
        f"Target: {redact_text(scan.get('target', ''))}",
    ]
    if goal:
        lines.append(f"Goal: {redact_text(goal)}")
    lines.extend([
        f"Mode: {scan.get('mode', '')}",
        f"Program: {redact_text(program.get('program') or program.get('name') or scan.get('program') or 'not provided')}",
        f"Scanner Permission: {automated}",
        "Agents Used: " + (", ".join(agents) if agents else "none recorded"),
        f"URLs Checked: {len(recon.get('urls', []) or [])}",
        f"Great Findings: {counts.get('great', 0)}",
        f"Needs Manual Check: {counts.get('manual', 0)}",
        f"Rejected Noise: {counts.get('rejected', 0)}",
        "",
    ])
    great = findings.get("great", [])
    manual = findings.get("manual", [])
    if great:
        lines.extend(["Great Findings", "", markdown_table(
            ["#", "Finding", "Rate", "Confidence", "Affected Asset", "Evidence", "Why It Matters", "Next Step"],
            [
                [
                    str(index),
                    item["title"],
                    item["rate"],
                    f"{item['confidence']}%",
                    item["affected_asset"],
                    item["evidence"],
                    item["why_it_matters"],
                    item["next_step"],
                ]
                for index, item in enumerate(great, start=1)
            ],
        ), ""])
    else:
        lines.extend(["No great findings found.", ""])
    if manual:
        lines.extend(["Needs Manual Check", "", markdown_table(
            ["#", "Finding", "Rate", "Confidence", "Affected Asset", "Evidence", "Missing Proof", "Manual Check Needed"],
            [
                [
                    str(index),
                    item["title"],
                    item["rate"],
                    f"{item['confidence']}%",
                    item["affected_asset"],
                    item["evidence"],
                    item["missing_proof"],
                    item["manual_check_needed"],
                ]
                for index, item in enumerate(manual, start=1)
            ],
        ), ""])
    elif not great:
        lines.extend([
            "Manual-check opportunities:",
            "",
            "* Add two authorized test users for access-control comparison.",
            "* Provide authenticated cookies if allowed by the program.",
            "* Re-run in bounty mode only if the program allows active checks.",
            "",
        ])
    lines.extend([
        "Noise Removed:",
        "",
        "* missing-header-only issues",
        "* duplicate findings",
        "* low-confidence guesses",
        "* out-of-scope URLs",
        "* AI-only assumptions",
        "",
        "Best Next Safe Actions:",
        "",
    ])
    for index, action in enumerate(_best_next_actions(scan, great, manual), start=1):
        lines.append(f"{index}. {action}")
    lines.append("")
    lines.append("Technical scan data saved to {}".format(
        _scan_artifact_dir(scan)
    ))
    return "\n".join(lines).rstrip() + "\n"


def _scan_artifact_dir(scan: dict) -> str:
    paths = scan.get("artifact_paths") if isinstance(scan.get("artifact_paths"), dict) else {}
    first = next(iter(paths.values()), "")
    if first:
        return str(Path(first).parent)
    output = scan.get("options", {}).get("output") if isinstance(scan.get("options"), dict) else "scans"
    return str(Path(str(output or "scans")) / str(scan.get("id") or "scan"))


def _best_next_actions(scan: dict, great: list[dict], manual: list[dict]) -> list[str]:
    goal = str(scan.get("goal") or "bounty-hunt")
    actions: list[str] = []
    if any("access" in item.get("bug_type_name", "").lower() or "idor" in item.get("title", "").lower() or "bola" in item.get("title", "").lower() for item in manual):
        actions.append("Add two authorized test users and rerun with access-control goal.")
    if goal != "burp-import-analysis":
        actions.append("Import Burp HTTP history to improve API and business-logic detection.")
    if str(scan.get("automated_scanning_allowed") or "").lower() != "yes":
        actions.append("Run bounty mode only if the program rules allow active checks.")
    elif not great:
        actions.append("Rerun with bounty-hunt goal only within the program rate limits.")
    if not actions:
        actions.append("Manually verify impact using only authorized test data.")
    actions.append("Keep all testing in scope and avoid brute force, DoS, and destructive actions.")
    return list(dict.fromkeys(actions))[:4]


def _agents_used(scan: dict) -> list[str]:
    labels = {
        "scope": "Scope Guardian",
        "recon": "Recon",
        "crawler": "Crawler",
        "javascript": "JS",
        "api": "API",
        "auth": "Auth",
        "access-control": "Access Control",
        "graphql": "GraphQL",
        "upload": "Upload",
        "open-redirect": "Redirect",
        "header": "Header/Cookie",
        "rate-limit": "Rate Limit",
        "proof": "Proof Validator",
        "false-positive-killer": "False Positive Killer",
        "privacy-redactor": "Privacy Redactor",
        "final-findings-presenter": "Final Findings Presenter",
    }
    status = scan.get("agent_status", {})
    if isinstance(status, dict) and status:
        return [labels.get(name, str(name)) for name in status]
    return [
        "Scope Guardian",
        "Recon",
        "Crawler",
        "JS",
        "API",
        "Auth",
        "Access Control",
        "GraphQL",
        "Upload",
        "Redirect",
        "Header/Cookie",
        "Rate Limit",
        "Proof Validator",
        "False Positive Killer",
        "Privacy Redactor",
        "Final Findings Presenter",
    ]
