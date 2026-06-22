from __future__ import annotations

import logging
from typing import Any

from finding_model import normalize_finding
from deduplication import deduplicate_findings
from fp_eliminator import eliminate_false_positives
from report_quality_scorer import score_finding as score_quality
from impact_scoring_engine import score_finding as score_impact
from scope_policy import ScopePolicy, scope_policy
from validation_enhancements import (
    calculate_cvss_40,
    keep_best_similar,
    rejection_reason_codes,
    report_readiness,
)


READY_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}
READY_EXPLOITABILITY = {"confirmed", "probable"}
READY_EVIDENCE = {"strong", "moderate"}
logger = logging.getLogger(__name__)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _steps_present(value: Any) -> bool:
    if isinstance(value, list):
        return any(_text(step) for step in value)
    return bool(_text(value))


def _with_gate(finding: dict, label: str, failed_checks: list[str]) -> dict:
    out = dict(finding)
    out["zero_fp_label"] = label
    out["zero_fp_failed_checks"] = failed_checks
    return out


def _active_scope_allowed(url: str, policy: ScopePolicy = scope_policy) -> tuple[bool, str]:
    if not _text(url):
        return False, "missing_affected_url"
    allowed, reason = policy.validate_target(url, action="active")
    if allowed:
        return True, ""
    return False, reason or "out_of_scope"


def _failed_ready_checks(finding: dict, policy: ScopePolicy = scope_policy) -> list[str]:
    failed: list[str] = []
    affected_url = _text(finding.get("affected_url") or finding.get("url"))
    severity = _text(finding.get("severity")).upper()
    exploitability = _lower(finding.get("exploitability_status"))
    evidence_strength = _lower(finding.get("evidence_strength"))
    false_positive_risk = _lower(finding.get("false_positive_risk"))

    scope_ok, scope_reason = _active_scope_allowed(affected_url, policy)
    if not scope_ok:
        failed.append(f"scope:{scope_reason}")
    if severity not in READY_SEVERITIES:
        failed.append("severity_not_medium_or_higher")
    if exploitability not in READY_EXPLOITABILITY:
        failed.append("exploitability_not_confirmed_or_probable")
    if evidence_strength not in READY_EVIDENCE:
        failed.append("evidence_not_strong_or_moderate")
    if int(float(finding.get("confidence", 0) or 0)) < 70:
        failed.append("confidence_below_70")
    if not _text(finding.get("business_impact")):
        failed.append("missing_business_impact")
    if not _steps_present(finding.get("reproduction_steps")):
        failed.append("missing_reproduction_steps")
    if not _text(finding.get("remediation")):
        failed.append("missing_remediation")
    if _lower(finding.get("redaction_status")) != "redacted":
        failed.append("unredacted_evidence")
    if false_positive_risk == "high":
        failed.append("high_false_positive_risk")
    if exploitability == "false_positive":
        failed.append("marked_false_positive")
    if exploitability == "candidate" and severity in {"MEDIUM", "LOW", "INFO", "INFORMATIONAL"}:
        failed.append("medium_or_lower_candidate")
    return failed


def apply_zero_fp_gate(
    findings: list[dict],
    scope: dict,
    chain_data: dict | None = None,
    tech_stack: list[str] | None = None,
    scan_context: dict | None = None,
) -> dict:
    policy = scope_policy
    if scope:
        policy = ScopePolicy()
        policy.update(scope, persist=False)
    result = {
        "valid_bugs": [],
        "needs_more_proof": [],
        "candidates": [],
        "informational": [],
        "false_positives_removed": [],
        "skipped_out_of_scope": [],
    }

    deduplicated = deduplicate_findings(findings or [])
    pre_eliminated = [
        finding for finding in deduplicated
        if _lower(finding.get("exploitability_status")) in {
            "false_positive", "not_vulnerable"
        }
        or _text(finding.get("verdict")).upper() == "KILL"
    ]
    eliminator_input = [
        finding for finding in deduplicated
        if finding not in pre_eliminated
    ]
    fp_result = eliminate_false_positives(
        eliminator_input,
        tech_stack or [],
        scan_context or {},
    )
    eliminated = pre_eliminated + fp_result.get("false_positives", [])
    logger.info(
        "FP eliminator removed %d of %d finding(s)",
        len(eliminated),
        len(findings or []),
    )
    result["false_positives_removed"].extend(
        _with_gate(
            normalize_finding(finding),
            "REMOVED",
            ["fp_eliminator:{}".format(finding.get("fp_reason", "rule match"))],
        )
        for finding in eliminated
    )
    gate_findings = (
        fp_result.get("confirmed", [])
        + fp_result.get("candidates", [])
    )

    for raw in gate_findings:
        finding = normalize_finding(raw)
        affected_url = _text(finding.get("affected_url") or finding.get("url"))
        scoring_input = dict(finding)
        scoring_input["_scope_match"] = policy.validate_target(
            affected_url, action="report"
        )[0] if affected_url else False
        quality = score_quality(scoring_input)
        finding["quality_score"] = quality["score"]
        finding["grade"] = quality["grade"]
        finding["quality_grade"] = quality["grade"]
        finding["ready_to_submit"] = quality["ready_to_submit"]
        finding["quality_improvements"] = quality["improvements"]
        finding["quality_blocking_issues"] = quality["blocking_issues"]
        impact = score_impact(finding, chain_data)
        finding["cvss_plus_plus"] = impact["cvss_plus_plus"]
        finding["classification"] = impact["classification"]
        finding["impact_scoring"] = impact
        cvss_40 = calculate_cvss_40(finding)
        finding["cvss_40_score"] = cvss_40["score"]
        finding["cvss_40_vector"] = cvss_40["vector"]
        scope_ok, _scope_reason = _active_scope_allowed(affected_url, policy)
        finding["report_readiness"] = report_readiness(finding, scope_ok)
        finding["rejection_reason_codes"] = rejection_reason_codes(
            finding,
            in_scope=scope_ok,
        )
        failed = _failed_ready_checks(finding, policy)
        if quality["score"] < 70:
            failed.append("quality_score_below_70")
        severity = _text(finding.get("severity")).upper()
        exploitability = _lower(finding.get("exploitability_status"))
        evidence_strength = _lower(finding.get("evidence_strength"))
        false_positive_risk = _lower(finding.get("false_positive_risk"))
        confidence = int(float(finding.get("confidence", 0) or 0))
        verdict = _text(finding.get("verdict")).upper()

        if not scope_ok:
            result["skipped_out_of_scope"].append(_with_gate(finding, "SKIPPED", failed))
        elif verdict == "NEEDS_MANUAL_REVIEW":
            result["needs_more_proof"].append(
                _with_gate(finding, "MANUAL REVIEW", failed)
            )
        elif exploitability == "false_positive" or false_positive_risk == "high":
            result["false_positives_removed"].append(_with_gate(finding, "REMOVED", failed))
        elif not failed:
            label = (
                "READY"
                if finding["report_readiness"]["ready"]
                else "VALID"
            )
            result["valid_bugs"].append(_with_gate(finding, label, []))
        elif severity in {"INFO", "INFORMATIONAL"} or not _text(finding.get("business_impact")):
            result["informational"].append(_with_gate(finding, "INFO", failed))
        elif exploitability == "candidate" or confidence < 70:
            result["candidates"].append(_with_gate(finding, "CANDIDATE", failed))
        elif (
            "exploitability_not_confirmed_or_probable" in failed
            or "evidence_not_strong_or_moderate" in failed
            or evidence_strength not in READY_EVIDENCE
        ):
            result["needs_more_proof"].append(_with_gate(finding, "NEEDS PROOF", failed))
        else:
            result["candidates"].append(_with_gate(finding, "CANDIDATE", failed))

    kept, duplicates = keep_best_similar(result["valid_bugs"])
    result["valid_bugs"] = kept
    result["false_positives_removed"].extend(
        _with_gate(
            duplicate,
            "REMOVED",
            ["duplicate_of:{}".format(duplicate.get("duplicate_of", ""))],
        )
        for duplicate in duplicates
    )

    for bucket in result.values():
        for finding in bucket:
            affected_url = _text(
                finding.get("affected_url") or finding.get("url")
            )
            scope_ok = _active_scope_allowed(affected_url, policy)[0]
            if "cvss_40_score" not in finding:
                cvss_40 = calculate_cvss_40(finding)
                finding["cvss_40_score"] = cvss_40["score"]
                finding["cvss_40_vector"] = cvss_40["vector"]
            finding.setdefault(
                "report_readiness",
                report_readiness(finding, scope_ok),
            )
            finding.setdefault(
                "rejection_reason_codes",
                rejection_reason_codes(
                    finding,
                    in_scope=scope_ok,
                    duplicate=bool(finding.get("duplicate_of")),
                ),
            )
        bucket.sort(
            key=lambda item: (
                float(item.get("cvss_plus_plus", 0) or 0),
                float(item.get("cvss_40_score", 0) or 0),
            ),
            reverse=True,
        )
    return result
