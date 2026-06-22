"""
reporter.py — Bug bounty / pentest report generator
Phase 4: Converts triaged findings into a structured Markdown report.
Format compatible with HackerOne, Bugcrowd, and Intigriti submissions.
"""

from datetime import datetime
import csv
import io
import json
from gemini_client import ask_gemini
from security_hardening import escape_markdown_table, safe_code_block
from finding_model import normalize_finding, normalize_findings
from impact_scoring_engine import score_finding as score_impact_finding
from validation_enhancements import calculate_cvss_40, report_readiness


SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SARIF_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}


async def generate_full_report(
    target: str,
    recon_data: dict,
    findings: list[dict],
    analysis: dict,
    api_key: str = "",
    scope: dict = None,
    review_items: list[dict] = None,
) -> str:
    """Generate a full Markdown pentest/bug-bounty report."""

    # Only include PASS and DOWNGRADE verdicts
    findings = normalize_findings(findings)
    reportable = [
        f for f in findings
        if f.get("verdict", "PASS") in ("PASS", "DOWNGRADE")
        and f.get("severity", "INFO") != "INFO"
    ]
    chain_data = analysis.get("exploit_chains") or {}
    for finding in reportable:
        impact_score = score_impact_finding(finding, chain_data)
        finding.setdefault("cvss_plus_plus", impact_score["cvss_plus_plus"])
        finding.setdefault("classification", impact_score["classification"])
        cvss_40 = calculate_cvss_40(finding)
        finding.setdefault("cvss_40_score", cvss_40["score"])
        finding.setdefault("cvss_40_vector", cvss_40["vector"])
        finding.setdefault(
            "cvss_40_severity", cvss_40["cvss_40_severity"]
        )
        finding.setdefault(
            "cvss_40_official", cvss_40["cvss_40_official"]
        )
        finding.setdefault(
            "report_readiness",
            report_readiness(finding, bool(finding.get("_scope_match", True))),
        )
    reportable.sort(
        key=lambda item: (
            float(item.get("cvss_40_score", 0) or 0),
            float(item.get("cvss_plus_plus", 0) or 0),
        ),
        reverse=True,
    )

    # Counts
    counts = {}
    for f in reportable:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # ── Executive Summary via Gemini ──────────────────────────────────────────
    exec_summary = ""
    if api_key and reportable:
        finding_list = "\n".join(
            "- {} {} at {}".format(f["severity"], f["vuln_type"], f["url"])
            for f in reportable[:15]
        )
        exec_summary = await ask_gemini(
            "Write a 3-sentence executive summary for a bug bounty report on target '{}' "
            "with these findings:\n{}\n\nBe concise and professional. No markdown headers.".format(
                target, finding_list
            ),
            api_key=api_key,
        )

    if not exec_summary:
        crit = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        exec_summary = (
            "Security assessment of {} identified {} reportable vulnerabilities "
            "({} Critical, {} High). "
            "Key risks include unauthorized data access, potential account compromise, "
            "and sensitive information disclosure. "
            "Immediate remediation is recommended for all Critical and High severity findings."
        ).format(target, len(reportable), crit, high)

    # ── Build report ──────────────────────────────────────────────────────────
    lines = []

    lines.append("# Security Assessment Report")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append("| **Target** | `{}` |".format(escape_markdown_table(target)))
    lines.append("| **Date** | {} |".format(now))
    lines.append("| **Subdomains Found** | {} |".format(recon_data.get("stats", {}).get("subdomains", 0)))
    lines.append("| **Live Hosts** | {} |".format(recon_data.get("stats", {}).get("live_hosts", 0)))
    lines.append("| **URLs Discovered** | {} |".format(recon_data.get("stats", {}).get("urls", 0)))
    lines.append("| **Total Findings** | {} |".format(len(reportable)))
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts.get(sev, 0) > 0:
            lines.append("| **{}** | {} |".format(sev.capitalize(), counts[sev]))
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(exec_summary)
    lines.append("")

    lines.extend(_scope_block(scope or {}))
    lines.append("## Methodology")
    lines.append("")
    lines.extend(_methodology_lines())
    lines.append("")

    if analysis.get("coverage_v2") or analysis.get("coverage"):
        lines.append("## Coverage")
        lines.append("")
        lines.append("```json")
        lines.append(safe_code_block(json.dumps(analysis.get("coverage_v2") or analysis.get("coverage"), indent=2)))
        lines.append("```")
        lines.append("")

    # Exploit chains
    graph = analysis.get("attack_graph", {})
    if graph:
        lines.append("## Attack Graph")
        lines.append("")
        for path in graph.get("attack_paths", [])[:10]:
            lines.append("- **{}** [{}] score {} - {}".format(
                escape_markdown_table(path.get("summary", "")),
                escape_markdown_table(path.get("chain_label", "")),
                escape_markdown_table(path.get("score", "")),
                escape_markdown_table(path.get("impact", "")),
            ))
        lines.append("")

    chains = analysis.get("chains", [])
    if chains:
        lines.append("## ⛓️ Exploit Chains Identified")
        lines.append("")
        for chain in chains:
            lines.append("### {} [{}]".format(chain.get("name", "Chain"), chain.get("combined_severity", "")))
            lines.append("")
            lines.append(chain.get("description", ""))
            lines.append("")
            lines.append("**Steps:** {}".format(" → ".join(chain.get("steps", []))))
            lines.append("")

    # CVSS 4.0 / CVSS++ impact ranking
    lines.append("## Impact Ranking (CVSS 4.0 and CVSS++)")
    lines.append("")
    lines.append("| Finding | CVSS 4.0 | CVSS++ | Readiness |")
    lines.append("|---------|----------|--------|-----------|")
    for finding in sorted(
        reportable,
        key=lambda item: float(item.get("cvss_40_score", 0) or 0),
        reverse=True,
    ):
        title = finding.get("title") or finding.get("vuln_type") or "Finding"
        lines.append("| {} | {} | {} | {} |".format(
            escape_markdown_table(title),
            escape_markdown_table(finding.get("cvss_40_score", 0)),
            escape_markdown_table(finding.get("cvss_plus_plus", 0)),
            escape_markdown_table(
                finding.get("report_readiness", {}).get("status", "NOT_READY")
            ),
        ))
    lines.append("")

    # Findings
    lines.append("## Vulnerability Findings")
    lines.append("")

    for idx, f in enumerate(reportable, 1):
        sev   = f.get("severity", "INFO")
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        verdict_note = ""
        if f.get("verdict") == "DOWNGRADE":
            orig = f.get("original_severity", "")
            verdict_note = " *(downgraded from {})*".format(orig)

        lines.append("---")
        lines.append("")
        lines.append("### {} Finding #{}: {}{}".format(emoji, idx, f.get("vuln_type", ""), verdict_note))
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        lines.append("| **Severity** | {} |".format(sev))
        lines.append("| **Confidence** | {}% |".format(f.get("confidence", 0)))
        lines.append("| **CWE** | {} |".format(f.get("cwe", "N/A")))
        lines.append("| **CVSS** | {} |".format(f.get("cvss", 0)))
        lines.append("| **CVSS 4.0** | {} |".format(f.get("cvss_40_score", 0)))
        lines.append("| **CVSS 4.0 Severity** | {} |".format(
            escape_markdown_table(f.get("cvss_40_severity", "Unknown"))
        ))
        lines.append("| **CVSS 4.0 Vector** | `{}` |".format(
            escape_markdown_table(f.get("cvss_40_vector", ""))
        ))
        lines.append("| **CVSS++** | {} ({}) |".format(
            f.get("cvss_plus_plus", 0),
            f.get("classification", "Low"),
        ))
        lines.append("| **URL** | `{}` |".format(escape_markdown_table(f.get("url", ""))))
        lines.append("| **Method** | `{}` |".format(escape_markdown_table(f.get("method", ""))))
        lines.append("| **Source** | {} |".format(escape_markdown_table(f.get("source", "auto"))))
        lines.append("| **Report Readiness** | {} |".format(
            escape_markdown_table(
                f.get("report_readiness", {}).get("status", "NOT_READY")
            )
        ))
        if f.get("rejection_reason_codes"):
            lines.append("| **Rejection Codes** | {} |".format(
                escape_markdown_table(", ".join(f.get("rejection_reason_codes", [])))
            ))
        lines.append("")

        lines.append("**Description:**")
        lines.append("")
        lines.append(safe_code_block(f.get("description", "")))
        lines.append("")

        lines.append("**Evidence:**")
        lines.append("```")
        lines.append(safe_code_block(f.get("evidence", "")))
        lines.append("```")
        lines.append("")

        triage = f.get("triage", {})
        impact = triage.get("impact_statement", "")
        if impact:
            lines.append("**Impact:**")
            lines.append("")
            lines.append(impact)
            lines.append("")

        lines.append("**Remediation:**")
        lines.append("")
        lines.append(safe_code_block(f.get("remediation", "")))
        lines.append("")

        chain_hint = triage.get("chain_hint", "")
        if chain_hint:
            lines.append("**Chain Hint:** {}".format(chain_hint))
            lines.append("")

    # Exploit chains
    lines.append("## Exploit Chains")
    lines.append("")
    exploit_chains = chain_data.get("chains", []) if isinstance(chain_data, dict) else []
    if not exploit_chains:
        lines.append("No exploit chains identified in this scan.")
        lines.append("")
    else:
        for chain in exploit_chains:
            lines.append("### {}: {}".format(
                chain.get("id", "CHAIN"),
                chain.get("title", "Exploit chain"),
            ))
            lines.append("")
            lines.append("**Exploitation steps:**")
            lines.append("")
            for index, step in enumerate(chain.get("steps", []), start=1):
                lines.append("{}. {}".format(index, step))
            lines.append("")
            lines.append("**Safe read-only PoC steps:**")
            lines.append("")
            for index, step in enumerate(chain.get("poc_steps", []), start=1):
                lines.append("{}. {}".format(index, step))
            lines.append("")
            lines.append("**Exploitability score:** {}".format(
                chain.get("exploitability_score", 0)
            ))
            lines.append("")

    # Recon summary
    lines.append("---")
    lines.append("")
    lines.append("## Recon Summary")
    lines.append("")
    lines.append("### Live Hosts")
    lines.append("")
    lines.append("| URL | Status | Technologies |")
    lines.append("|---|---|---|")
    for h in recon_data.get("live_hosts", [])[:20]:
        tech = ", ".join(h.get("tech", [])) or "—"
        lines.append("| `{}` | {} | {} |".format(
            escape_markdown_table(h.get("url", "")),
            escape_markdown_table(h.get("status", "")),
            escape_markdown_table(tech)))
    lines.append("")

    # JS findings
    js_findings = recon_data.get("js_findings", [])
    if js_findings:
        lines.append("### JS File Analysis")
        lines.append("")
        lines.append("| Type | File | Evidence |")
        lines.append("|---|---|---|")
        for jf in js_findings[:20]:
            lines.append("| {} | `{}` | `{}` |".format(
                escape_markdown_table(jf.get("type", "")),
                escape_markdown_table(jf.get("file", "")),
                escape_markdown_table(jf.get("evidence", "")[:60])
            ))
        lines.append("")

    # Additional surfaces
    surfaces = analysis.get("additional_surfaces", [])
    if surfaces:
        lines.append("## Recommended Additional Testing")
        lines.append("")
        for s in surfaces:
            lines.append("- {}".format(s))
        lines.append("")

    # Killed findings appendix
    killed = [f for f in findings if f.get("verdict") == "KILL"]
    if killed:
        lines.append("## Appendix A: Killed Findings (Not Reportable)")
        lines.append("")
        lines.append("These findings were flagged by automated scanning but failed the 7-Question Gate.")
        lines.append("")
        for f in killed[:10]:
            reasoning = f.get("triage", {}).get("kill_reason",
                        f.get("triage", {}).get("reasoning", "Failed gate check"))
            lines.append("- **{}** @ `{}` — *{}*".format(
                escape_markdown_table(f.get("vuln_type", "")),
                escape_markdown_table(f.get("url", "")),
                escape_markdown_table(reasoning)
            ))
        lines.append("")

    # AMBIGUOUS_PARSE appendix — findings that failed JSON triage and need human review
    ambiguous = [f for f in findings if f.get("verdict") == "AMBIGUOUS_PARSE"]
    if ambiguous:
        lines.append("## Appendix B: AMBIGUOUS_PARSE Findings (Manual Review Required)")
        lines.append("")
        lines.append(
            "The following {} finding(s) could not be triaged automatically because Gemini "
            "returned unparseable JSON after 3 attempts. These may be valid vulnerabilities. "
            "Use `GET /review` to inspect and resolve them.".format(len(ambiguous))
        )
        lines.append("")
        for f in ambiguous:
            rq_id = f.get("review_queue_id", "unknown")
            lines.append("### ⚠ {} — {}".format(f.get("vuln_type", "Unknown"), f.get("severity", "")))
            lines.append("")
            lines.append("- **URL:** `{}`".format(escape_markdown_table(f.get("url", ""))))
            lines.append("- **Review Queue ID:** `{}`".format(rq_id))
            lines.append("- **Evidence:** {}".format(escape_markdown_table(f.get("evidence", "")[:200])))
            lines.append("- **Description:** {}".format(escape_markdown_table(f.get("description", ""))))
            lines.append("")
            lines.append("**Action:** Run `POST /review/{}/resolve` with your verdict.".format(rq_id))
            lines.append("")

    lines.append("---")
    lines.append("*Report generated by BurpOllama v3.4 — {}*".format(now))

    return "\n".join(lines)


def _split_findings(findings: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    normalized = normalize_findings(findings)
    confirmed = [f for f in normalized if f.get("exploitability_status") == "confirmed"]
    candidates = [f for f in normalized if f.get("exploitability_status") in ("probable", "candidate", "needs_manual_validation")]
    false_pos = [f for f in normalized if f.get("exploitability_status") == "false_positive" or f.get("verdict") == "KILL"]
    return confirmed, candidates, false_pos


def _methodology_lines() -> list[str]:
    return [
        "- Passive Burp traffic analysis with response fingerprinting and deduplication.",
        "- Authorized recon, URL discovery, JavaScript analysis, and API schema ingestion.",
        "- ScopePolicy-gated active testing with rate limits and safety controls.",
        "- ProofGate classification to avoid marking advanced candidates as confirmed without strong evidence.",
        "- AI-assisted triage with privacy redaction and local-first routing.",
        "- Attack graph correlation and coverage analysis.",
    ]


def _scope_block(scope: dict) -> list[str]:
    return [
        "## Scope And Safety",
        "",
        "| Setting | Value |",
        "|---|---|",
        "| Allowed domains | {} |".format(escape_markdown_table(", ".join(scope.get("allowed_domains", [])) or "Not configured")),
        "| Blocked domains | {} |".format(escape_markdown_table(", ".join(scope.get("blocked_domains", [])) or "None")),
        "| Scan mode | {} |".format(escape_markdown_table(scope.get("scan_mode", ""))),
        "| Passive only | {} |".format(scope.get("passive_only_mode", False)),
        "| Active testing | {} |".format(scope.get("active_testing_enabled", False)),
        "| Authenticated testing | {} |".format(scope.get("authenticated_testing_enabled", False)),
        "| OOB testing | {} |".format(scope.get("oob_testing_enabled", False)),
        "| Cloud AI | {} |".format(scope.get("cloud_ai_enabled", False)),
        "| Emergency stop | {} |".format(scope.get("emergency_stop", False)),
        "",
        "**Redaction notice:** Evidence and AI-bound content are redacted for secrets, credentials, tokens, session identifiers, personal data, and secret-looking values where detected.",
        "",
    ]


def generate_executive_report(target: str, recon_data: dict, findings: list[dict],
                              analysis: dict, scope: dict) -> str:
    confirmed, candidates, _ = _split_findings(findings)
    cov = analysis.get("coverage_v2") or analysis.get("coverage") or {}
    graph = analysis.get("attack_graph", {})
    lines = [
        "# Executive Security Report",
        "",
        "| Field | Value |",
        "|---|---|",
        "| Target | `{}` |".format(escape_markdown_table(target)),
        "| Date | {} |".format(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")),
        "| Confirmed findings | {} |".format(len(confirmed)),
        "| Candidate findings | {} |".format(len(candidates)),
        "| Coverage | {}% |".format(cov.get("coverage_percent", 0)),
        "| Attack paths | {} |".format(graph.get("path_count", 0)),
        "",
    ]
    lines.extend(_scope_block(scope))
    lines.extend(["## Business Impact", ""])
    if confirmed:
        for f in confirmed[:10]:
            lines.append("- **{}**: {}".format(escape_markdown_table(f.get("title", "")),
                                               escape_markdown_table(f.get("business_impact") or f.get("technical_impact", ""))))
    else:
        lines.append("No confirmed vulnerabilities currently meet the ProofGate threshold.")
    lines.extend(["", "## Candidate Risk", ""])
    lines.append("{} candidate or manually validated findings require analyst review before reporting as confirmed.".format(len(candidates)))
    lines.extend(["", "## Recommended Next Actions", "",
                  "- Review high-risk untested URLs from coverage v2.",
                  "- Manually validate candidate findings using safe validation steps.",
                  "- Remediate confirmed findings first, then probable/candidate classes by business exposure."])
    return "\n".join(lines)


def generate_technical_report(target: str, recon_data: dict, findings: list[dict],
                              analysis: dict, scope: dict, review_items: list[dict] = None) -> str:
    confirmed, candidates, false_pos = _split_findings(findings)
    cov = analysis.get("coverage_v2") or analysis.get("coverage") or {}
    graph = analysis.get("attack_graph", {})
    lines = ["# Technical Security Report", ""]
    lines.extend(_scope_block(scope))
    lines.extend(["## Methodology", ""])
    lines.extend(_methodology_lines())
    lines.extend(["", "## Tested Assets", ""])
    assets = cov.get("tested_assets") or [h.get("url", "") for h in recon_data.get("live_hosts", [])[:25]]
    lines.extend("- `{}`".format(escape_markdown_table(a)) for a in assets[:50])
    lines.extend(["", "## Coverage", "", "```json", safe_code_block(json.dumps(cov, indent=2)), "```", ""])
    lines.extend(["## Attack Graph", "", "```json", safe_code_block(json.dumps(graph, indent=2)), "```", ""])

    def section(title: str, rows: list[dict]):
        lines.extend(["## " + title, ""])
        if not rows:
            lines.append("None.")
            lines.append("")
            return
        for f in rows:
            lines.extend([
                "### {} [{}]".format(escape_markdown_table(f.get("title", "")), escape_markdown_table(f.get("severity", ""))),
                "",
                "- **Status:** {}".format(escape_markdown_table(f.get("exploitability_status", ""))),
                "- **Evidence strength:** {}".format(escape_markdown_table(f.get("evidence_strength", ""))),
                "- **False positive risk:** {}".format(escape_markdown_table(f.get("false_positive_risk", ""))),
                "- **URL:** `{}`".format(escape_markdown_table(f.get("affected_url", ""))),
                "- **CWE:** {}".format(escape_markdown_table(f.get("cwe", ""))),
                "- **OWASP Top 10:** {}".format(escape_markdown_table(f.get("owasp_top_10", ""))),
                "",
                "**Technical impact:**",
                "",
                safe_code_block(f.get("technical_impact", "")),
                "",
                "**Evidence:**",
                "```",
                safe_code_block(f.get("evidence", "")),
                "```",
                "",
                "**Safe manual validation:**",
            ])
            for step in f.get("safe_manual_validation_steps", []) or []:
                lines.append("- {}".format(escape_markdown_table(step)))
            lines.extend(["", "**Remediation:**", "", safe_code_block(f.get("remediation", "")), ""])

    section("Confirmed Findings", confirmed)
    section("Candidate Findings", candidates)
    section("False Positives / Killed Findings", false_pos)
    lines.extend(["## Review Appendix", ""])
    for item in review_items or []:
        lines.append("- `{}` {} {} - {}".format(
            escape_markdown_table(item.get("id", "")),
            escape_markdown_table(item.get("severity", "")),
            escape_markdown_table(item.get("vuln_type", "")),
            escape_markdown_table(item.get("status", "")),
        ))
    return "\n".join(lines)


def generate_json_report(target: str, recon_data: dict, findings: list[dict],
                         analysis: dict, scope: dict, review_items: list[dict] = None) -> dict:
    confirmed, candidates, false_pos = _split_findings(findings)
    for finding in confirmed + candidates + false_pos:
        cvss_40 = calculate_cvss_40(finding)
        finding.setdefault("cvss_40_score", cvss_40["score"])
        finding.setdefault("cvss_40_vector", cvss_40["vector"])
        finding.setdefault("cvss_40_severity", cvss_40["cvss_40_severity"])
        finding.setdefault("cvss_40_official", cvss_40["cvss_40_official"])
    return {
        "target": target,
        "generated_at": datetime.utcnow().isoformat(),
        "scope": scope,
        "methodology": _methodology_lines(),
        "tested_assets": (analysis.get("coverage_v2") or {}).get("tested_assets", []),
        "coverage": analysis.get("coverage_v2") or analysis.get("coverage") or {},
        "attack_graph": analysis.get("attack_graph", {}),
        "confirmed_findings": confirmed,
        "candidate_findings": candidates,
        "false_positive_findings": false_pos,
        "review_appendix": review_items or [],
        "redaction_notice": "Evidence is redacted for credentials, tokens, session identifiers, personal data, and secret-looking values where detected.",
    }


def generate_csv_report(findings: list[dict]) -> str:
    rows = normalize_findings(findings)
    output = io.StringIO()
    fields = [
        "id", "scan_id", "title", "vulnerability_class", "affected_url", "method",
        "parameter", "severity", "confidence", "exploitability_status",
        "evidence_strength", "false_positive_risk", "cwe", "owasp_top_10",
        "cvss_40_score", "cvss_40_vector", "cvss_40_severity",
        "cvss_40_official", "cvss_plus_plus",
        "quality_score", "ready_to_submit", "duplicate_of",
        "rejection_reason_codes", "raw_evidence_id", "redaction_status",
        "created_at", "updated_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        export_row = dict(row)
        cvss_40 = calculate_cvss_40(export_row)
        export_row.setdefault("cvss_40_score", cvss_40["score"])
        export_row.setdefault("cvss_40_vector", cvss_40["vector"])
        export_row.setdefault(
            "cvss_40_severity", cvss_40["cvss_40_severity"]
        )
        export_row.setdefault(
            "cvss_40_official", cvss_40["cvss_40_official"]
        )
        if isinstance(export_row.get("rejection_reason_codes"), list):
            export_row["rejection_reason_codes"] = ",".join(
                export_row["rejection_reason_codes"]
            )
        export_row["ready_to_submit"] = bool(
            export_row.get("report_readiness", {}).get("ready")
            or export_row.get("ready_to_submit")
        )
        writer.writerow(export_row)
    return output.getvalue()


def generate_sarif_report(
    target: str,
    findings: list[dict],
    *,
    tool_version: str = "3.2",
) -> dict:
    """Generate a SARIF 2.1.0 report for CI and GitHub code scanning."""
    rows = normalize_findings(findings)
    reportable = [
        row for row in rows
        if row.get("verdict", "PASS") in ("PASS", "DOWNGRADE", "CONFIRMED")
        and row.get("severity", "INFO") != "INFO"
    ]
    rules = {}
    results = []
    for finding in reportable:
        rule_id = str(
            finding.get("cwe")
            or finding.get("vulnerability_class")
            or finding.get("vuln_type")
            or "BURPOLLAMA-FINDING"
        ).strip().replace(" ", "-").upper()
        title = finding.get("title") or finding.get("vuln_type") or rule_id
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": str(title)[:200],
            "shortDescription": {"text": str(title)[:500]},
            "fullDescription": {
                "text": str(
                    finding.get("description")
                    or finding.get("technical_impact")
                    or title
                )[:2000]
            },
            "help": {
                "text": str(finding.get("remediation") or "Review and remediate the validated security finding.")[:4000],
            },
            "properties": {
                "tags": list(filter(None, [
                    "security",
                    str(finding.get("cwe", "")),
                    str(finding.get("owasp_top_10", "")),
                ])),
                "security-severity": str(
                    finding.get("cvss_40_score")
                    or finding.get("cvss")
                    or 0
                ),
            },
        })
        affected = finding.get("affected_url") or finding.get("url") or target
        result = {
            "ruleId": rule_id,
            "level": SARIF_LEVELS.get(
                str(finding.get("severity", "INFO")).upper(),
                "warning",
            ),
            "message": {
                "text": "{}: {}".format(
                    title,
                    finding.get("business_impact")
                    or finding.get("technical_impact")
                    or finding.get("description")
                    or "Validated security finding.",
                )[:4000],
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(affected)},
                },
                "logicalLocations": [{
                    "name": str(finding.get("parameter") or finding.get("method") or "request"),
                    "kind": "web-request",
                }],
            }],
            "partialFingerprints": {
                "burpollamaFindingId": str(finding.get("id", "")),
                "burpollamaEvidenceId": str(finding.get("raw_evidence_id", "")),
            },
            "properties": {
                "severity": finding.get("severity", "INFO"),
                "confidence": finding.get("confidence", 0),
                "exploitability_status": finding.get("exploitability_status", ""),
                "evidence_strength": finding.get("evidence_strength", ""),
                "report_readiness": finding.get("report_readiness", {}).get(
                    "status", "NOT_READY"
                ),
            },
        }
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BurpOllama",
                    "version": tool_version,
                    "informationUri": "https://github.com/mouhammad-coder/BurpOllama",
                    "rules": list(rules.values()),
                }
            },
            "automationDetails": {"id": "BurpOllama/{}".format(target)},
            "results": results,
        }],
    }


def generate_submission(finding: dict) -> str:
    """Generate a single HackerOne/Bugcrowd-ready submission for one finding."""
    finding = normalize_finding(finding)
    sev   = finding.get("severity", "")
    vtype = finding.get("vuln_type", "")
    url   = finding.get("url", "")
    triage = finding.get("triage", {})

    lines = []
    lines.append("## Summary")
    lines.append("")
    lines.append("{} was found at `{}`.".format(
        escape_markdown_table(vtype), escape_markdown_table(url)))
    lines.append("")
    lines.append("## Description")
    lines.append("")
    lines.append(safe_code_block(finding.get("description", "")))
    lines.append("")
    lines.append("## Steps to Reproduce")
    lines.append("")
    lines.append("1. Send the following request:")
    lines.append("```")
    lines.append("{} {}".format(finding.get("method", "GET"), escape_markdown_table(url)))
    lines.append("```")
    lines.append("")
    lines.append("2. Observe the following in the response:")
    lines.append("```")
    lines.append(safe_code_block(finding.get("evidence", "")))
    lines.append("```")
    lines.append("")
    lines.append("## Impact")
    lines.append("")
    lines.append(safe_code_block(triage.get("impact_statement", finding.get("description", ""))))
    lines.append("")
    lines.append("## Suggested Fix")
    lines.append("")
    lines.append(safe_code_block(finding.get("remediation", "")))
    lines.append("")
    lines.append("## Severity")
    lines.append("")
    lines.append("**{}** — CWE: {} / CVSS: {}".format(sev, finding.get("cwe", ""), finding.get("cvss", 0)))

    return "\n".join(lines)
