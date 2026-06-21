"""h1_bugcrowd_reports.py

Submission-quality report generators for HackerOne and Bugcrowd.

    generate_h1_report(finding: dict)       -> str   # Markdown, H1 triager style
    generate_bugcrowd_report(finding: dict) -> str   # Markdown, Bugcrowd VRT style

Both consume the SAME finding dict:
    title, vulnerability_class, affected_url, method, parameter,
    severity, confidence, exploitability_status, evidence,
    reproduction_steps, business_impact, technical_impact,
    remediation, cwe, cvss_plus_plus

Design goal: land P1/P2 / Critical-High, not Informative. That means:
  - Lead with plain-English impact a non-security PM understands.
  - Make severity defensible against the platform's own rubric.
  - Reproduction steps a non-technical triager can copy-paste and follow.
  - Evidence in fenced code blocks (triagers skim; raw req/resp builds trust).
  - Map to the platform taxonomy the triager expects (CWE/CVSS for H1, VRT for BC).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ===========================================================================
# SHARED HELPERS
# ===========================================================================

# HackerOne severity rubric anchors (CVSS-aligned bands H1 triagers use).
_H1_SEVERITY_BANDS = {
    "critical": ("Critical", "9.0 – 10.0"),
    "high": ("High", "7.0 – 8.9"),
    "medium": ("Medium", "4.0 – 6.9"),
    "low": ("Low", "0.1 – 3.9"),
    "none": ("None", "0.0"),
    "informational": ("None", "0.0"),
}

# Plain-English consequence templates keyed by vuln class. Used to build the
# executive summary so it reads like impact, not jargon.
_PLAIN_IMPACT = {
    "sql injection": (
        "an attacker can read and potentially modify the application's entire "
        "database — including other users' personal data and credentials — "
        "simply by tampering with a value in the web address"
    ),
    "sqli": (
        "an attacker can read and potentially modify the application's entire "
        "database, including other users' personal data and credentials"
    ),
    "idor": (
        "any logged-in user can view and act on other people's private records "
        "just by changing an ID number in the request — no special access needed"
    ),
    "broken access control": (
        "users can reach data and actions that should be restricted to other "
        "people or to administrators"
    ),
    "xss": (
        "an attacker can run their own code inside another user's browser "
        "session, letting them hijack accounts and steal data shown on the page"
    ),
    "stored xss": (
        "an attacker can plant malicious code that runs automatically in the "
        "browser of every user who views the affected page, enabling mass "
        "account takeover"
    ),
    "ssrf": (
        "an attacker can make the server send requests on their behalf, reaching "
        "internal systems and cloud metadata that are normally unreachable from "
        "the outside"
    ),
    "rce": (
        "an attacker can execute arbitrary commands on the server, giving them "
        "full control of the system and the data it holds"
    ),
    "authentication bypass": (
        "an attacker can get into accounts without valid credentials, "
        "completely defeating the login protection"
    ),
}

# Bugcrowd VRT mapping: vuln class -> (VRT category path, typical priority).
# Priority is P1 (Critical) .. P5 (Informational). These are the common,
# defensible default ratings used by Bugcrowd's VRT.
_BUGCROWD_VRT = {
    "sql injection": ("Server-Side Injection > SQL Injection", "P1"),
    "sqli": ("Server-Side Injection > SQL Injection", "P1"),
    "rce": ("Server Security Misconfiguration > Remote Code Execution (RCE)", "P1"),
    "ssrf": ("Server-Side Injection > Server-Side Request Forgery (SSRF) > Internal", "P2"),
    "stored xss": ("Cross-Site Scripting (XSS) > Stored > Privileged User to No Privilege(s)", "P2"),
    "xss": ("Cross-Site Scripting (XSS) > Reflected", "P3"),
    "idor": ("Broken Access Control (BAC) > Insecure Direct Object References (IDOR)", "P2"),
    "broken access control": ("Broken Access Control (BAC)", "P2"),
    "authentication bypass": ("Broken Authentication and Session Management > Authentication Bypass", "P1"),
}

# Map our internal severity word -> Bugcrowd priority when no VRT class matches.
_SEVERITY_TO_PRIORITY = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "none": "P5",
    "informational": "P5",
}


def _get(finding: Dict[str, Any], key: str, default: str = "") -> str:
    """Safe string fetch with trimming."""
    val = finding.get(key, default)
    if val is None:
        return default
    return str(val).strip()


def _norm_class(finding: Dict[str, Any]) -> str:
    return _get(finding, "vulnerability_class").lower().strip()


def _plain_impact(finding: Dict[str, Any]) -> str:
    """Return a plain-English impact clause for the executive summary."""
    cls = _norm_class(finding)
    # Try exact, then substring match (e.g. "Blind SQL Injection" -> "sql injection").
    if cls in _PLAIN_IMPACT:
        return _PLAIN_IMPACT[cls]
    for key, text in _PLAIN_IMPACT.items():
        if key in cls:
            return text
    # Fall back to the supplied business_impact, else a generic clause.
    bi = _get(finding, "business_impact")
    if bi:
        return bi[0].lower() + bi[1:] if bi else bi
    return (
        "an attacker can abuse this weakness to compromise the security of the "
        "application and its users"
    )


def _normalize_steps(finding: Dict[str, Any]) -> List[str]:
    """Coerce reproduction_steps (list or newline string) into a clean list."""
    steps = finding.get("reproduction_steps", [])
    if isinstance(steps, str):
        raw = re.split(r"\r?\n", steps)
    elif isinstance(steps, (list, tuple)):
        raw = list(steps)
    else:
        raw = [str(steps)]
    cleaned: List[str] = []
    for s in raw:
        s = str(s).strip()
        if not s:
            continue
        # Strip any pre-existing numbering ("1.", "1)", "Step 1:") for clean re-numbering.
        s = re.sub(r"^\s*(step\s*)?\d+\s*[\.\):-]\s*", "", s, flags=re.I)
        cleaned.append(s)
    return cleaned


def _format_evidence(finding: Dict[str, Any]) -> str:
    """Render evidence as fenced code block(s). Handles dict/list/str shapes."""
    ev = finding.get("evidence")
    if ev is None or ev == "":
        return "_No raw evidence supplied._"

    blocks: List[str] = []
    if isinstance(ev, dict):
        # Prefer recognised request/response keys; render the rest as key: value.
        req = ev.get("request") or ev.get("raw_request")
        resp = ev.get("response") or ev.get("raw_response")
        if req:
            blocks.append("**Request**\n```http\n" + str(req).strip() + "\n```")
        if resp:
            blocks.append("**Response (excerpt)**\n```http\n" + str(resp).strip() + "\n```")
        leftover = {
            k: v for k, v in ev.items()
            if k not in {"request", "raw_request", "response", "raw_response"}
        }
        if leftover:
            kv = "\n".join(f"{k}: {v}" for k, v in leftover.items())
            blocks.append("**Details**\n```\n" + kv + "\n```")
    elif isinstance(ev, (list, tuple)):
        joined = "\n".join(str(x) for x in ev)
        blocks.append("```\n" + joined.strip() + "\n```")
    else:
        blocks.append("```\n" + str(ev).strip() + "\n```")

    return "\n\n".join(blocks) if blocks else "_No raw evidence supplied._"


def _cvss_line(finding: Dict[str, Any]) -> str:
    cvss = _get(finding, "cvss_plus_plus")
    return cvss if cvss else "Not provided"


def _confidence_note(finding: Dict[str, Any]) -> str:
    """Translate confidence + exploitability_status into a trust statement."""
    conf = finding.get("confidence")
    status = _get(finding, "exploitability_status") or "confirmed"
    try:
        conf_i = int(float(conf))
    except (TypeError, ValueError):
        conf_i = None
    if conf_i is not None:
        return f"{status.capitalize()} (detection confidence {conf_i}/100)"
    return status.capitalize()


# ===========================================================================
# HACKERONE REPORT
# ===========================================================================
def generate_h1_report(finding: Dict[str, Any]) -> str:
    """Generate a HackerOne-ready Markdown report from a finding dict.

    The structure follows what H1 triagers reward: executive summary first,
    explicit severity justification against the H1 rubric, copy-pasteable
    reproduction steps, fenced evidence, business+technical impact, and
    remediation with references.
    """
    title = _get(finding, "title") or "Security Vulnerability"
    vclass = _get(finding, "vulnerability_class") or "Vulnerability"
    url = _get(finding, "affected_url")
    method = _get(finding, "method") or "GET"
    param = _get(finding, "parameter")
    severity_word = _get(finding, "severity").lower() or "high"
    band_label, band_range = _H1_SEVERITY_BANDS.get(
        severity_word, ("High", "7.0 – 8.9")
    )
    cwe = _get(finding, "cwe")
    plain = _plain_impact(finding)
    steps = _normalize_steps(finding)
    evidence_md = _format_evidence(finding)

    # ---- Header -----------------------------------------------------------
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(
        f"**Vulnerability type:** {vclass}  |  "
        f"**Severity:** {band_label} ({band_range})  |  "
        f"**Weakness:** {cwe or 'N/A'}"
    )
    if url:
        lines.append(f"**Asset:** `{method} {url}`" + (f"  |  **Parameter:** `{param}`" if param else ""))
    lines.append("")

    # ---- 1. Executive summary (plain English) -----------------------------
    lines.append("## Summary")
    lines.append(
        f"The `{param or 'affected'}` "
        f"{'parameter' if param else 'input'} on `{url or 'the target endpoint'}` "
        f"is vulnerable to **{vclass}**. In plain terms, {plain}. "
        "This is a directly exploitable, remotely reachable issue that affects the "
        "confidentiality and/or integrity of real user data, and it requires no "
        "unusual preconditions to trigger."
    )
    lines.append("")

    # ---- 2. Severity justification (H1 rubric) ----------------------------
    lines.append("## Severity Justification")
    lines.append(
        f"Per the **HackerOne severity rubric (CVSS-aligned)**, this report is rated "
        f"**{band_label} ({band_range})**."
    )
    lines.append("")
    lines.append(f"- **CVSS / vector:** `{_cvss_line(finding)}`")
    lines.append(f"- **Evidence strength:** {_confidence_note(finding)}")
    if _get(finding, "technical_impact"):
        lines.append(f"- **Technical impact:** {_get(finding, 'technical_impact')}")
    lines.append(
        "- **Rationale:** the combination of attacker capability, the sensitivity "
        "of the affected data, and the low privilege required to exploit places "
        f"this squarely in the {band_label} band rather than a lower tier."
    )
    lines.append("")

    # ---- 3. Reproduction steps (non-technical) ----------------------------
    lines.append("## Steps to Reproduce")
    lines.append("_These steps can be followed exactly as written, in order:_")
    lines.append("")
    if steps:
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
    else:
        # Build a sane default sequence from the finding metadata.
        lines.append(f"1. Open the target URL: `{url or '<affected URL>'}`.")
        lines.append(
            f"2. Send a `{method}` request and modify the `{param or '<parameter>'}` "
            "value as shown in the Evidence section below."
        )
        lines.append("3. Observe the application's response demonstrating the vulnerability.")
    lines.append("")

    # ---- 4. Evidence (code block) -----------------------------------------
    lines.append("## Evidence / Proof of Concept")
    lines.append(evidence_md)
    lines.append("")

    # ---- 5. Business impact (what an attacker can do) ---------------------
    lines.append("## Impact")
    bi = _get(finding, "business_impact")
    if bi:
        lines.append(bi)
    else:
        lines.append(
            f"By exploiting this issue, {plain}. "
            "An attacker could leverage it to harm real users and the business."
        )
    lines.append("")
    lines.append(
        "**What this means for users and the company:**"
    )
    lines.append(
        "- Real users' private data can be exposed or manipulated without their consent."
    )
    lines.append(
        "- The company faces potential data-breach disclosure obligations, regulatory "
        "exposure (e.g. GDPR/CCPA), and reputational damage."
    )
    lines.append(
        "- Depending on chaining, the issue may enable account takeover or deeper "
        "compromise of the platform."
    )
    lines.append("")

    # ---- 6. Remediation (with references) ---------------------------------
    lines.append("## Remediation")
    remediation = _get(finding, "remediation")
    if remediation:
        lines.append(remediation)
    else:
        lines.append(
            "Apply secure-coding controls appropriate to the vulnerability class "
            "(input validation, output encoding, parameterised queries, and "
            "server-side authorization checks)."
        )
    lines.append("")
    lines.append("**References:**")
    for ref in _references(finding):
        lines.append(f"- {ref}")
    lines.append("")

    lines.append("---")
    lines.append(
        "_Reported in good faith under the program's disclosure policy. Happy to "
        "provide a live walkthrough or additional PoC on request._"
    )

    return "\n".join(lines)


# ===========================================================================
# BUGCROWD REPORT
# ===========================================================================
def generate_bugcrowd_report(finding: Dict[str, Any]) -> str:
    """Generate a Bugcrowd-ready Markdown report using VRT taxonomy.

    Bugcrowd triagers expect: a VRT category, a priority (P1–P5), a tight
    summary, deterministic repro steps, raw evidence, and impact phrased in
    terms of risk to the program. We surface the VRT mapping explicitly so the
    triager doesn't have to guess our intended rating.
    """
    title = _get(finding, "title") or "Security Vulnerability"
    vclass = _get(finding, "vulnerability_class") or "Vulnerability"
    url = _get(finding, "affected_url")
    method = _get(finding, "method") or "GET"
    param = _get(finding, "parameter")
    severity_word = _get(finding, "severity").lower() or "high"
    cwe = _get(finding, "cwe")
    plain = _plain_impact(finding)
    steps = _normalize_steps(finding)
    evidence_md = _format_evidence(finding)

    # ---- VRT resolution ---------------------------------------------------
    cls = _norm_class(finding)
    vrt_category, vrt_priority = None, None
    if cls in _BUGCROWD_VRT:
        vrt_category, vrt_priority = _BUGCROWD_VRT[cls]
    else:
        for key, (cat, pri) in _BUGCROWD_VRT.items():
            if key in cls:
                vrt_category, vrt_priority = cat, pri
                break
    if vrt_category is None:
        vrt_category = f"{vclass} (closest VRT match)"
        vrt_priority = _SEVERITY_TO_PRIORITY.get(severity_word, "P3")

    priority_label = {
        "P1": "P1 — Critical",
        "P2": "P2 — High",
        "P3": "P3 — Medium",
        "P4": "P4 — Low",
        "P5": "P5 — Informational",
    }.get(vrt_priority, vrt_priority)

    lines: List[str] = []

    # ---- Title + VRT header ----------------------------------------------
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Bug Title:** {title}")
    lines.append(f"**VRT Category:** {vrt_category}")
    lines.append(f"**Priority:** {priority_label}")
    lines.append(f"**CWE:** {cwe or 'N/A'}")
    if _get(finding, 'cvss_plus_plus'):
        lines.append(f"**CVSS:** `{_cvss_line(finding)}`")
    if url:
        lines.append(f"**Affected URL / Endpoint:** `{method} {url}`")
    if param:
        lines.append(f"**Affected Parameter:** `{param}`")
    lines.append("")

    # ---- Summary ----------------------------------------------------------
    lines.append("## Summary")
    lines.append(
        f"The endpoint `{url or 'the target'}` is vulnerable to **{vclass}** via the "
        f"`{param or 'affected'}` "
        f"{'parameter' if param else 'input'}. In practical terms, {plain}. "
        "The issue is remotely exploitable and maps cleanly to the VRT category above."
    )
    lines.append("")

    # ---- Priority / VRT justification ------------------------------------
    lines.append("## Priority & VRT Justification")
    lines.append(
        f"This maps to **{vrt_category}**, which Bugcrowd's VRT rates at "
        f"**{priority_label}**."
    )
    lines.append(f"- **Detection status:** {_confidence_note(finding)}")
    if _get(finding, "technical_impact"):
        lines.append(f"- **Technical impact:** {_get(finding, 'technical_impact')}")
    lines.append(
        "- **Why this priority holds:** the demonstrated attacker capability and "
        "affected data sensitivity match the VRT baseline for this category; the "
        "PoC below removes any ambiguity about exploitability."
    )
    lines.append("")

    # ---- Steps to reproduce ----------------------------------------------
    lines.append("## Steps to Reproduce")
    if steps:
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
    else:
        lines.append(f"1. Navigate to `{url or '<affected URL>'}`.")
        lines.append(
            f"2. Issue a `{method}` request, manipulating `{param or '<parameter>'}` "
            "per the PoC below."
        )
        lines.append("3. Observe the vulnerable behaviour in the response.")
    lines.append("")

    # ---- PoC / Evidence ---------------------------------------------------
    lines.append("## Proof of Concept")
    lines.append(evidence_md)
    lines.append("")

    # ---- Impact -----------------------------------------------------------
    lines.append("## Impact")
    bi = _get(finding, "business_impact")
    lines.append(bi if bi else f"By exploiting this issue, {plain}.")
    lines.append("")
    lines.append(
        "For the program specifically, this exposes real customer data and/or "
        "platform integrity, creating breach-disclosure, regulatory, and trust risk."
    )
    lines.append("")

    # ---- Remediation ------------------------------------------------------
    lines.append("## Remediation")
    remediation = _get(finding, "remediation")
    lines.append(
        remediation if remediation else
        "Implement the standard secure-coding controls for this vulnerability class "
        "(parameterised queries, server-side authorization, output encoding)."
    )
    lines.append("")
    lines.append("**References:**")
    for ref in _references(finding):
        lines.append(f"- {ref}")

    return "\n".join(lines)


# ===========================================================================
# REFERENCE BUILDER (OWASP / CWE / CVE)
# ===========================================================================
_OWASP_LINKS = {
    "sql injection": "OWASP: SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    "sqli": "OWASP: SQL Injection Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    "xss": "OWASP: Cross Site Scripting Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "stored xss": "OWASP: Cross Site Scripting Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "idor": "OWASP: Insecure Direct Object Reference Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    "broken access control": "OWASP Top 10 A01:2021 — Broken Access Control — https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "ssrf": "OWASP: Server Side Request Forgery Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    "rce": "OWASP: Code Injection — https://owasp.org/www-community/attacks/Code_Injection",
    "authentication bypass": "OWASP: Authentication Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
}


def _references(finding: Dict[str, Any]) -> List[str]:
    """Build a reference list from CWE + class-specific OWASP guidance."""
    refs: List[str] = []
    cwe = _get(finding, "cwe")
    if cwe:
        num = re.search(r"(\d+)", cwe)
        if num:
            refs.append(
                f"{cwe} — https://cwe.mitre.org/data/definitions/{num.group(1)}.html"
            )
        else:
            refs.append(cwe)

    cls = _norm_class(finding)
    owasp = _OWASP_LINKS.get(cls)
    if not owasp:
        for key, link in _OWASP_LINKS.items():
            if key in cls:
                owasp = link
                break
    if owasp:
        refs.append(owasp)

    refs.append("OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/")
    return refs


# ===========================================================================
# SELF-TEST
# ===========================================================================
if __name__ == "__main__":
    sample = {
        "title": "Unauthenticated SQL Injection in product search exposes full user database",
        "vulnerability_class": "SQL Injection",
        "affected_url": "https://shop.example.com/api/v2/search?q=phone",
        "method": "GET",
        "parameter": "q",
        "severity": "critical",
        "confidence": 98,
        "exploitability_status": "confirmed",
        "evidence": {
            "request": "GET /api/v2/search?q=phone'+UNION+SELECT+username,password+FROM+users--+- HTTP/1.1\nHost: shop.example.com",
            "response": "HTTP/1.1 200 OK\n\n[{\"name\":\"admin\",\"detail\":\"$2b$12$...hash...\"}]",
            "dbms": "MySQL",
        },
        "reproduction_steps": [
            "Log out so you are an anonymous, unauthenticated visitor.",
            "Open the search URL: https://shop.example.com/api/v2/search?q=phone",
            "Replace the q value with: phone' UNION SELECT username,password FROM users-- -",
            "Send the request and observe usernames and password hashes returned in the JSON response.",
        ],
        "business_impact": "An attacker with no account can dump every customer's email and password hash, enabling mass account takeover and a reportable data breach.",
        "technical_impact": "Full read access to the application database via UNION-based injection; likely write access via stacked queries.",
        "remediation": "Replace the concatenated query with parameterised statements (prepared statements). Apply least-privilege DB credentials and a WAF as defence-in-depth.",
        "cwe": "CWE-89",
        "cvss_plus_plus": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
    }

    h1 = generate_h1_report(sample)
    bc = generate_bugcrowd_report(sample)
    print("=" * 70)
    print("HACKERONE REPORT")
    print("=" * 70)
    print(h1)
    print()
    print("=" * 70)
    print("BUGCROWD REPORT")
    print("=" * 70)
    print(bc)

    # Minimal structural assertions.
    assert "## Summary" in h1 and "## Severity Justification" in h1
    assert "Steps to Reproduce" in h1 and "```" in h1
    assert "VRT Category" in bc and "Priority" in bc
    assert "P1" in bc  # critical -> P1
    print("\n[self-test OK]")
