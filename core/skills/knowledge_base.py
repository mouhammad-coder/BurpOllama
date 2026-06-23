"""Local cached skill knowledge/fingerprints."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CACHE_ROOT = ROOT / ".burpollama" / "skills"


DEFAULT_TAKEOVER_FINGERPRINTS = {
    "providers": [
        {
            "name": "GitHub Pages",
            "cname_patterns": ["github.io"],
            "http_fingerprints": ["There isn't a GitHub Pages site here."],
            "false_positive_notes": "Custom domain may be protected by domain verification.",
        },
        {
            "name": "Heroku",
            "cname_patterns": ["herokuapp.com", "herokudns.com"],
            "http_fingerprints": ["no such app", "heroku | no such app"],
            "false_positive_notes": "Some Heroku targets require exact app-name validation.",
        },
        {
            "name": "AWS S3",
            "cname_patterns": ["s3.amazonaws.com", "s3-website"],
            "http_fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
            "false_positive_notes": "Bucket naming and region behavior must be verified.",
        },
        {
            "name": "Azure",
            "cname_patterns": ["azurewebsites.net", "cloudapp.net"],
            "http_fingerprints": ["404 Web Site not found"],
            "false_positive_notes": "Azure has service-specific tenant protections.",
        },
        {
            "name": "Fastly",
            "cname_patterns": ["fastly.net"],
            "http_fingerprints": ["Fastly error: unknown domain"],
            "false_positive_notes": "Requires current provider behavior confirmation.",
        },
    ],
    "remediation": [
        "Remove dangling DNS records.",
        "Claim and configure the external resource before pointing DNS at it.",
        "Use provider-side domain verification where available.",
    ],
}


def _skill_reference_file(skill_name: str, relative: str) -> Path:
    return ROOT / "skills" / skill_name / relative


def _load_real_report_corpus(skill_name: str) -> dict[str, Any]:
    path = _skill_reference_file(skill_name, "references/real_reports.json")
    if not path.exists():
        return {}
    try:
        corpus = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    detailed_cases = corpus.get("detailed_cases") or []
    ranked_reports = (
        corpus.get("ranked_hackerone_reports")
        or corpus.get("ranked_h1_reports")
        or []
    )
    resources = corpus.get("curated_resources") or []
    services = Counter(
        str(case.get("service_type") or "").strip()
        for case in detailed_cases
        if str(case.get("service_type") or "").strip()
    )
    top_services = [
        {"service": service, "cases": count}
        for service, count in services.most_common(25)
    ]
    top_reports = [
        {
            "title": report.get("title", ""),
            "url": report.get("url", ""),
            "program": report.get("program", ""),
            "upvotes": report.get("upvotes", 0),
            "bounty": report.get("bounty", 0),
        }
        for report in ranked_reports[:25]
    ]
    return {
        "counts": corpus.get("counts", {}),
        "top_services": top_services,
        "top_ranked_reports": top_reports,
        "curated_resources": resources,
        "source_file": str(path),
    }


class SkillKnowledgeBase:
    def __init__(self, cache_root: Path | str = CACHE_ROOT):
        self.cache_root = Path(cache_root)

    def cache_file(self, skill_name: str) -> Path:
        return self.cache_root / skill_name / "knowledge.json"

    def load(self, skill_name: str) -> tuple[dict[str, Any], bool]:
        path = self.cache_file(skill_name)
        if not path.exists():
            return DEFAULT_TAKEOVER_FINGERPRINTS.copy(), False
        try:
            return json.loads(path.read_text(encoding="utf-8")), True
        except (OSError, json.JSONDecodeError):
            return DEFAULT_TAKEOVER_FINGERPRINTS.copy(), False

    def refresh(self, skill_name: str) -> Path:
        path = self.cache_file(skill_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        real_reports = _load_real_report_corpus(skill_name)
        data = {
            **DEFAULT_TAKEOVER_FINGERPRINTS,
            "skill": skill_name,
            "refreshed_at": datetime.now(timezone.utc).isoformat(),
            "source": (
                "bundled safe fingerprints + local disclosed-report corpus; "
                "no live reference download"
            ),
            "real_report_corpus": real_reports,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path
