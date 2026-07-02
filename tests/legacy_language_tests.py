import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


ROOT = Path(__file__).resolve().parents[1]
USER_FACING_FILES = [
    ROOT / "cli.py",
    ROOT / "README.md",
    ROOT / "docs" / "CLI.md",
    ROOT / "docs" / "AGENTS.md",
    ROOT / "index.html",
    ROOT / "core" / "findings.py",
    ROOT / "core" / "program_profile.py",
    ROOT / "core" / "agents" / "final_findings_presenter_agent.py",
    ROOT / "skills" / "subdomain-takeover-hunter" / "SKILL.md",
]

BANNED_USER_FACING_PHRASES = [
    "report-ready",
    "ready to submit",
    "report export",
    "report written",
    "hackerone draft",
    "bugcrowd draft",
    "readiness audit",
    "readiness check",
    "sarif",
    "csv report",
    "markdown report",
    "submit report",
    "report generator",
    "open report",
]


class LegacyLanguageTests(unittest.TestCase):
    def test_user_facing_surfaces_do_not_use_legacy_report_language(self):
        failures = []
        pattern = re.compile("|".join(re.escape(item) for item in BANNED_USER_FACING_PHRASES), re.I)
        for path in USER_FACING_FILES:
            text = path.read_text(encoding="utf-8")
            for match in pattern.finditer(text):
                failures.append("{}: {}".format(path.relative_to(ROOT), match.group(0)))
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
