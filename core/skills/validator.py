"""Validate skill folder structure without crashing on malformed skills."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.skills.loader import SkillLoader, SKILLS_ROOT


REQUIRED_SUBDOMAIN_TAKEOVER_FILES = [
    "SKILL.md",
    "references/safety.md",
    "references/commands.md",
    "references/templates.md",
    "references/proof.md",
    "references/impact.md",
]


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "files": self.files,
        }


class SkillValidator:
    def __init__(self, skills_root: Path | str = SKILLS_ROOT):
        self.skills_root = Path(skills_root)
        self.loader = SkillLoader(skills_root)

    def validate(self, name: str) -> ValidationResult:
        skill_dir = self.skills_root / Path(name).name
        errors: list[str] = []
        warnings: list[str] = []
        files: list[str] = []
        if not skill_dir.exists():
            return ValidationResult(False, ["skill folder missing"], [], [])
        required = ["SKILL.md"]
        if name == "subdomain-takeover-hunter":
            required = REQUIRED_SUBDOMAIN_TAKEOVER_FILES
        for relative in required:
            path = skill_dir / relative
            files.append(relative)
            if not path.exists() or not path.is_file():
                errors.append("missing required file: {}".format(relative))
        try:
            skill_file = skill_dir / "SKILL.md"
            if skill_file.exists():
                raw = skill_file.read_text(encoding="utf-8", errors="replace")
                if raw.startswith("---") and raw.find("\n---", 3) == -1:
                    errors.append("malformed frontmatter: missing closing ---")
            skill = self.loader.load(name)
            if not skill.name:
                errors.append("missing skill name")
            if not skill.description:
                warnings.append("missing description metadata")
            for reference in skill.references:
                if not (skill_dir / reference).exists():
                    errors.append("referenced file missing: {}".format(reference))
        except Exception as exc:
            errors.append("{}: {}".format(type(exc).__name__, exc))
        return ValidationResult(not errors, errors, warnings, files)
