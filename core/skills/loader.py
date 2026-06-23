"""Load Markdown-backed BurpOllama skills safely from disk."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SKILLS_ROOT = ROOT / "skills"


@dataclass
class Skill:
    name: str
    path: Path
    markdown: str
    metadata: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)

    @property
    def description(self) -> str:
        return str(self.metadata.get("description") or "").strip()

    @property
    def purpose(self) -> str:
        match = re.search(
            r"(?ims)^##\s+Purpose\s*(.*?)(?:^##\s+|\Z)",
            self.markdown,
        )
        if match:
            return " ".join(match.group(1).strip().split())
        return self.description

    @property
    def supported_modes(self) -> list[str]:
        if self.name == "subdomain-takeover-hunter":
            return ["passive", "validate", "report"]
        return ["passive"]

    @property
    def required_inputs(self) -> list[str]:
        if self.name == "subdomain-takeover-hunter":
            return [
                "target domain",
                "scope confirmation",
                "authorization confirmation",
                "active probing permission for validate mode",
                "explicit proof-of-control permission if proof is requested",
            ]
        return ["target", "authorization confirmation"]

    @property
    def safety_summary(self) -> str:
        match = re.search(
            r"(?ims)^##\s+Hard Safety Rules.*?\n(.*?)(?:^##\s+|\Z)",
            self.markdown,
        )
        if match:
            lines = [
                line.strip("- ").strip()
                for line in match.group(1).splitlines()
                if line.strip().startswith("-")
            ]
            return " ".join(lines[:5])
        return "Run only against authorized, in-scope targets."


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    raw = text[3:end].strip()
    body = text[end + 4 :].lstrip()
    metadata: dict[str, Any] = {}
    current_key = ""
    for line in raw.splitlines():
        if not line.strip():
            continue
        if line.startswith("- ") and current_key:
            metadata.setdefault(current_key, []).append(line[2:].strip())
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current_key = key.strip()
            value = value.strip()
            metadata[current_key] = [] if value == "" else value
    return metadata, body


def _references_from_markdown(text: str) -> list[str]:
    refs = sorted(set(re.findall(r"references/[A-Za-z0-9_.-]+\.md", text)))
    return refs


class SkillLoader:
    def __init__(self, skills_root: Path | str = SKILLS_ROOT):
        self.skills_root = Path(skills_root)

    def list_names(self) -> list[str]:
        if not self.skills_root.exists():
            return []
        return sorted(
            path.name
            for path in self.skills_root.iterdir()
            if path.is_dir() and (path / "SKILL.md").exists()
        )

    def load(self, name: str) -> Skill:
        safe_name = Path(name).name
        skill_dir = self.skills_root / safe_name
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            raise FileNotFoundError("Skill not found: {}".format(name))
        markdown = skill_file.read_text(encoding="utf-8", errors="replace")
        metadata, body = _parse_frontmatter(markdown)
        skill_name = str(metadata.get("name") or safe_name)
        references = _references_from_markdown(markdown)
        return Skill(
            name=skill_name,
            path=skill_dir,
            markdown=body,
            metadata=metadata,
            references=references,
        )
