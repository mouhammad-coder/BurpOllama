"""Skill registry abstraction."""

from __future__ import annotations

from pathlib import Path

from core.skills.loader import Skill, SkillLoader, SKILLS_ROOT


class SkillRegistry:
    def __init__(self, skills_root: Path | str = SKILLS_ROOT):
        self.loader = SkillLoader(skills_root)

    def list(self) -> list[Skill]:
        skills = []
        for name in self.loader.list_names():
            try:
                skills.append(self.loader.load(name))
            except Exception:
                continue
        return skills

    def get(self, name: str) -> Skill:
        return self.loader.load(name)
