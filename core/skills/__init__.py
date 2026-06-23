"""Modular CLI-only skill system for BurpOllama."""

from core.skills.loader import Skill, SkillLoader
from core.skills.registry import SkillRegistry

__all__ = ["Skill", "SkillLoader", "SkillRegistry"]
