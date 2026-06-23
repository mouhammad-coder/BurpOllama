"""Bounded specialist agents used by the core scanner."""

from core.agents.ai_triage_agent import AITriageAgent
from core.agents.ai_advisory_agents import (
    AIHypothesisAgent,
    AIReconRanker,
    AIReportAgent,
    AIStrategyAgent,
)
from core.agents.access_control_agent import AccessControlAgent
from core.agents.auth_agent import AuthAgent
from core.agents.crawler_agent import CrawlerAgent
from core.agents.header_agent import HeaderAgent
from core.agents.hunt_agents import HuntCoordinatorAgent, SPECIALIST_AGENTS
from core.agents.injection_agent import InjectionAgent
from core.agents.javascript_agent import JavaScriptAgent
from core.agents.rate_limit_agent import RateLimitAgent
from core.agents.recon_agent import ReconAgent
from core.agents.report_agent import ReportAgent
from core.agents.xss_agent import XSSAgent

__all__ = [
    "AITriageAgent",
    "AIHypothesisAgent",
    "AIReconRanker",
    "AIReportAgent",
    "AIStrategyAgent",
    "AccessControlAgent",
    "AuthAgent",
    "CrawlerAgent",
    "HeaderAgent",
    "HuntCoordinatorAgent",
    "InjectionAgent",
    "JavaScriptAgent",
    "RateLimitAgent",
    "ReconAgent",
    "ReportAgent",
    "SPECIALIST_AGENTS",
    "XSSAgent",
]
