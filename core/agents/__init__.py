"""Bounded specialist agents used by the core scanner."""

from core.agents.ai_triage_agent import AITriageAgent
from core.agents.ai_advisory_agents import (
    AIHypothesisAgent,
    AIReconRanker,
    AIStrategyAgent,
)
from core.agents.access_control_agent import AccessControlAgent
from core.agents.auth_agent import AuthAgent
from core.agents.crawler_agent import CrawlerAgent
from core.agents.final_findings_presenter_agent import FinalFindingsPresenterAgent
from core.agents.header_agent import HeaderAgent
from core.agents.graphql_agent import GraphQLAgent
from core.agents.hunt_agents import HuntCoordinatorAgent, SPECIALIST_AGENTS
from core.agents.injection_agent import InjectionAgent
from core.agents.javascript_agent import JavaScriptAgent
from core.agents.open_redirect_agent import OpenRedirectAgent
from core.agents.rate_limit_agent import RateLimitAgent
from core.agents.recon_agent import ReconAgent
from core.agents.ssrf_agent import SSRFAgent
from core.agents.upload_agent import UploadAgent
from core.agents.xss_agent import XSSAgent

__all__ = [
    "AITriageAgent",
    "AIHypothesisAgent",
    "AIReconRanker",
    "AIStrategyAgent",
    "AccessControlAgent",
    "AuthAgent",
    "CrawlerAgent",
    "FinalFindingsPresenterAgent",
    "HeaderAgent",
    "GraphQLAgent",
    "HuntCoordinatorAgent",
    "InjectionAgent",
    "JavaScriptAgent",
    "OpenRedirectAgent",
    "RateLimitAgent",
    "ReconAgent",
    "SSRFAgent",
    "UploadAgent",
    "SPECIALIST_AGENTS",
    "XSSAgent",
]
