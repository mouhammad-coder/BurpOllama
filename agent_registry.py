"""Specialist agent registry used by the CLI and orchestration layers.

Agents are capability profiles, not autonomous shell executors.  Every active
operation remains subject to BurpOllama's scope, authorization, and request
budget controls.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AgentProfile:
    name: str
    role: str
    capabilities: tuple[str, ...]
    phase: str
    active_testing: bool = False
    requires_authorization: bool = True

    def to_dict(self) -> dict:
        data = asdict(self)
        data["capabilities"] = list(self.capabilities)
        return data


AGENTS = (
    AgentProfile(
        "recon-agent", "Maps reachable assets and application attack surface.",
        ("subdomains", "live-hosts", "crawl", "javascript", "technology"), "recon",
    ),
    AgentProfile(
        "recon-ranker", "Ranks URLs and assets by likely security value.",
        ("risk-ranking", "coverage-gaps", "endpoint-priority"), "planning",
    ),
    AgentProfile(
        "credential-hunter", "Finds and validates exposed credentials safely.",
        ("secret-discovery", "redaction", "non-destructive-validation"), "hunt",
        active_testing=True,
    ),
    AgentProfile(
        "token-auditor", "Reviews JWT, OAuth, session, and token boundaries.",
        ("jwt", "oauth", "sessions", "token-storage"), "hunt", active_testing=True,
    ),
    AgentProfile(
        "validator", "Replays evidence and separates candidates from proven bugs.",
        ("proof-gates", "false-positive-elimination", "scope-check"), "validation",
        active_testing=True,
    ),
    AgentProfile(
        "chain-builder", "Connects validated weaknesses into impact chains.",
        ("attack-graph", "exploit-chains", "impact-scoring"), "analysis",
    ),
    AgentProfile(
        "report-writer", "Produces reproducible, platform-ready reports.",
        ("hackerone", "bugcrowd", "executive-report", "cvss-4"), "reporting",
        requires_authorization=False,
    ),
    AgentProfile(
        "web3-auditor", "Performs isolated static smart-contract analysis.",
        ("solidity", "access-control", "reentrancy", "token-risk"), "web3",
        requires_authorization=False,
    ),
    AgentProfile(
        "autopilot", "Coordinates bounded phases using durable working memory.",
        ("planning", "budgets", "resume", "loop-detection"), "orchestration",
    ),
)


def list_agents() -> list[dict]:
    return [agent.to_dict() for agent in AGENTS]


def get_agent(name: str) -> AgentProfile | None:
    normalized = str(name or "").strip().lower()
    return next((agent for agent in AGENTS if agent.name == normalized), None)

