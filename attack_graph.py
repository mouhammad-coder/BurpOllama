"""
attack_graph.py — Directed Attack Graph Engine
Correlates individual findings into exploit chains, builds a directed
attack graph, calculates compound path severity, and prioritises by
exploitability rather than raw per-finding severity.

Architecture:
  Node  = a finding (vuln_type, url, severity)
  Edge  = a directed exploit dependency (A enables B, A → B)
  Path  = ordered sequence of nodes from initial access to impact
  Score = compound CVSS-like score weighted by chain depth and impact

Commercial equivalents: Nucleus Security attack paths, Pentera chains,
XM Cyber attack graph.
"""

from __future__ import annotations

import json
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ── CVSS numeric mapping ──────────────────────────────────────────────────────
SEV_SCORE = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "INFO":     0.5,
}

# ── Exploit chain rules ───────────────────────────────────────────────────────
# Each rule: (prerequisite_vuln_pattern, enables_vuln_pattern, multiplier, description)
# Pattern matching is case-insensitive substring.
CHAIN_RULES: List[Tuple[str, str, float, str]] = [
    # Open Redirect → OAuth token theft
    ("open redirect",      "oauth",           1.8,  "Open redirect enables OAuth token theft"),
    ("open redirect",      "session",         1.9,  "Open redirect can expose a token and enable session hijack"),
    # XSS → session hijack
    ("xss",                "session",         1.9,  "XSS enables session cookie theft"),
    # XSS → CSRF bypass
    ("xss",                "csrf",            1.6,  "XSS bypasses CSRF protections"),
    # SSRF → internal IDOR
    ("ssrf",               "idor",            2.0,  "SSRF pivots to internal IDOR endpoints"),
    # SSRF → cloud metadata → credential dump
    ("ssrf",               "aws",             2.5,  "SSRF + cloud metadata = credential dump"),
    # IDOR → mass data exfiltration
    ("idor",               "data exfil",      1.7,  "IDOR enables bulk data exfiltration"),
    ("idor",               "privilege",       2.2,  "IDOR enables privilege escalation and admin access"),
    # Auth bypass → admin IDOR
    ("auth bypass",        "idor",            2.2,  "Auth bypass unlocks admin IDOR"),
    # Auth bypass → RCE
    ("auth bypass",        "rce",             2.8,  "Auth bypass → admin panel → RCE"),
    # JWT alg:none → full auth bypass
    ("jwt alg:none",       "auth bypass",     2.9,  "JWT alg:none grants unauthenticated access"),
    # SQLi → credential dump
    ("sql injection",      "credential",      2.3,  "SQLi enables credential exfiltration"),
    ("sql injection",      "auth bypass",     2.4,  "SQLi enables authentication bypass and account takeover"),
    # SQLi → SSRF (out-of-band)
    ("sql injection",      "oob",             1.5,  "Blind SQLi enables OOB data channel"),
    # Subdomain takeover → phishing / XSS
    ("subdomain takeover", "xss",             1.6,  "Takeover enables stored XSS on subdomain"),
    # SSTI → RCE
    ("ssti",               "rce",             2.7,  "SSTI is a direct path to RCE"),
    # XXE → SSRF
    ("xxe",                "ssrf",            1.8,  "XXE enables blind SSRF via external entities"),
    # CORS wildcard → XSS chain
    ("cors",               "xss",             1.4,  "CORS misconfiguration amplifies XSS impact"),
    # Path traversal → file read → source code disclosure
    ("path traversal",     "source",          1.6,  "Path traversal enables source code disclosure"),
    # Prototype pollution → XSS
    ("prototype pollution","xss",             1.7,  "Prototype pollution enables XSS"),
    # Request smuggling → cache poisoning
    ("request smuggling",  "cache poisoning", 1.9,  "HTTP desync enables cache poisoning"),
    # Cache poisoning → reflected XSS delivery
    ("cache poisoning",    "xss",             1.8,  "Cached XSS payload delivered to all users"),
    # Mass assignment → privilege escalation
    ("mass assignment",    "privilege",       2.0,  "Mass assignment enables role escalation"),
    # File upload → RCE
    ("file upload",        "rce",             2.5,  "Unrestricted upload enables code execution"),
    # Race condition → payment fraud
    ("race condition",     "business logic",  1.8,  "Race condition exploits business logic"),
    # Missing rate limit → brute force
    ("rate limit",         "credential",      1.5,  "No rate limit enables credential stuffing"),
    # GraphQL introspection → IDOR
    ("graphql introspection","idor",          1.3,  "Schema disclosure enables targeted IDOR"),
    ("api exposure",       "sensitive",       1.6,  "Exposed API reveals a sensitive endpoint"),
    ("sensitive endpoint", "data exfil",      1.8,  "Sensitive endpoint enables unauthorized data extraction"),
]


@dataclass
class AttackNode:
    finding_id:  str
    vuln_type:   str
    severity:    str
    url:         str
    confidence:  int
    cvss:        float
    source:      str = ""
    verdict:     str = "PASS"
    exploitability_status: str = "candidate"
    evidence_strength: str = "weak"

    @property
    def base_score(self) -> float:
        return SEV_SCORE.get(self.severity.upper(), 0.0) * (self.confidence / 100)


@dataclass
class AttackEdge:
    from_id:     str
    to_id:       str
    multiplier:  float
    description: str


@dataclass
class AttackPath:
    nodes:       List[AttackNode]
    edges:       List[AttackEdge]
    path_score:  float
    impact:      str
    summary:     str
    chain_label: str = "hypothesis_chain"


class AttackGraph:
    """
    Directed graph where nodes are vulnerability findings and edges represent
    exploit dependencies. Calculates compound attack path scores using
    multiplicative chaining to model real attacker progression.
    """

    def __init__(self):
        self._nodes:     Dict[str, AttackNode] = {}
        self._edges:     List[AttackEdge]      = []
        self._adj:       Dict[str, List[str]]  = defaultdict(list)  # from_id → [to_id]
        self._rev_adj:   Dict[str, List[str]]  = defaultdict(list)  # to_id → [from_id]
        self._paths:     List[AttackPath]      = []
        self._ato_chains: List[dict]           = []
        self._built:     bool                  = False

    def add_ato_chains(self, chains: List[dict]):
        """Attach pre-correlated account-takeover impact chains."""
        self._ato_chains = [dict(chain) for chain in (chains or [])]

    # ── Construction ─────────────────────────────────────────────────────────

    def add_findings(self, findings: List[dict]):
        """Ingest a list of triage-passed findings as graph nodes."""
        for f in findings:
            if f.get("verdict") not in ("PASS", "DOWNGRADE", "CONFIRMED"):
                continue
            node = AttackNode(
                finding_id = f.get("id", ""),
                vuln_type  = f.get("vuln_type", ""),
                severity   = f.get("severity", "LOW"),
                url        = f.get("url", ""),
                confidence = f.get("confidence", 50),
                cvss       = float(f.get("cvss", 0.0)),
                source     = f.get("source", ""),
                verdict    = f.get("verdict", "PASS"),
                exploitability_status = f.get("exploitability_status", "candidate"),
                evidence_strength = f.get("evidence_strength", "weak"),
            )
            self._nodes[node.finding_id] = node
        self._built = False

    def _matches(self, text: str, pattern: str) -> bool:
        return pattern.lower() in text.lower()

    def build_edges(self):
        """
        Apply chain rules to draw edges between compatible nodes.
        Two nodes on different URLs but same host are still connectable.
        """
        nodes = list(self._nodes.values())
        for i, src in enumerate(nodes):
            for j, dst in enumerate(nodes):
                if i == j:
                    continue
                for prereq, enables, mult, desc in CHAIN_RULES:
                    if (self._matches(src.vuln_type, prereq) and
                            self._matches(dst.vuln_type, enables)):
                        edge = AttackEdge(
                            from_id     = src.finding_id,
                            to_id       = dst.finding_id,
                            multiplier  = mult,
                            description = desc,
                        )
                        self._edges.append(edge)
                        self._adj[src.finding_id].append(dst.finding_id)
                        self._rev_adj[dst.finding_id].append(src.finding_id)
                        break   # one edge per pair
        self._built = True

    # ── Path discovery ────────────────────────────────────────────────────────

    def _find_paths(self, start_id: str, max_depth: int = 5) -> List[List[str]]:
        """BFS all simple paths from start_id up to max_depth."""
        paths  = []
        queue  = deque([(start_id, [start_id])])
        while queue:
            node_id, path = queue.popleft()
            if len(path) >= max_depth:
                paths.append(path)
                continue
            neighbours = self._adj.get(node_id, [])
            if not neighbours:
                if len(path) > 1:
                    paths.append(path)
                continue
            for nid in neighbours:
                if nid not in path:   # prevent cycles
                    queue.append((nid, path + [nid]))
        return paths

    def _score_path(self, path_ids: List[str]) -> float:
        """
        Compound score = base_score(entry) * product(edge_multipliers) + terminal_score.
        Uses geometric mean to prevent runaway scores on long chains.
        """
        if not path_ids:
            return 0.0
        entry_score = self._nodes[path_ids[0]].base_score
        mult_product = 1.0
        for i in range(len(path_ids) - 1):
            edge = next(
                (e for e in self._edges
                 if e.from_id == path_ids[i] and e.to_id == path_ids[i+1]),
                None
            )
            if edge:
                mult_product *= edge.multiplier
        terminal_score = self._nodes[path_ids[-1]].base_score
        raw = (entry_score * mult_product + terminal_score) / 2
        # Cap at 10.0 and penalise low-confidence chains
        avg_conf = sum(self._nodes[nid].confidence for nid in path_ids) / len(path_ids)
        return min(10.0, raw * (avg_conf / 100))

    def _path_impact(self, terminal_node: AttackNode) -> str:
        vt = terminal_node.vuln_type.lower()
        if any(k in vt for k in ("rce", "command", "exec")):
            return "Remote Code Execution"
        if any(k in vt for k in ("sql injection", "credential")):
            return "Data Exfiltration / Account Takeover"
        if any(k in vt for k in ("auth bypass", "privilege")):
            return "Privilege Escalation"
        if any(k in vt for k in ("ssrf", "metadata")):
            return "Cloud Infrastructure Compromise"
        if any(k in vt for k in ("xss", "session")):
            return "Session Hijacking"
        if any(k in vt for k in ("idor", "bola")):
            return "Unauthorized Data Access"
        return "Security Compromise"

    def _chain_label(self, nodes: List[AttackNode]) -> str:
        statuses = [getattr(n, "exploitability_status", "") for n in nodes]
        strengths = [getattr(n, "evidence_strength", "") for n in nodes]
        if statuses and all(s == "confirmed" for s in statuses) and all(e == "strong" for e in strengths):
            return "confirmed_chain"
        if any(s == "needs_manual_validation" for s in statuses):
            return "needs_manual_validation"
        if any(s in ("candidate", "") for s in statuses):
            return "hypothesis_chain"
        return "candidate_chain"

    def compute_paths(self) -> List[AttackPath]:
        """
        Discover all meaningful attack paths, score them, deduplicate,
        and return sorted by descending compound score.
        """
        if not self._built:
            self.build_edges()

        # Entry nodes: nodes with no incoming edges (initial attack surface)
        all_dst = set(e.to_id for e in self._edges)
        entry_nodes = [nid for nid in self._nodes if nid not in all_dst]
        # If fully connected graph, start from highest-base-score nodes
        if not entry_nodes:
            entry_nodes = sorted(
                self._nodes.keys(),
                key=lambda x: self._nodes[x].base_score,
                reverse=True
            )[:5]

        seen_paths: Set[str] = set()
        attack_paths: List[AttackPath] = []

        for entry in entry_nodes:
            for path_ids in self._find_paths(entry, max_depth=6):
                sig = "→".join(sorted(path_ids))
                if sig in seen_paths:
                    continue
                seen_paths.add(sig)

                nodes_in_path = [self._nodes[nid] for nid in path_ids]
                edges_in_path = [
                    e for e in self._edges
                    if e.from_id in path_ids and e.to_id in path_ids
                ]
                score   = self._score_path(path_ids)
                impact  = self._path_impact(nodes_in_path[-1])
                summary = " → ".join(
                    n.vuln_type.split("—")[0].strip() for n in nodes_in_path
                )
                attack_paths.append(AttackPath(
                    nodes      = nodes_in_path,
                    edges      = edges_in_path,
                    path_score = round(score, 2),
                    impact     = impact,
                    summary    = summary,
                    chain_label= self._chain_label(nodes_in_path),
                ))

        attack_paths.sort(key=lambda p: p.path_score, reverse=True)
        self._paths = attack_paths[:20]   # top 20 paths
        return self._paths

    # ── Output ────────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        if not self._paths:
            self.compute_paths()
        nodes = [
            {
                "id": node.finding_id,
                "type": "finding",
                "vuln_type": node.vuln_type,
                "severity": node.severity,
                "url": node.url,
            }
            for node in self._nodes.values()
        ]
        edges = [
            {
                "from_id": edge.from_id,
                "to_id": edge.to_id,
                "description": edge.description,
                "multiplier": edge.multiplier,
            }
            for edge in self._edges
        ]
        attack_paths = [
            {
                "summary":    p.summary,
                "score":      p.path_score,
                "impact":     p.impact,
                "chain_label":p.chain_label,
                "steps":      len(p.nodes),
                "step_detail": [
                    {"vuln_type": n.vuln_type, "url": n.url,
                     "severity": n.severity, "confidence": n.confidence,
                     "exploitability_status": n.exploitability_status,
                     "evidence_strength": n.evidence_strength}
                    for n in p.nodes
                ],
                "chain_rules": [e.description for e in p.edges],
            }
            for p in self._paths
        ]
        for chain in self._ato_chains:
            chain_id = chain.get("id", "")
            nodes.append({
                "id": chain_id,
                "type": "ato_chain",
                "vuln_type": chain.get("title", "Account Takeover Chain"),
                "severity": chain.get("combined_severity", chain.get("severity", "HIGH")),
                "url": chain.get("affected_url", chain.get("url", "")),
                "chain_status": chain.get("chain_status", "candidate_chain"),
            })
            for finding_id in chain.get("individual_finding_ids", []):
                edges.append({
                    "from_id": finding_id,
                    "to_id": chain_id,
                    "description": "Contributes to account takeover chain",
                    "multiplier": 2.0,
                })
            attack_paths.append({
                "summary": chain.get("title", "Account Takeover Chain"),
                "score": 10.0 if chain.get("combined_severity") == "CRITICAL" else 8.5,
                "impact": "Account Takeover",
                "chain_label": chain.get("chain_status", "candidate_chain"),
                "steps": len(chain.get("steps", [])),
                "step_detail": [{"step": step} for step in chain.get("steps", [])],
                "chain_rules": [chain.get("bounty_note", "")],
                "ato_chain_id": chain_id,
            })
        return {
            "node_count":    len(nodes),
            "edge_count":    len(edges),
            "path_count":    len(attack_paths),
            "nodes":         nodes,
            "edges":         edges,
            "attack_paths":  attack_paths,
            "ato_chains":    self._ato_chains,
            "highest_path_score": max(
                [path.get("score", 0) for path in attack_paths] or [0]
            ),
        }

    def top_entry_points(self, n: int = 5) -> List[AttackNode]:
        """Return the n nodes with highest outbound chain potential."""
        if not self._built:
            self.build_edges()
        scored = []
        for node_id, node in self._nodes.items():
            out_edges = len(self._adj.get(node_id, []))
            potential = node.base_score * (1 + out_edges * 0.3)
            scored.append((potential, node))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [node for _, node in scored[:n]]


# ── Module-level builder function ─────────────────────────────────────────────

def build_attack_graph(findings: List[dict], ato_chains: List[dict] | None = None) -> AttackGraph:
    """Build and compute an attack graph from a list of triage-passed findings."""
    graph = AttackGraph()
    graph.add_findings(findings)
    graph.add_ato_chains(ato_chains or [])
    graph.build_edges()
    graph.compute_paths()
    return graph
