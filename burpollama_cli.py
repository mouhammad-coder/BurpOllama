#!/usr/bin/env python3
"""BurpOllama terminal command center."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx

from agent_registry import list_agents
from discovery_workflows import aggregate_scope_documents, run_discovery_workflow
from external_tools import tool_status
from technique_memory import TechniqueMemory
from waf_bypass import analyze_waf_differentials
from web3_scanner import audit_solidity_path


VERSION = "3.2"
DEFAULT_API = "http://127.0.0.1:8888"


def _print_json(value) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _banner() -> None:
    print("BurpOllama {}  |  authorized security testing command center".format(VERSION))


async def _api(method: str, path: str, *, base: str, payload: dict | None = None):
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.request(method, base.rstrip("/") + path, json=payload)
        if response.status_code >= 400:
            raise RuntimeError("HTTP {}: {}".format(response.status_code, response.text[:500]))
        return response.json()


async def _run_api_command(args) -> int:
    if args.command == "status":
        _print_json(await _api("GET", "/ready", base=args.api))
        return 0
    if args.command == "scans":
        _print_json(await _api("GET", "/scans", base=args.api))
        return 0
    if args.command == "scan":
        if not args.authorized:
            print("Refusing to scan: pass --authorized only when you own the target or have written permission.", file=sys.stderr)
            return 2
        payload = {
            "target": args.target,
            "scan_mode": args.mode,
            "authorization_confirmed": True,
        }
        result = await _api("POST", "/scan", base=args.api, payload=payload)
        _print_json(result)
        return 0
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="burpollama", description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--api", default=DEFAULT_API, help="BurpOllama API base URL")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Show backend, AI, database, and scan readiness.")
    sub.add_parser("scans", help="List scans known to the running backend.")
    scan = sub.add_parser("scan", help="Start an authorized scan through the local API.")
    scan.add_argument("target")
    scan.add_argument("--mode", choices=("LIGHT", "BALANCED", "DEEP"), default="BALANCED")
    scan.add_argument("--authorized", action="store_true", help="Confirm ownership or written permission.")
    serve = sub.add_parser("serve", help="Run the dashboard and API.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8888)
    serve.add_argument("--reload", action="store_true")
    sub.add_parser("agents", help="List the nine specialist agents.")
    sub.add_parser("tools", help="Show optional external-tool availability.")
    memory = sub.add_parser("memory", help="Inspect persistent technique memory.")
    memory.add_argument("--limit", type=int, default=20)
    scope = sub.add_parser("scope-import", help="Aggregate exported JSON/CSV scope files.")
    scope.add_argument("files", nargs="+")
    discover = sub.add_parser("discover", help="Run a guarded optional-tool discovery workflow.")
    discover.add_argument("workflow", choices=("cloud", "takeover", "secrets", "parameters"))
    discover.add_argument("target")
    discover.add_argument("--authorized", action="store_true")
    discover.add_argument("--intensive", action="store_true")
    web3 = sub.add_parser("web3-audit", help="Run static Solidity candidate checks.")
    web3.add_argument("path")
    waf = sub.add_parser("waf-check", help="Run safe WAF differential checks.")
    waf.add_argument("target")
    waf.add_argument("--authorized", action="store_true")
    waf.add_argument("--intensive", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _banner()
    if args.command == "agents":
        _print_json(list_agents())
        return 0
    if args.command == "tools":
        _print_json(tool_status())
        return 0
    if args.command == "memory":
        memory = TechniqueMemory()
        _print_json({"stats": memory.stats(), "recent": memory.recent(args.limit)})
        return 0
    if args.command == "scope-import":
        documents = [
            (path, Path(path).read_text(encoding="utf-8", errors="replace"))
            for path in args.files
        ]
        _print_json(aggregate_scope_documents(documents))
        return 0
    if args.command == "discover":
        if not args.authorized:
            print("Refusing discovery: pass --authorized only for assets you may test.", file=sys.stderr)
            return 2
        results = asyncio.run(
            run_discovery_workflow(
                args.workflow, args.target, authorized=True,
                intensive_authorized=args.intensive,
            )
        )
        _print_json([result.to_dict() for result in results])
        return 0
    if args.command == "web3-audit":
        _print_json(audit_solidity_path(args.path))
        return 0
    if args.command == "waf-check":
        result = asyncio.run(
            analyze_waf_differentials(
                args.target,
                authorized=args.authorized,
                intensive_authorized=args.intensive,
            )
        )
        _print_json(result)
        return 0 if result.get("ran") else 2
    if args.command == "serve":
        import uvicorn
        uvicorn.run("main:app", host=args.host, port=args.port, reload=args.reload)
        return 0
    try:
        return asyncio.run(_run_api_command(args))
    except (httpx.HTTPError, RuntimeError) as exc:
        print("BurpOllama API error: {}".format(exc), file=sys.stderr)
        print("Start it with: burpollama serve", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
