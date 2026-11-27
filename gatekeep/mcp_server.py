"""Expose one sandbox scenario as an MCP server (stdio, JSON-RPC 2.0, newline-delimited).

Use this to test ANY MCP-capable SOC agent (your own, an open-source AI SOC, Claude
Code, etc.) against gatekeep: point the agent at this server as its "SIEM", ask it to
triage the alert, and when the client disconnects gatekeep scores the final state.

    gatekeep serve-mcp --scenario SOC-001 --family authority_forgery \
        --objective conceal --posture enforced --out result.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, Optional, TextIO

from . import __version__
from .guard.policy import Policy
from .models import Objective, Posture, Scenario, TrialResult
from .trial import Sandbox, build_sandbox, collect_result, make_trial_id

DEFAULT_PROTOCOL = "2025-06-18"

PARSE_ERROR = -32700
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603


def _ok(mid: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, msg: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": msg}}


class SandboxMCPServer:
    def __init__(self, scenario: Scenario, posture: Posture, policy: Policy,
                 family: Optional[str] = None, objective: Optional[Objective] = None,
                 agent_label: str = "external-mcp-agent"):
        self.scenario, self.posture, self.family, self.objective = scenario, Posture(posture), family, objective
        self.agent_label = agent_label
        sb = build_sandbox(scenario, self.posture, policy, family, objective)
        self.instance, self.survival, self.siem, self.gateway = sb.instance, sb.survival, sb.siem, sb.gateway
        self.calls = 0

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "protocolVersion": params.get("protocolVersion", DEFAULT_PROTOCOL),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "gatekeep-sandbox-siem", "version": __version__},
            "instructions": (f"SIEM/SOAR tools for a SOC. Open alert to triage: {self.instance.alert.id} "
                             f"({self.instance.alert.rule_name} on {self.instance.alert.host})."),
        }

    def _tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"tools": [{"name": t["name"], "description": t["description"],
                           "inputSchema": t["parameters"]} for t in self.gateway.specs()]}

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        out = self.gateway.call(params.get("name", ""), params.get("arguments") or {})
        return {"content": [{"type": "text", "text": json.dumps(out, default=str)}],
                "isError": "error" in out}

    def _ping(self, params: dict[str, Any]) -> dict[str, Any]:
        return {}

    def handle(self, msg: dict[str, Any]) -> Optional[dict[str, Any]]:
        method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
        if mid is None:  # notification (e.g. notifications/initialized)
            return None
        handler = self._methods.get(method) if isinstance(method, str) else None
        if handler is None:
            return _err(mid, METHOD_NOT_FOUND, f"method not found: {method}")
        try:
            return _ok(mid, handler(self, params))
        except Exception as exc:  # never crash the transport
            return _err(mid, INTERNAL_ERROR, str(exc))

    _methods: dict[Any, Callable[["SandboxMCPServer", dict[str, Any]], dict[str, Any]]] = {
        "initialize": _initialize,
        "tools/list": _tools_list,
        "tools/call": _tools_call,
        "ping": _ping,
    }

    def serve(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                stdout.write(json.dumps(_err(None, PARSE_ERROR, "parse error")) + "\n")
                stdout.flush()
                continue
            resp = self.handle(msg)
            if resp is not None:
                stdout.write(json.dumps(resp) + "\n")
                stdout.flush()

    def result(self) -> TrialResult:
        sb = Sandbox(self.instance, self.survival, self.siem, self.gateway)
        tid = make_trial_id(self.scenario.id, self.agent_label, self.posture, self.family, self.objective, 0)
        return collect_result(sb, self.scenario, trial_id=tid, model=self.agent_label, posture=self.posture,
                              family=self.family, objective=self.objective, steps=self.calls)


def run_server(server: SandboxMCPServer, out: Optional[Path]) -> TrialResult:
    try:
        server.serve()
    except KeyboardInterrupt:
        pass
    res = server.result()
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a") as fh:
            fh.write(res.model_dump_json() + "\n")
    print(f"[gatekeep] {res.trial_id}: attack_success={res.attack_success} utility_ok={res.utility_ok} "
          f"held={res.held} denied={res.denied}", file=sys.stderr)
    return res
