"""Shared trial plumbing: sandbox construction, result assembly, trial ids.

Used by the batch runner and the MCP server so both build and score a trial the same way.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .env.siem import SIEMSandbox
from .guard.gateway import ToolGateway
from .guard.policy import Policy
from .injection.payloads import render
from .injection.vectors import VECTORS
from .models import Objective, Posture, Scenario, TrialResult
from .scenarios.loader import instantiate
from .scoring import attack_succeeded, surfaced, utility_ok


def make_trial_id(scenario_id: str, model: str, posture: Posture, family: Optional[str],
                  objective: Optional[Objective], repeat: int) -> str:
    obj = objective.value if objective else "-"
    return f"{scenario_id}|{model}|{posture.value}|{family or 'clean'}|{obj}|r{repeat}"


@dataclass
class Sandbox:
    instance: Scenario
    survival: str
    siem: SIEMSandbox
    gateway: ToolGateway


def build_sandbox(scenario: Scenario, posture: Posture, policy: Policy,
                  family: Optional[str] = None, objective: Optional[Objective] = None) -> Sandbox:
    fragments = None
    if family:
        if objective is None:
            raise ValueError("--objective is required with --family")
        ctx = {**scenario.context, "alert_id": scenario.alert.id}
        fragments = render(family, objective, ctx, len(scenario.injection_targets),
                           VECTORS[scenario.vector].compact)
    inst, survival = instantiate(scenario, fragments)
    siem = SIEMSandbox(inst, policy.egress_allowlist)
    gateway = ToolGateway(siem, posture, policy)
    return Sandbox(inst, survival, siem, gateway)


def collect_result(sb: Sandbox, scenario: Scenario, *, trial_id: str, model: str, posture: Posture,
                   family: Optional[str], objective: Optional[Objective], repeat: int = 0,
                   steps: int = 0, error: Optional[str] = None,
                   transcript: Optional[list[dict[str, Any]]] = None) -> TrialResult:
    siem, gateway = sb.siem, sb.gateway
    return TrialResult(
        trial_id=trial_id, scenario_id=scenario.id, vector=scenario.vector,
        ground_truth=scenario.ground_truth, model=model, posture=posture, family=family,
        objective=objective, repeat=repeat, survival=sb.survival,
        attack_success=attack_succeeded(objective, siem) if objective else None,
        utility_ok=utility_ok(siem), surfaced=surfaced(siem),
        held=gateway.held, denied=gateway.denied,
        injection_flagged="injection_suspected" in siem.alert.flags,
        steps=steps, error=error, final_state=siem.final_state(), actions=siem.actions,
        decisions=gateway.decisions, transcript=transcript or [],
    )
