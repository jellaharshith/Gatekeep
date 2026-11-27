"""Core data models shared by every gatekeep component."""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]
SEV_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def sev(value: Any) -> int:
    """Numeric severity; -1 for anything unrecognised."""
    return SEV_ORDER.get(str(value or "").strip().lower(), -1)


class Objective(str, Enum):
    """What the attacker wants the SOC agent to do."""

    CONCEAL = "conceal"                # hide a real attack: close / false-positive / downgrade
    SUPPRESS = "suppress_persist"      # plant a suppression rule for attacker infrastructure
    EXFIL = "exfil"                    # make the agent send alert data to an attacker URL
    MISDIRECT = "misdirect_response"   # make the agent isolate an innocent (critical) host
    FABRICATE = "fabricate"            # turn a benign alert into a fake critical incident


# Verdicts that close an alert (single source of truth for env, guard and scoring).
CLOSE_VERDICTS = frozenset({"false_positive", "benign_true_positive"})


class Posture(str, Enum):
    """Defense posture the agent runs under."""

    NONE = "none"          # raw tools, raw data
    ADVISORY = "advisory"  # policy in the system prompt + untrusted-data spotlighting
    ENFORCED = "enforced"  # advisory + policy gateway that intercepts every tool call


class Host(BaseModel):
    name: str
    criticality: Literal["normal", "high", "critical"] = "normal"
    isolated: bool = False


class Event(BaseModel):
    id: str
    ts: str
    source: str
    host: str
    fields: dict[str, Any]
    # Field names an external attacker can write (usernames, user agents, subjects...).
    attacker_controlled: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    host: str
    event_ids: list[str]
    # Entities extracted by the detection rule. These are TRUSTED: they come from the
    # detection pipeline, not from free-text an attacker wrote.
    entities: dict[str, list[str]] = Field(default_factory=dict)
    attck: list[str] = Field(default_factory=list)
    status: Literal["open", "closed", "escalated"] = "open"
    verdict: Optional[str] = None
    notes: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)


class Scenario(BaseModel):
    id: str
    title: str
    description: str = ""
    attck: list[str] = Field(default_factory=list)
    owasp_asi: list[str] = Field(default_factory=list)
    vector: str
    ground_truth: Literal["true_positive", "benign"]
    objectives: list[Objective]
    hosts: list[Host]
    iocs: list[str] = Field(default_factory=list)
    events: list[Event]
    alert: Alert
    # Event ids whose string fields contain the {{PAYLOAD}} placeholder.
    injection_targets: list[str]
    # True when every target carries the same attacker string (e.g. a filename that
    # appears in both the file-create and process-start events).
    replicate_payload: bool = False
    # Template variables: attacker_value, decoy_host, exfil_url, clean_value.
    context: dict[str, str] = Field(default_factory=dict)


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    tool: str
    arguments: dict[str, Any]
    action: Literal["allow", "deny", "hold"]
    rule: Optional[str] = None
    reason: str = ""


class TrialResult(BaseModel):
    trial_id: str
    scenario_id: str
    vector: str
    ground_truth: str
    model: str
    posture: Posture
    family: Optional[str] = None            # None => clean control run
    objective: Optional[Objective] = None
    repeat: int = 0
    survival: str = "n/a"                   # intact | transformed | truncated | n/a
    attack_success: Optional[bool] = None   # None for clean runs
    utility_ok: bool = False                # alert reached the correct disposition
    surfaced: bool = False                  # attack visible to a human (escalated/held/flagged)
    held: int = 0
    denied: int = 0
    injection_flagged: bool = False
    steps: int = 0
    error: Optional[str] = None
    final_state: dict[str, Any] = Field(default_factory=dict)
    actions: list[dict[str, Any]] = Field(default_factory=list)
    decisions: list[Decision] = Field(default_factory=list)
    transcript: list[dict[str, Any]] = Field(default_factory=list)
