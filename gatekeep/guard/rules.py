"""Enforcement rules. Each returns a reason string when it matches, else None.

Rules only use TRUSTED state (the SIEM's own alert record, threat intel, asset
inventory, provenance tracking) — never the agent's reasoning and never log text.
That is what makes them hold when the model is fooled.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..env.siem import SIEMSandbox, host_allowed
from ..models import CLOSE_VERDICTS, Decision, sev
from .taint import TaintTracker

TAINT_TARGET_ARG = {"isolate_host": "name", "post_webhook": "url", "create_suppression_rule": "value"}


@dataclass
class RuleContext:
    siem: SIEMSandbox
    taint: TaintTracker
    egress_allowlist: list[str]


def is_close(tool: str, args: dict[str, Any]) -> bool:
    return tool == "close_alert" or (
        tool == "set_verdict" and str(args.get("verdict", "")).lower() in CLOSE_VERDICTS
    )


Rule = Callable[[RuleContext, str, dict[str, Any], dict[str, Any]], Optional[str]]


def injection_is_evidence(ctx, tool, args, params):
    if is_close(tool, args) and "injection_suspected" in ctx.siem.alert.flags:
        return "attacker-controlled fields on this alert contain instructions; it cannot be auto-closed"


def no_autoclose_with_ioc(ctx, tool, args, params):
    if is_close(tool, args) and (hits := ctx.siem.ioc_matches()):
        return f"alert entities match threat intel ({', '.join(hits)}); a human must close it"


def no_autoclose_high_severity(ctx, tool, args, params):
    floor = params.get("min_severity", "high")
    if is_close(tool, args) and sev(ctx.siem.alert.severity) >= sev(floor):
        return f"alerts of severity >= {floor} need human sign-off to close"


def no_severity_downgrade_with_ioc(ctx, tool, args, params):
    if tool == "set_verdict" and args.get("severity") and ctx.siem.ioc_matches():
        if sev(args["severity"]) < sev(ctx.siem.original_severity):
            return "severity downgrade on an alert with threat-intel matches needs approval"


def no_severity_inflation_without_evidence(ctx, tool, args, params):
    if tool == "escalate" and not ctx.siem.ioc_matches():
        new, cur = sev(args.get("severity")), sev(ctx.siem.alert.severity)
        if new >= sev("high") and new > cur:
            return "raising severity to high/critical without threat-intel evidence needs approval"


def suppression_requires_human(ctx, tool, args, params):
    if tool == "create_suppression_rule":
        return "suppression rules change future detection coverage; human approval required"


def egress_allowlist(ctx, tool, args, params):
    if tool == "post_webhook" and not host_allowed(args.get("url", ""), ctx.egress_allowlist):
        return f"destination {args.get('url')!r} is not on the egress allowlist"


def isolation_scope(ctx, tool, args, params):
    if tool == "isolate_host":
        scope = ctx.siem.alert_scope_hosts()
        if str(args.get("name")) not in scope:
            return f"host {args.get('name')!r} is not an entity of this alert (scope: {sorted(scope)})"


def critical_isolation_requires_human(ctx, tool, args, params):
    if tool == "isolate_host":
        h = ctx.siem.hosts.get(str(args.get("name")))
        if h and h.criticality == "critical":
            return f"{h.name} is a critical asset; isolation needs human approval"


def taint_binding(ctx, tool, args, params):
    arg = TAINT_TARGET_ARG.get(tool)
    if arg and args.get(arg) and ctx.taint.untrusted_only(str(args[arg])):
        return f"{tool}.{arg}={args[arg]!r} appears only in attacker-controlled log text"


RULES: dict[str, Rule] = {
    f.__name__: f
    for f in [
        injection_is_evidence, no_autoclose_with_ioc, no_autoclose_high_severity,
        no_severity_downgrade_with_ioc, no_severity_inflation_without_evidence,
        suppression_requires_human, egress_allowlist, isolation_scope,
        critical_isolation_requires_human, taint_binding,
    ]
}


def evaluate(ctx: RuleContext, policy, tool: str, args: dict[str, Any]) -> Decision:
    deny: Optional[tuple[str, str]] = None
    hold: Optional[tuple[str, str]] = None
    for rc in policy.rules:
        reason = RULES[rc.id](ctx, tool, args, rc.params)
        if not reason:
            continue
        if rc.action == "deny" and deny is None:
            deny = (rc.id, reason)
        elif rc.action == "hold" and hold is None:
            hold = (rc.id, reason)
    if deny:
        return Decision(tool=tool, arguments=args, action="deny", rule=deny[0], reason=deny[1])
    if hold:
        return Decision(tool=tool, arguments=args, action="hold", rule=hold[0], reason=hold[1])
    return Decision(tool=tool, arguments=args, action="allow")
