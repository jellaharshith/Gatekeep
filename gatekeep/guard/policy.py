"""Policy file loading."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_POLICY = Path(__file__).parent / "policies" / "default.yaml"


@dataclass
class RuleConfig:
    id: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class Policy:
    name: str
    egress_allowlist: list[str]
    rules: list[RuleConfig]
    spotlight: bool = True
    tripwire: bool = True

    @classmethod
    def load(cls, path: Optional[str | Path] = None) -> "Policy":
        from .rules import RULES  # local import avoids a cycle

        data = yaml.safe_load(Path(path or DEFAULT_POLICY).read_text())
        rules = []
        for r in data.get("rules", []):
            rc = RuleConfig(id=r["id"], action=r.get("action", "deny"), params=r.get("params") or {})
            if rc.id not in RULES:
                raise ValueError(f"unknown rule id in policy: {rc.id}")
            if rc.action not in ("deny", "hold"):
                raise ValueError(f"rule {rc.id}: action must be deny or hold")
            rules.append(rc)
        return cls(
            name=data.get("name", "unnamed"),
            egress_allowlist=[a.lower() for a in data.get("egress_allowlist", [])],
            rules=rules,
            spotlight=bool(data.get("spotlight", True)),
            tripwire=bool(data.get("tripwire", True)),
        )
