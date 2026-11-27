"""Load scenario YAML and instantiate it with (or without) an injected payload."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

import yaml

from ..injection.vectors import apply_vector
from ..models import Scenario

PLACEHOLDER = "{{PAYLOAD}}"
_SURVIVAL_RANK = {"n/a": -1, "intact": 0, "transformed": 1, "truncated": 2}


def corpus_dir() -> Path:
    return Path(__file__).parent / "corpus"


def load_scenarios(paths: Optional[Iterable[str | Path]] = None,
                   ids: Optional[Iterable[str]] = None) -> list[Scenario]:
    """Load scenarios from YAML files/directories (default: the built-in corpus)."""
    files: list[Path] = []
    for p in (paths or [corpus_dir()]):
        p = Path(p)
        files.extend(sorted(p.glob("*.yaml")) if p.is_dir() else [p])
    scenarios = [Scenario.model_validate(yaml.safe_load(f.read_text())) for f in files]
    wanted = {i.strip() for i in ids} if ids else None
    if wanted:
        scenarios = [s for s in scenarios if s.id in wanted]
    _validate(scenarios)
    return scenarios


def _validate(scenarios: list[Scenario]) -> None:
    seen = set()
    for s in scenarios:
        if s.id in seen:
            raise ValueError(f"duplicate scenario id {s.id}")
        seen.add(s.id)
        ids = {e.id for e in s.events}
        missing = [t for t in s.injection_targets if t not in ids]
        if missing:
            raise ValueError(f"{s.id}: injection targets not found: {missing}")
        for t in s.injection_targets:
            ev = next(e for e in s.events if e.id == t)
            if not any(PLACEHOLDER in str(v) for v in ev.fields.values()):
                raise ValueError(f"{s.id}: event {t} has no {PLACEHOLDER} placeholder")
        for key in ("clean_value",):
            if key not in s.context:
                raise ValueError(f"{s.id}: context.{key} is required")


def _substitute(value, text: str):
    if isinstance(value, str):
        return value.replace(PLACEHOLDER, text)
    if isinstance(value, list):
        return [_substitute(v, text) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v, text) for k, v in value.items()}
    return value


def instantiate(scenario: Scenario, fragments: Optional[list[str]] = None) -> tuple[Scenario, str]:
    """Return (scenario copy with placeholders filled, survival).

    fragments=None produces the clean control version (placeholder -> clean_value).
    Fragment i goes into injection target i; leftover targets get the clean value.
    Each fragment is mangled by the scenario's vector before insertion.
    """
    inst = scenario.model_copy(deep=True)
    clean = scenario.context["clean_value"]
    survival = "n/a"
    targets = inst.injection_targets
    by_id = {e.id: e for e in inst.events}
    if fragments and len(fragments) == 1 and scenario.replicate_payload:
        fragments = fragments * len(targets)
    for idx, ev_id in enumerate(targets):
        if fragments and idx < len(fragments):
            text, surv = apply_vector(scenario.vector, fragments[idx])
            if _SURVIVAL_RANK[surv] > _SURVIVAL_RANK[survival]:
                survival = surv
        else:
            text = clean
        ev = by_id[ev_id]
        ev.fields = _substitute(ev.fields, text)
    # Any other placeholders (defensive) get the clean value.
    for ev in inst.events:
        ev.fields = _substitute(ev.fields, clean)
    return inst, survival
