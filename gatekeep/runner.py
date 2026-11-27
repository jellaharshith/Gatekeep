"""Experiment runner: scenario x payload family x objective x posture x model x repeat."""
from __future__ import annotations

import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .agent import ReferenceTriageAgent
from .guard.policy import Policy
from .injection.payloads import FAMILIES, compatible
from .llm.base import make_backend
from .models import Objective, Posture, Scenario, TrialResult
from .trial import build_sandbox, collect_result, make_trial_id


@dataclass
class TrialSpec:
    scenario: Scenario
    model: str
    posture: Posture
    family: Optional[str]
    objective: Optional[Objective]
    repeat: int

    @property
    def trial_id(self) -> str:
        return make_trial_id(self.scenario.id, self.model, self.posture, self.family,
                             self.objective, self.repeat)


@dataclass
class RunConfig:
    models: list[str]
    postures: list[Posture] = field(default_factory=lambda: list(Posture))
    families: Optional[list[str]] = None
    objectives: Optional[list[Objective]] = None
    repeats: int = 1
    max_steps: int = 10
    temperature: float = 0.0
    include_clean: bool = True
    sample: Optional[int] = None
    seed: int = 0
    workers: int = 1
    keep_transcripts: bool = True


def plan(scenarios: list[Scenario], cfg: RunConfig) -> list[TrialSpec]:
    fams = cfg.families or list(FAMILIES)
    specs: list[TrialSpec] = []
    for s in scenarios:
        for model in cfg.models:
            for posture in cfg.postures:
                for rep in range(cfg.repeats):
                    if cfg.include_clean:
                        specs.append(TrialSpec(s, model, posture, None, None, rep))
                    for obj in s.objectives:
                        if cfg.objectives and obj not in cfg.objectives:
                            continue
                        for fam in fams:
                            if compatible(fam, len(s.injection_targets)):
                                specs.append(TrialSpec(s, model, posture, fam, obj, rep))
    if cfg.sample and cfg.sample < len(specs):
        # Sample attack cells but keep every clean control (needed for conditional ASR).
        rng = random.Random(cfg.seed)
        clean = [t for t in specs if t.family is None]
        attacks = [t for t in specs if t.family is not None]
        specs = clean + rng.sample(attacks, max(0, cfg.sample - len(clean)))
    return specs


def run_trial(spec: TrialSpec, policy: Policy, cfg: RunConfig) -> TrialResult:
    s = spec.scenario
    sb = build_sandbox(s, spec.posture, policy, spec.family, spec.objective)
    error = None
    transcript: list[dict] = []
    steps = 0
    try:
        backend = make_backend(spec.model, cfg.temperature)
        backend.begin_trial(spec.trial_id)
        agent = ReferenceTriageAgent(backend, spec.posture, cfg.max_steps)
        transcript, steps = agent.run(sb.instance.alert, sb.gateway)
    except Exception as exc:  # recorded, excluded from rates
        error = f"{type(exc).__name__}: {exc}"
    return collect_result(
        sb, s, trial_id=spec.trial_id, model=spec.model, posture=spec.posture,
        family=spec.family, objective=spec.objective, repeat=spec.repeat, steps=steps,
        error=error, transcript=transcript if cfg.keep_transcripts else [])


def run(scenarios: list[Scenario], cfg: RunConfig, policy: Policy, out_dir: Path,
        progress: Optional[Callable[[int, int, TrialResult], None]] = None) -> list[TrialResult]:
    out_dir.mkdir(parents=True, exist_ok=True)
    specs = plan(scenarios, cfg)
    results: list[TrialResult] = []
    path = out_dir / "results.jsonl"

    def _one(spec: TrialSpec) -> TrialResult:
        return run_trial(spec, policy, cfg)

    def _consume(iterator, fh) -> None:
        for i, r in enumerate(iterator, 1):
            results.append(r)
            fh.write(r.model_dump_json() + "\n")
            fh.flush()
            if progress:
                progress(i, len(specs), r)

    with path.open("w") as fh:
        if cfg.workers > 1:
            with ThreadPoolExecutor(max_workers=cfg.workers) as pool:
                _consume(pool.map(_one, specs), fh)
        else:
            _consume(map(_one, specs), fh)  # lazy: each trial runs just before its write
    return results


def load_results(path: Path) -> list[TrialResult]:
    return [TrialResult.model_validate_json(line) for line in Path(path).read_text().splitlines() if line.strip()]


def print_progress(i: int, n: int, r: TrialResult) -> None:
    if i == n or i % 25 == 0:
        print(f"  [{i}/{n}] {r.trial_id}", file=sys.stderr)
    if r.error:
        print(f"  ! {r.trial_id}: {r.error}", file=sys.stderr)


def write_summary(summary: dict, out_dir: Path) -> Path:
    p = out_dir / "summary.json"
    p.write_text(json.dumps(summary, indent=2))
    return p
