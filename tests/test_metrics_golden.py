"""Golden-output pin for metrics.summarize on a small hand-built fixture."""
import json
from pathlib import Path

from gatekeep.metrics import summarize
from gatekeep.models import Objective, Posture, TrialResult

GOLDEN = Path(__file__).with_name("metrics_golden.json")


def _r(sid, model, posture, family=None, objective=None, rep=0, atk=None, util=True,
       surfaced=False, held=0, denied=0, survival="n/a", error=None):
    return TrialResult(
        trial_id=f"{sid}|{model}|{posture.value}|{family or 'clean'}|{objective.value if objective else '-'}|r{rep}",
        scenario_id=sid, vector="siem_field", ground_truth="true_positive", model=model, posture=posture,
        family=family, objective=objective, repeat=rep, survival=survival, attack_success=atk,
        utility_ok=util, surfaced=surfaced, held=held, denied=denied, error=error)


def fixture():
    N, A, E = Posture.NONE, Posture.ADVISORY, Posture.ENFORCED
    C, X = Objective.CONCEAL, Objective.EXFIL
    rows = []
    for m in ("sim:a", "sim:b"):
        for sid in ("S1", "S2"):
            for p in (N, A, E):
                rows.append(_r(sid, m, p, util=not (sid == "S2" and m == "sim:b" and p == N)))
                rows.append(_r(sid, m, p, util=(sid == "S1"), rep=1))
                for fam, obj in (("authority_forgery", C), ("tool_output", X)):
                    for rep in range(2):
                        success = (p is N) or (p is A and rep == 0 and sid == "S1")
                        rows.append(_r(sid, m, p, fam, obj, rep, atk=success, util=not success,
                                       surfaced=(p is E), held=int(p is E), denied=int(p is E and rep),
                                       survival="intact" if rep else "transformed"))
    rows.append(_r("S1", "sim:a", N, error="boom"))
    return rows


def test_summarize_golden():
    got = json.loads(json.dumps(summarize(fixture())))
    # dumps comparison pins key order at every level, not just values
    assert json.dumps(got, indent=1) + "\n" == GOLDEN.read_text()
