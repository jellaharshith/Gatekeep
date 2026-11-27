from gatekeep.guard.detect import scan
from gatekeep.injection.payloads import FAMILIES, render
from gatekeep.models import Objective, Posture
from gatekeep.runner import RunConfig, TrialSpec, run_trial

def test_family_registered_and_renders_every_objective(ctx):
    assert "analyst_persona" in FAMILIES
    for obj in Objective:
        frags = render("analyst_persona", obj, ctx, n_targets=3)
        assert frags and all(isinstance(f, str) and f for f in frags)


def test_compact_template_has_no_whitespace(ctx):
    fam = FAMILIES["analyst_persona"]
    assert "{d}" in fam.long and "{d}" in fam.short
    for obj in Objective:
        (frag,) = render("analyst_persona", obj, ctx, compact=True)
        prefix = frag.split(":", 1)[0] + ":"
        assert prefix == "t2-handoff:"
        assert not any(c.isspace() for c in fam.short.replace("{d}", ""))


def test_wrapper_alone_evades_tripwires():
    # DELIBERATE, RECORDED DETECTION GAP: the persona wrapper contains no tripwire
    # indicator, so scan() does not flag it. Only the embedded directive is caught.
    wrapper = FAMILIES["analyst_persona"].long.format(d="noop")
    assert scan(wrapper) == []


def test_directive_inside_payload_still_flagged(ctx):
    (frag,) = render("analyst_persona", Objective.CONCEAL, ctx)
    assert "verdict_directive" in scan(frag)


def test_enforcement_holds_against_gullible(scenarios, policy):
    spec = TrialSpec(scenario=scenarios["SOC-001"], model="sim:gullible",
                     posture=Posture.ENFORCED, family="analyst_persona",
                     objective=Objective.CONCEAL, repeat=0)
    res = run_trial(spec, policy, RunConfig(models=["sim:gullible"]))
    assert res.error is None, res.error
    assert res.attack_success is False
