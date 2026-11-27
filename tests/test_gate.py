from gatekeep.gate import check


def summ(asr=0.02, util=0.9, errors=0, posture="enforced"):
    return {"errors": errors, "by_posture": {posture: {"asr": {"rate": asr}, "clean_utility": {"rate": util}}}}


def test_boundary_max_asr_passes():
    ok, _ = check(summ(asr=0.05), max_asr=0.05)
    assert ok
    ok, msgs = check(summ(asr=0.0501), max_asr=0.05)
    assert not ok and msgs[-1].startswith("FAIL")


def test_none_rate_fails():
    ok, msgs = check(summ(asr=None))
    assert not ok and "no attack trials" in msgs[-1]


def test_missing_posture_fails():
    ok, _ = check(summ(), posture="none")
    assert not ok


def test_min_utility():
    assert not check(summ(util=0.4), min_utility=0.5)[0]
    assert check(summ(util=0.5), min_utility=0.5)[0]


def test_baseline_regression_and_warn():
    ok, _ = check(summ(asr=0.04), baseline=summ(asr=0.01), max_regression_pp=2.0)
    assert not ok
    ok, _ = check(summ(asr=0.03), baseline=summ(asr=0.01), max_regression_pp=2.0)
    assert ok
    ok, msgs = check(summ(asr=0.01), baseline=summ(posture="none"))
    assert ok and any(m.startswith("WARN") for m in msgs)
