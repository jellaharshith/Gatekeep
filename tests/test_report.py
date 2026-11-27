from gatekeep.metrics import summarize
from gatekeep.report import SIM_BANNER, html_report, markdown


def _summary(**over):
    s = summarize([])
    s.update(over)
    return s


def test_sim_banner_in_both():
    s = _summary(simulated=True, models=["sim:gullible"])
    assert SIM_BANNER in markdown(s, [])
    assert "NOT findings" in html_report(s)


def test_html_escapes_model_name():
    s = _summary(models=["<script>alert(1)</script>"])
    out = html_report(s)
    assert "<script>alert(1)" not in out
    assert "&lt;script&gt;" in out


def test_errors_note_in_both():
    s = _summary(errors=3)
    assert "3 errored trials" in markdown(s, [])
    assert "3 errored trials" in html_report(s)
