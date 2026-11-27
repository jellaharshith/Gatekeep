import json

from gatekeep.cli import main


def test_list(capsys):
    assert main(["list"]) == 0
    assert "Scenarios:" in capsys.readouterr().out


def test_run_dry_run(tmp_path):
    assert main(["run", "--dry-run", "--sample", "5", "--out", str(tmp_path / "o")]) == 0


def test_bad_flags_return_2(capsys):
    for flag in ("--families", "--postures", "--objectives"):
        assert main(["run", "--dry-run", flag, "nope"]) == 2
    assert "unknown" in capsys.readouterr().err


def test_demo_report_and_gate(tmp_path):
    out = tmp_path / "nested" / "demo"
    assert main(["demo", "--sample", "5", "--out", str(out)]) == 0
    for f in ("results.jsonl", "summary.json", "report.md", "report.html"):
        assert (out / f).exists()
    out2 = tmp_path / "rebuilt"
    assert main(["report", str(out / "results.jsonl"), "--out", str(out2)]) == 0
    assert (out2 / "report.md").exists()


def test_gate_exit_codes(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"errors": 0, "by_posture": {"enforced": {
        "asr": {"rate": 0.03}, "clean_utility": {"rate": 1.0}}}}))
    assert main(["gate", "--summary", str(f)]) == 0
    assert main(["gate", "--summary", str(f), "--max-asr", "0.01"]) == 1


def test_gate_missing_and_bad_json(tmp_path, capsys):
    assert main(["gate", "--summary", str(tmp_path / "missing.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(["gate", "--summary", str(bad)]) == 2
    assert "error" in capsys.readouterr().err


def test_lab_inject_requires_flag(capsys):
    rc = main(["lab", "inject", "--target", "127.0.0.1", "--vector", "ssh.username"])
    assert rc == 2
    assert "refusing" in capsys.readouterr().err
