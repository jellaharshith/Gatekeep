from gatekeep.guard.detect import scan
from gatekeep.guard.taint import _norm
from gatekeep.models import CLOSE_VERDICTS, Posture
from gatekeep.textnorm import ZW, strip_zw

ZW_CHARS = "​‌‍⁠﻿"


def test_strip_zw_removes_all_invisible_chars():
    assert strip_zw(f"ig{ZW_CHARS}nore") == "ignore"
    assert ZW.search(ZW_CHARS)


def test_taint_norm_uses_shared_helper():
    assert _norm(f" Ho{ZW_CHARS}ST ") == "host"


def test_detect_flags_zero_width():
    assert "zero_width_chars" in scan(f"ig{ZW_CHARS}nore previous")


def test_close_verdicts_single_source():
    assert CLOSE_VERDICTS == {"false_positive", "benign_true_positive"}


def test_posture_declaration_order():
    assert [p.value for p in Posture] == ["none", "advisory", "enforced"]
