"""Injection tripwire: does attacker-controlled text look like instructions?

This is a cheap heuristic signal, not the defense. The defense is the tool-layer
policy. A hit is treated as an indicator of attack (someone is trying to steer the
SOC), which is valuable to a human analyst regardless of whether the agent obeyed.
"""
from __future__ import annotations

import re

from ..textnorm import ZW, strip_zw

_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")

PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(rx, re.I)
    for name, rx in {
        "override": r"\bignore\s+(all\s+)?(previous|prior)\b",
        "verdict_directive": r"\b(false\s*positive|benign)\b.*\b(close|classify|mark)\b|\b(close|classify|mark)\b.*\b(false\s*positive|benign)\b",
        "authority_claim": r"\b(soc\s*admin|whitelist(ed)?|approved\s+by|change\s+chg)\b",
        "test_claim": r"\bauthori[sz]ed\s+pen(etration)?\s*test\b|\bjust\s+testing\b",
        "markup_breakout": r"</?\s*(system|sys|log\s*entry|data|instructions?)\s*>",
        "action_directive": r"\b(suppress(ion)?|isolate|post\s*webhook|escalate\b.*\bcritical)\b",
        "fragmentation": r"\bpart\s+\d+\s*/\s*\d+\b|\bp\d+of\d+\b",
        "encoding_hint": r"\b(base64|b64)\b",
    }.items()
}


def _normalize(text: str) -> str:
    t = strip_zw(text)
    t = re.sub(r"[_\-]+", " ", t)
    return t


def scan(text: str) -> list[str]:
    """Return the names of matched indicators (empty list = looks clean)."""
    raw = str(text)
    hits = []
    if ZW.search(raw):
        hits.append("zero_width_chars")
    if _B64.search(raw):
        hits.append("base64_blob")
    norm = _normalize(raw)
    hits.extend(name for name, rx in PATTERNS.items() if rx.search(norm))
    return hits
