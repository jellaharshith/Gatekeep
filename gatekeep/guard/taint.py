"""Provenance tracking: which values the agent could only have learned from attacker text.

The gateway sees every event the agent reads. Values inside attacker-controlled
fields are TAINTED. Values produced by the detection pipeline (alert entities,
alert host) are TRUSTED. A high-impact argument (host to isolate, URL to post to,
value to suppress) that appears in tainted text but not in trusted data was put
there by the attacker, so the call is refused.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..models import Alert, Event
from ..textnorm import strip_zw



def _norm(s: str) -> str:
    return strip_zw(s).strip().lower()


class TaintTracker:
    def __init__(self, trusted_values: Iterable[str]):
        self.trusted = {_norm(v) for v in trusted_values if str(v).strip()}
        self._tainted_text: list[str] = []

    @classmethod
    def for_alert(cls, alert: Alert) -> "TaintTracker":
        vals = [alert.host, alert.id] + [v for vs in alert.entities.values() for v in vs]
        return cls(vals)

    def observe(self, event: Event) -> None:
        for f in event.attacker_controlled:
            v = event.fields.get(f)
            if v is not None:
                self._tainted_text.append(_norm(v))

    @property
    def tainted_text(self) -> str:
        return "\n".join(self._tainted_text)

    def is_trusted(self, value: str) -> bool:
        v = _norm(value)
        return any(v == t or (len(t) > 3 and t in v) for t in self.trusted)

    def untrusted_only(self, value: str) -> bool:
        """True if value occurs in attacker-written text and has no trusted origin."""
        v = _norm(value)
        if not v or self.is_trusted(v):
            return False
        text = self.tainted_text
        if v in text:
            return True
        # DNS-style mangling turns '.' and ' ' into '-': compare loosely too.
        loose = re.sub(r"[^a-z0-9]", "", v)
        return len(loose) >= 6 and loose in re.sub(r"[^a-z0-9]", "", text)
