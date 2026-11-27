"""Shared text-normalisation primitives (leaf module: no gatekeep imports)."""
from __future__ import annotations

import re

# Zero-width / invisible characters used to smuggle or split payload tokens.
ZW = re.compile("[​‌‍⁠﻿]")


def strip_zw(s: object) -> str:
    """Remove zero-width characters from ``str(s)``."""
    return ZW.sub("", str(s))
