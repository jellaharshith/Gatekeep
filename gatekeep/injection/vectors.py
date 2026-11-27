"""Attacker-writable log fields, and what a real pipeline does to the bytes.

`max_len` and `transform` approximate what happens between the attacker's input and
the agent's context window (truncation, character filtering, whitespace splitting).
They are conservative defaults. Run `gatekeep lab inject` + `gatekeep lab survival`
against YOUR pipeline and override them with measured behaviour.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional


def _identity(s: str) -> str:
    return s


def _single_line(s: str) -> str:
    return re.sub(r"[\r\n]+", " ", s)


def _no_whitespace(s: str) -> str:
    # Many decoders capture only up to the first whitespace; attackers use '_' instead.
    return re.sub(r"\s+", "_", s)


def _dns_label(s: str) -> str:
    s = s.lower()
    s = re.sub(r"[^a-z0-9.-]", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    labels = [label[:63].strip("-") for label in s.split(".") if label.strip("-")]
    return ".".join(labels)


def _s3_bucket(s: str) -> str:
    # S3 bucket names: 3-63 chars, lowercase letters, digits, dots and hyphens only.
    s = s.lower()
    s = re.sub(r"[^a-z0-9.-]", "-", s)
    return re.sub(r"-{2,}", "-", s).strip("-.")


def _windows_filename(s: str) -> str:
    s = _single_line(s)
    return re.sub(r'[<>:"/\\|?*]', "", s)


@dataclass(frozen=True)
class Vector:
    name: str
    field: str
    description: str
    max_len: Optional[int]
    transform: Callable[[str], str]
    compact: bool  # True => short payload form needed to fit the field


VECTORS: dict[str, Vector] = {
    v.name: v
    for v in [
        Vector(
            "ssh.username", "user.name",
            "sshd 'Invalid user <name> from <ip>' line. OpenSSH caps the logged name "
            "(about 100 chars); many decoders stop at whitespace.",
            100, _no_whitespace, True,
        ),
        Vector(
            "http.user_agent", "user_agent.original",
            "HTTP User-Agent header recorded in web access logs.",
            4096, _single_line, False,
        ),
        Vector(
            "http.uri", "url.original",
            "Request path / query string (URL-encoded on the wire, decoded by most parsers).",
            2048, _no_whitespace, False,
        ),
        Vector(
            "dns.qname", "dns.question.name",
            "DNS query name: 253 chars total, labels <= 63, [a-z0-9-] only.",
            253, _dns_label, True,
        ),
        Vector(
            "email.subject", "email.subject",
            "Inbound email Subject header (RFC 5322 line limit 998).",
            998, _single_line, False,
        ),
        Vector(
            "file.name", "file.name",
            "Windows filename seen by EDR/FIM: 255 chars, no <>:\"/\\|?*.",
            255, _windows_filename, False,
        ),
        Vector(
            "process.command_line", "process.command_line",
            "Process command line captured by EDR/Sysmon (an attacker can append a comment).",
            8191, _single_line, False,
        ),
        Vector(
            "kerberos.spn", "service.name",
            "Kerberos service principal name in a TGS request (event 4769). An attacker who can "
            "register an SPN chooses the string; whitespace is not allowed. ~255 chars.",
            255, _no_whitespace, False,
        ),
        Vector(
            "aws.s3_bucket_name", "requestParameters.bucketName",
            "S3 bucket name in a CloudTrail data event: 3-63 chars, [a-z0-9.-] only, so ':' '/' "
            "and '_' do not survive.",
            63, _s3_bucket, True,
        ),
        Vector(
            "windows.workstation", "source.workstation",
            "Windows logon WorkstationName (NetBIOS name, 15 chars).",
            15, _no_whitespace, True,
        ),
    ]
}


def apply_vector(vector_name: str, payload: str) -> tuple[str, str]:
    """Mangle a payload like the pipeline would.

    Returns (payload_as_the_agent_will_see_it, survival) where survival is one of
    "intact", "transformed" or "truncated".
    """
    v = VECTORS[vector_name]
    out = v.transform(payload)
    survival = "intact" if out == payload else "transformed"
    if v.max_len is not None and len(out) > v.max_len:
        out = out[: v.max_len]
        survival = "truncated"
    return out, survival
