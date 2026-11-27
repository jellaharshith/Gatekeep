"""Send realistic log lines carrying a payload to a LAB syslog receiver (e.g. Wazuh manager).

Safety rails (do not remove them):
  * the target must resolve to a loopback/private/link-local address, and
  * the caller must pass --i-own-this-lab.
Only use this against infrastructure you own or are explicitly authorized to test.
"""
from __future__ import annotations

import ipaddress
import random
import socket
from datetime import datetime, timezone
from urllib.parse import quote

SUPPORTED = ("ssh.username", "http.user_agent", "http.uri", "dns.qname", "email.subject")


class ScopeError(RuntimeError):
    pass


def assert_lab_target(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ScopeError(f"cannot resolve {host}: {exc}") from exc
    addrs = {i[4][0] for i in infos}
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            raise ScopeError(f"{host} resolves to public address {a}; gatekeep lab only targets private lab networks")
    return sorted(addrs)[0]


def build_line(vector: str, payload: str, src_ip: str = "203.0.113.66", hostname: str = "web-01") -> str:
    now = datetime.now(timezone.utc)
    ts = f"{now:%b} {now.day:>2} {now:%H:%M:%S}"  # RFC 3164 timestamp
    pid = random.randint(1000, 30000)
    port = random.randint(40000, 65000)
    if vector == "ssh.username":
        return f"<38>{ts} {hostname} sshd[{pid}]: Invalid user {payload} from {src_ip} port {port}"
    if vector == "http.user_agent":
        clf = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
        return (f'<190>{ts} {hostname} nginx: {src_ip} - - [{clf}] "GET /index.php HTTP/1.1" 200 512 '
                f'"-" "{payload}"')
    if vector == "http.uri":
        clf = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
        return (f'<190>{ts} {hostname} nginx: {src_ip} - - [{clf}] "GET /search?q={quote(payload)} HTTP/1.1" '
                f'404 162 "-" "Mozilla/5.0"')
    if vector == "dns.qname":
        return (f"<30>{ts} {hostname} named[{pid}]: client @0x7f3a {src_ip}#{port} ({payload}): "
                f"query: {payload} IN A + (10.0.0.53)")
    if vector == "email.subject":
        return (f"<22>{ts} {hostname} postfix/cleanup[{pid}]: 4F2A1C0B3D: warning: header Subject: {payload} "
                f"from mail.attacker.invalid[{src_ip}]; from=<billing@invoices-secure.example> "
                f"to=<j.doe@corp.example> proto=ESMTP helo=<mail.attacker.invalid>")
    raise ValueError(f"vector {vector!r} not supported by the syslog injector; choose from {SUPPORTED}")


def build_payload(vector: str, marker: str, family: str | None = None, objective: str = "conceal",
                  alert_id: str = "A-LAB", src_ip: str = "203.0.113.66", decoy_host: str = "fin-db-01",
                  payload: str | None = None) -> str:
    """Assemble the marker-prefixed payload for a vector (rendered family or custom/default text)."""
    from ..injection.payloads import render
    from ..injection.vectors import VECTORS, apply_vector
    from ..models import Objective

    if family:
        ctx = {"alert_id": alert_id, "attacker_value": src_ip, "decoy_host": decoy_host,
               "exfil_url": "https://collect.attacker.invalid/ingest"}
        text = " ".join(render(family, Objective(objective), ctx, 1, VECTORS[vector].compact))
    else:
        text = payload or "gatekeep-survival-probe the quick brown fox"
    text = f"{marker} {text}"
    if vector == "ssh.username":
        text = text.replace(" ", "_")
    if vector == "dns.qname":
        text = apply_vector("dns.qname", text)[0] + ".lab.example"
    return text


def send(target: str, port: int, lines: list[str], proto: str = "udp") -> int:
    addr = assert_lab_target(target)
    if proto == "udp":
        with socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_DGRAM) as s:
            for line in lines:
                s.sendto(line.encode("utf-8", "replace"), (addr, port))
    else:
        with socket.create_connection((addr, port), timeout=10) as s:
            for line in lines:
                s.sendall(line.encode("utf-8", "replace") + b"\n")
    return len(lines)
