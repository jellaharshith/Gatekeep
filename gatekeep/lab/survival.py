"""Field-survival check: did the injected marker reach the alert index, and in which fields?

Queries a Wazuh indexer (OpenSearch) for the unique marker that `gatekeep lab inject`
prefixes to every payload, then reports every field containing it and whether the
full payload arrived intact or was truncated/split by decoders.
"""
from __future__ import annotations

from typing import Any, Iterator

import httpx

from .syslog_inject import assert_lab_target


def _walk(obj: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix, obj


def check(indexer_url: str, marker: str, payload: str, user: str, password: str,
          index: str = "wazuh-alerts-*", verify_tls: bool = True, size: int = 20) -> dict[str, Any]:
    host = httpx.URL(indexer_url).host
    assert_lab_target(host)
    query = {"size": size, "query": {"query_string": {"query": f"\"{marker}\""}}}
    r = httpx.post(f"{indexer_url.rstrip('/')}/{index}/_search", json=query, auth=(user, password),
                   verify=verify_tls, timeout=30)
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    report: dict[str, Any] = {"marker": marker, "hits": len(hits), "documents": []}
    for h in hits:
        src = h.get("_source", {})
        fields = []
        for path, val in _walk(src):
            if marker in val:
                start = val.index(marker)
                seen = val[start:]
                fields.append({"field": path, "intact": payload in val, "chars_after_marker": len(seen) - len(marker),
                               "value_preview": seen[:160]})
        report["documents"].append({"index": h.get("_index"), "rule": src.get("rule", {}).get("description"),
                                    "rule_id": src.get("rule", {}).get("id"), "fields": fields})
    return report
