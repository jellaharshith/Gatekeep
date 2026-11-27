"""Shared POST-with-retry helper for the HTTP LLM backends."""
from __future__ import annotations

import time
from typing import Any, Collection, Optional

import httpx


def post_json(url: str, payload: dict[str, Any], headers: dict[str, str], *, timeout: float,
              retries: int, name: str, retry_statuses: Collection[int],
              raise_for_status: bool = False,
              fail_fast_below: Optional[int] = None) -> dict[str, Any]:
    """POST JSON and return the decoded body, retrying with 2**attempt backoff.

    retry_statuses: statuses that are retried.
    raise_for_status: if True, other non-2xx statuses go through httpx raise_for_status
        (and are then retried unless fail_fast_below applies); if False, any other
        status >= 400 raises RuntimeError immediately.
    fail_fast_below: HTTPStatusErrors with a status below this raise RuntimeError
        immediately instead of being retried.
    """
    last: Exception | None = None
    for attempt in range(retries):
        try:
            r = httpx.post(url, json=payload, headers=headers, timeout=timeout)
            if r.status_code in retry_statuses:
                raise httpx.HTTPStatusError(f"retryable {r.status_code}", request=r.request, response=r)
            if raise_for_status:
                r.raise_for_status()
            elif r.status_code >= 400:
                raise RuntimeError(f"{name}: {r.status_code} {r.text[:300]}")
            return r.json()
        except (httpx.HTTPStatusError, httpx.TransportError) as exc:
            last = exc
            if (fail_fast_below is not None and isinstance(exc, httpx.HTTPStatusError)
                    and exc.response.status_code < fail_fast_below):
                raise RuntimeError(f"{name}: {exc.response.status_code} {exc.response.text[:300]}")
            time.sleep(2 ** attempt)
    raise RuntimeError(f"{name}: request failed after {retries} attempts: {last}")
