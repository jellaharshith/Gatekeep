"""Any OpenAI-compatible chat/completions endpoint: OpenAI, Ollama, vLLM, OpenRouter, Groq."""
from __future__ import annotations

import json
import time
from typing import Any

import httpx

from ..models import ToolCall
from .base import LLMBackend, LLMResponse


class OpenAICompatBackend(LLMBackend):
    def __init__(self, model: str, base_url: str, api_key: str, temperature: float = 0.0,
                 timeout: float = 180.0, label: str = "", retries: int = 3):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout
        self.retries = retries
        self.name = label or model

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "tools": [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                         "parameters": t["parameters"]}} for t in tools],
            "tool_choice": "auto",
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        data = self._post(payload, headers)
        msg = data["choices"][0]["message"]
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except (json.JSONDecodeError, TypeError, ValueError):
                args = {"_unparsed": raw}
            calls.append(ToolCall(id=tc.get("id") or f"call_{i}", name=fn.get("name", ""), arguments=args))
        return LLMResponse(content=msg.get("content"), tool_calls=calls)

    def _post(self, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        last: Exception | None = None
        for attempt in range(self.retries):
            try:
                r = httpx.post(f"{self.base_url}/chat/completions", json=payload, headers=headers,
                               timeout=self.timeout)
                if r.status_code in (429, 500, 502, 503, 504):
                    raise httpx.HTTPStatusError(f"retryable {r.status_code}", request=r.request, response=r)
                r.raise_for_status()
                return r.json()
            except (httpx.HTTPStatusError, httpx.TransportError) as exc:
                last = exc
                if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 429:
                    raise RuntimeError(f"{self.name}: {exc.response.status_code} {exc.response.text[:300]}")
                time.sleep(2 ** attempt)
        raise RuntimeError(f"{self.name}: request failed after {self.retries} attempts: {last}")
