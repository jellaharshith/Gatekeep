"""Any OpenAI-compatible chat/completions endpoint: OpenAI, Ollama, vLLM, OpenRouter, Groq."""
from __future__ import annotations

import json
from typing import Any

from ..models import ToolCall
from ._http import post_json
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
        data = post_json(f"{self.base_url}/chat/completions", payload, headers, timeout=self.timeout,
                         retries=self.retries, name=self.name,
                         retry_statuses=(429, 500, 502, 503, 504),
                         raise_for_status=True, fail_fast_below=429)
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
