"""LLM backend interface. Messages use the OpenAI chat format internally."""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from pydantic import BaseModel, Field

from ..models import ToolCall


class LLMResponse(BaseModel):
    content: Optional[str] = None
    tool_calls: list[ToolCall] = Field(default_factory=list)


class LLMBackend(ABC):
    name: str = "llm"

    def begin_trial(self, trial_key: str) -> None:
        """Called before each trial (simulators reseed here)."""

    @abstractmethod
    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMResponse: ...


def assistant_message(resp: LLMResponse) -> dict[str, Any]:
    """OpenAI-format assistant message for an LLMResponse."""
    msg: dict[str, Any] = {"role": "assistant", "content": resp.content}
    if resp.tool_calls:
        msg["tool_calls"] = [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}}
            for tc in resp.tool_calls
        ]
    return msg


def tool_message(tool_call_id: str, result: Any, max_chars: int = 12_000) -> dict[str, Any]:
    """OpenAI-format tool-result message (JSON-encoded, truncated to max_chars)."""
    content = json.dumps(result, default=str, ensure_ascii=False)[:max_chars]
    return {"role": "tool", "tool_call_id": tool_call_id, "content": content}


@dataclass(frozen=True)
class _CompatProvider:
    url_env: str
    default_url: str
    key_env: Optional[str]
    key_required: bool = False


_OPENAI_COMPAT: dict[str, _CompatProvider] = {
    "openai": _CompatProvider("OPENAI_BASE_URL", "https://api.openai.com/v1", "OPENAI_API_KEY", True),
    "ollama": _CompatProvider("OLLAMA_BASE_URL", "http://localhost:11434/v1", None),
    "openrouter": _CompatProvider("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1",
                                  "OPENROUTER_API_KEY", True),
    "groq": _CompatProvider("GROQ_BASE_URL", "https://api.groq.com/openai/v1", "GROQ_API_KEY", True),
    "vllm": _CompatProvider("VLLM_BASE_URL", "http://localhost:8000/v1", "VLLM_API_KEY"),
    "compat": _CompatProvider("GATEKEEP_BASE_URL", "http://localhost:8000/v1", "GATEKEEP_API_KEY"),
}


def _make_sim(model: str, temperature: float) -> LLMBackend:
    from .simulated import SimulatedBackend

    return SimulatedBackend(profile=model or "gullible")


def _make_anthropic(model: str, temperature: float) -> LLMBackend:
    from .anthropic import AnthropicBackend

    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    return AnthropicBackend(model=model, api_key=key, temperature=temperature)


def _make_compat(provider: str, model: str, temperature: float) -> LLMBackend:
    from .openai_compat import OpenAICompatBackend

    spec = _OPENAI_COMPAT[provider]
    key = os.environ.get(spec.key_env) if spec.key_env else "ollama"
    if spec.key_env and not key and spec.key_required:
        raise RuntimeError(f"{spec.key_env} is not set")
    return OpenAICompatBackend(model=model, base_url=os.environ.get(spec.url_env, spec.default_url),
                               api_key=key or "none", temperature=temperature,
                               label=f"{provider}:{model}")


def make_backend(spec: str, temperature: float = 0.0) -> LLMBackend:
    """Build a backend from 'provider:model', e.g. 'ollama:qwen3:8b', 'sim:gullible'."""
    provider, _, model = spec.partition(":")
    provider = provider.lower()
    if provider == "sim":
        return _make_sim(model, temperature)
    if provider == "anthropic":
        return _make_anthropic(model, temperature)
    if provider in _OPENAI_COMPAT:
        return _make_compat(provider, model, temperature)
    raise ValueError(f"unknown provider {provider!r} in model spec {spec!r}")
