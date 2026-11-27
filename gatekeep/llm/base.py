"""LLM backend interface. Messages use the OpenAI chat format internally."""
from __future__ import annotations

import os
from abc import ABC, abstractmethod
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


_OPENAI_COMPAT = {
    "openai": ("OPENAI_BASE_URL", "https://api.openai.com/v1", "OPENAI_API_KEY"),
    "ollama": ("OLLAMA_BASE_URL", "http://localhost:11434/v1", None),
    "openrouter": ("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "groq": ("GROQ_BASE_URL", "https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "vllm": ("VLLM_BASE_URL", "http://localhost:8000/v1", "VLLM_API_KEY"),
    "compat": ("GATEKEEP_BASE_URL", "http://localhost:8000/v1", "GATEKEEP_API_KEY"),
}


def make_backend(spec: str, temperature: float = 0.0) -> LLMBackend:
    """Build a backend from 'provider:model', e.g. 'ollama:qwen3:8b', 'sim:gullible'."""
    provider, _, model = spec.partition(":")
    provider = provider.lower()
    if provider == "sim":
        from .simulated import SimulatedBackend

        return SimulatedBackend(profile=model or "gullible")
    if provider == "anthropic":
        from .anthropic import AnthropicBackend

        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        return AnthropicBackend(model=model, api_key=key, temperature=temperature)
    if provider in _OPENAI_COMPAT:
        from .openai_compat import OpenAICompatBackend

        url_env, default_url, key_env = _OPENAI_COMPAT[provider]
        key = os.environ.get(key_env) if key_env else "ollama"
        if key_env and not key and provider in ("openai", "openrouter", "groq"):
            raise RuntimeError(f"{key_env} is not set")
        return OpenAICompatBackend(model=model, base_url=os.environ.get(url_env, default_url),
                                   api_key=key or "none", temperature=temperature,
                                   label=f"{provider}:{model}")
    raise ValueError(f"unknown provider {provider!r} in model spec {spec!r}")
