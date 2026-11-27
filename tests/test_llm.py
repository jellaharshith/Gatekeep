import json

import httpx
import pytest

from gatekeep.llm import _http
from gatekeep.llm.anthropic import AnthropicBackend
from gatekeep.llm.base import LLMResponse, assistant_message, make_backend, tool_message
from gatekeep.llm.openai_compat import OpenAICompatBackend
from gatekeep.llm.simulated import SimulatedBackend
from gatekeep.models import ToolCall

KEYS = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY", "GROQ_API_KEY",
        "VLLM_API_KEY", "GATEKEEP_API_KEY"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in KEYS:
        monkeypatch.delenv(k, raising=False)


def test_all_providers_resolve(monkeypatch):
    for k in KEYS:
        monkeypatch.setenv(k, "k-" + k)
    assert isinstance(make_backend("sim:robust"), SimulatedBackend)
    assert isinstance(make_backend("sim"), SimulatedBackend)
    b = make_backend("anthropic:claude-x")
    assert isinstance(b, AnthropicBackend) and b.name == "anthropic:claude-x" and b.api_key == "k-ANTHROPIC_API_KEY"
    for prov in ["openai", "ollama", "openrouter", "groq", "vllm", "compat"]:
        b = make_backend(f"{prov}:m:1")
        assert isinstance(b, OpenAICompatBackend)
        assert b.name == f"{prov}:m:1"
    assert make_backend("ollama:q").api_key == "ollama"
    assert make_backend("openai:g").api_key == "k-OPENAI_API_KEY"
    assert make_backend("openai:g").base_url == "https://api.openai.com/v1"


def test_optional_keys_fall_back_to_none():
    assert make_backend("vllm:m").api_key == "none"
    assert make_backend("compat:m").api_key == "none"


def test_missing_key_errors():
    with pytest.raises(RuntimeError, match="^ANTHROPIC_API_KEY is not set$"):
        make_backend("anthropic:m")
    for prov, env in [("openai", "OPENAI_API_KEY"), ("openrouter", "OPENROUTER_API_KEY"),
                      ("groq", "GROQ_API_KEY")]:
        with pytest.raises(RuntimeError, match=f"^{env} is not set$"):
            make_backend(f"{prov}:m")


def test_unknown_provider():
    with pytest.raises(ValueError, match="unknown provider 'nope' in model spec 'nope:x'"):
        make_backend("nope:x")


def test_base_url_env_override(monkeypatch):
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://h:1/v1/")
    assert make_backend("ollama:m").base_url == "http://h:1/v1"


class _Seq:
    def __init__(self, statuses, body=None):
        self.statuses = list(statuses)
        self.body = body or {"ok": True}
        self.calls = 0

    def __call__(self, url, json=None, headers=None, timeout=None):
        self.calls += 1
        s = self.statuses.pop(0)
        if isinstance(s, Exception):
            raise s
        return httpx.Response(s, json=self.body if s < 400 else {"err": 1},
                              request=httpx.Request("POST", url))


@pytest.fixture
def sleeps(monkeypatch):
    out = []
    monkeypatch.setattr(_http.time, "sleep", lambda s: out.append(s))
    return out


def _anth():
    return AnthropicBackend("m", "k")


def _oai():
    return OpenAICompatBackend("m", "http://x/v1", "k", label="oai")


def test_anthropic_retries_then_succeeds(monkeypatch, sleeps):
    seq = _Seq([529, 429, 200], {"content": [{"type": "text", "text": "hi"}]})
    monkeypatch.setattr(httpx, "post", seq)
    assert _anth().chat([{"role": "user", "content": "q"}], []).content == "hi"
    assert seq.calls == 3 and sleeps == [1, 2]


def test_anthropic_fail_fast_and_504_not_retried(monkeypatch, sleeps):
    for status in (400, 504):
        seq = _Seq([status])
        monkeypatch.setattr(httpx, "post", seq)
        with pytest.raises(RuntimeError, match=f"anthropic:m: {status}"):
            _anth().chat([{"role": "user", "content": "q"}], [])
        assert seq.calls == 1
    assert sleeps == []


def test_anthropic_exhausts_retries(monkeypatch, sleeps):
    seq = _Seq([500, 500, httpx.ConnectError("boom")])
    monkeypatch.setattr(httpx, "post", seq)
    with pytest.raises(RuntimeError, match="failed after 3 attempts"):
        _anth().chat([{"role": "user", "content": "q"}], [])
    assert sleeps == [1, 2, 4]


def test_openai_retry_set_includes_504_not_529(monkeypatch, sleeps):
    body = {"choices": [{"message": {"content": "yo"}}]}
    seq = _Seq([504, 200], body)
    monkeypatch.setattr(httpx, "post", seq)
    assert _oai().chat([], []).content == "yo"
    assert seq.calls == 2 and sleeps == [1]


def test_openai_fail_fast_below_429(monkeypatch, sleeps):
    seq = _Seq([404])
    monkeypatch.setattr(httpx, "post", seq)
    with pytest.raises(RuntimeError, match="oai: 404"):
        _oai().chat([], [])
    assert seq.calls == 1 and sleeps == []


def test_openai_non_retry_status_ge_429_is_retried(monkeypatch, sleeps):
    # quirk preserved: 529 is not in the retry set but raise_for_status error >=429 is retried
    seq = _Seq([529, 529, 529])
    monkeypatch.setattr(httpx, "post", seq)
    with pytest.raises(RuntimeError, match="failed after 3 attempts"):
        _oai().chat([], [])
    assert seq.calls == 3 and sleeps == [1, 2, 4]


def test_golden_messages():
    resp = LLMResponse(content="thinking", tool_calls=[
        ToolCall(id="c1", name="lookup_ioc", arguments={"ioc": "é"}),
        ToolCall(id="c2", name="close_alert", arguments={})])
    assert assistant_message(resp) == {
        "role": "assistant", "content": "thinking",
        "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "lookup_ioc", "arguments": '{"ioc": "\\u00e9"}'}},
            {"id": "c2", "type": "function", "function": {"name": "close_alert", "arguments": "{}"}}]}
    assert assistant_message(LLMResponse(content="done")) == {"role": "assistant", "content": "done"}

    class Odd:
        def __str__(self):
            return "odd"

    m = tool_message("c1", {"t": "é", "o": Odd()})
    assert m == {"role": "tool", "tool_call_id": "c1", "content": '{"t": "é", "o": "odd"}'}
    assert len(tool_message("c", {"x": "a" * 20000})["content"]) == 12_000
    assert json.loads(tool_message("c", [1])["content"]) == [1]
