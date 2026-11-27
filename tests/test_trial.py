import json

from gatekeep.agent import ReferenceTriageAgent
from gatekeep.llm.base import make_backend
from gatekeep.mcp_server import SandboxMCPServer
from gatekeep.models import Objective, Posture
from gatekeep.runner import RunConfig, TrialSpec, run_trial
from gatekeep.trial import build_sandbox, collect_result, make_trial_id


def test_trial_id_format_pinned(scenarios):
    s = scenarios["SOC-001"]
    assert make_trial_id("SOC-001", "sim:gullible", Posture.ENFORCED, "authority_forgery",
                         Objective.CONCEAL, 2) == "SOC-001|sim:gullible|enforced|authority_forgery|conceal|r2"
    assert make_trial_id("SOC-001", "m", Posture.NONE, None, None, 0) == "SOC-001|m|none|clean|-|r0"
    spec = TrialSpec(s, "m", Posture.NONE, None, None, 1)
    assert spec.trial_id == "SOC-001|m|none|clean|-|r1"


def test_build_and_collect_matches_run_trial(scenarios, policy):
    s = scenarios["SOC-001"]
    obj = s.objectives[0]
    spec = TrialSpec(s, "sim:gullible", Posture.NONE, "authority_forgery", obj, 0)
    cfg = RunConfig(models=["sim:gullible"])
    expected = run_trial(spec, policy, cfg)

    sb = build_sandbox(s, spec.posture, policy, spec.family, spec.objective)
    backend = make_backend(spec.model, cfg.temperature)
    backend.begin_trial(spec.trial_id)
    transcript, steps = ReferenceTriageAgent(backend, spec.posture, cfg.max_steps).run(
        sb.instance.alert, sb.gateway)
    got = collect_result(sb, s, trial_id=spec.trial_id, model=spec.model, posture=spec.posture,
                         family=spec.family, objective=spec.objective, repeat=0,
                         steps=steps, transcript=transcript)
    assert got.model_dump() == expected.model_dump()


def test_mcp_handle(scenarios, policy):
    srv = SandboxMCPServer(scenarios["SOC-001"], Posture.ENFORCED, policy)
    r = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r["result"]["serverInfo"]["name"] == "gatekeep-sandbox-siem"
    r = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert r["result"]["tools"]
    r = srv.handle({"jsonrpc": "2.0", "id": 3, "method": "bogus"})
    assert r["error"]["code"] == -32601
    assert srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert srv.result().trial_id == "SOC-001|external-mcp-agent|enforced|clean|-|r0"
    json.dumps(srv.result().model_dump(mode="json"))


def _srv(scenarios, policy):
    return SandboxMCPServer(scenarios["SOC-001"], Posture.ENFORCED, policy)


def test_mcp_envelopes_and_calls(scenarios, policy):
    srv = _srv(scenarios, policy)
    r = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "X"}})
    assert list(r) == ["jsonrpc", "id", "result"] and r["id"] == 1
    assert r["result"]["protocolVersion"] == "X"
    assert r["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert "A-1001" in r["result"]["instructions"]
    r = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize"})
    assert r["result"]["protocolVersion"] == "2025-06-18"
    assert srv.calls == 0
    assert srv.handle({"jsonrpc": "2.0", "id": 3, "method": "ping"}) == {"jsonrpc": "2.0", "id": 3, "result": {}}
    r = srv.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
    assert all(set(t) == {"name", "description", "inputSchema"} for t in r["result"]["tools"])
    assert srv.calls == 0
    r = srv.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "no_such_tool"}})
    assert srv.calls == 1
    assert r["result"]["content"][0]["type"] == "text"
    assert r["result"]["isError"] is ("error" in json.loads(r["result"]["content"][0]["text"]))
    r = srv.handle({"jsonrpc": "2.0", "id": 6, "method": "nope"})
    assert r == {"jsonrpc": "2.0", "id": 6, "error": {"code": -32601, "message": "method not found: nope"}}
    assert srv.handle({"jsonrpc": "2.0", "method": "nope"}) is None
    assert srv.handle({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "x"}}) is None
    assert srv.calls == 1


def test_mcp_tool_exception_is_internal_error(scenarios, policy):
    srv = _srv(scenarios, policy)

    def boom(name, args):
        raise RuntimeError("kaboom")
    srv.gateway.call = boom
    r = srv.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "x"}})
    assert r == {"jsonrpc": "2.0", "id": 9, "error": {"code": -32603, "message": "kaboom"}}
    assert srv.calls == 1


def test_mcp_serve_parse_error(scenarios, policy):
    import io
    srv = _srv(scenarios, policy)
    out = io.StringIO()
    srv.serve(io.StringIO('{bad json\n\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
                          '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'), out)
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines == [{"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}},
                     {"jsonrpc": "2.0", "id": 1, "result": {}}]
