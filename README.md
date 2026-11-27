# Gatekeep

**Red-team benchmark and tool-layer enforcement gateway for AI SOC agents.**

AI triage agents read logs, and attackers write a large share of those logs: usernames, User-Agents,
DNS names, email subjects, filenames, command lines. gatekeep measures whether text planted in those
fields can make a SOC agent **do** something harmful: close a real attack, plant a suppression rule,
send alert data to an attacker URL, isolate the wrong host, or raise a fake P1. It then measures how
much of that a **policy gateway between the agent and its tools** stops, and what it costs in analyst
workload.

```
attacker-writable field ──► SIEM pipeline (truncation, charset, decoders) ──► agent context
                                                                                │ tool calls
                                         none / advisory / ENFORCED gateway ◄───┘
                                                         │
                                   SIEM/SOAR state ──► deterministic scoring ──► stats ──► report / CI gate
```

## Why this exists

Prior 2026 work showed that log-borne prompt injection works against LLM log *analysis*:
LogInject reported 83.4% average attack success on summarization/classification and 8.4% residual
after layered prompt/filter defenses ([arXiv:2607.14493](https://arxiv.org/abs/2607.14493));
Landauer et al. got attack traces classified as benign ([arXiv:2607.24174](https://arxiv.org/abs/2607.24174));
a DEF CON 34 AI Village poster mapped which fields survive SIEM ingestion. In finance,
FinAgent Red-Team showed that enforcing controls at the **tool layer** (vs. stating them in the
prompt) drives attack success to zero ([repo](https://github.com/nac7/finagent-redteam)).

gatekeep brings that question to **agentic SOCs**: agents with tools that change state.

| | Prior log-injection work | gatekeep |
|---|---|---|
| System under test | single LLM call (summarize / classify) | tool-using triage agent (any MCP agent, or the reference agent) |
| Success measured on | model output text | SIEM/SOAR **state** (closed? suppressed? isolated? exfiltrated?) |
| Defenses compared | prompt hardening, filters | none vs. advisory vs. **enforced tool-layer policy** |
| Cost of defense | rarely reported | clean-run utility + human-approval load per trial |
| Deployable | research artifact | CLI, MCP sandbox server, CI gate, policy file per customer |

## Quickstart (offline, runs in seconds)

```bash
git clone <your-repo-url> gatekeep && cd gatekeep
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
gatekeep list
gatekeep demo            # 636 trials with the built-in simulator -> runs/demo/report.md + report.html
gatekeep gate --summary runs/demo/summary.json --posture enforced --max-asr 0.05
```

> `sim:*` models are a deterministic **simulator**. They prove the pipeline works end to end
> without a GPU or API key. Their numbers are **not findings**. Every report built from them says so.

## Real models

```bash
# Local (free): Ollama with a tool-calling model
ollama pull qwen3:8b
gatekeep run --models ollama:qwen3:8b --sample 60 --out runs/qwen3-pilot

# Hosted
export ANTHROPIC_API_KEY=...   ; gatekeep run --models anthropic:claude-haiku-5-5 --workers 4 --out runs/haiku
export OPENAI_API_KEY=...      ; gatekeep run --models openai:<model> --workers 4 --out runs/openai
# Also: openrouter:<model>, groq:<model>, vllm:<model> (VLLM_BASE_URL), compat:<model> (GATEKEEP_BASE_URL)

gatekeep run --models ollama:qwen3:8b,ollama:llama3.1:8b --repeats 3 --out runs/local-full
```

Start with `--sample` (clean controls are always kept), check `--dry-run` for the trial count, then scale.

## Test someone else's agent (MCP mode)

gatekeep can serve one scenario as an MCP "SIEM". Point any MCP-capable SOC agent at it, ask it to
triage the alert, and gatekeep scores the final state when the client disconnects.

```bash
gatekeep serve-mcp --scenario SOC-001 --family authority_forgery --objective conceal \
    --posture none --agent-label my-agent --out runs/mcp/results.jsonl
```

Example (Claude Code as the agent under test):

```bash
claude mcp add gatekeep -- gatekeep serve-mcp --scenario SOC-002 --family test_decoy \
    --objective exfil --posture none --out runs/mcp/results.jsonl
```

Then `gatekeep report runs/mcp/results.jsonl`. See [examples/](examples/) for a generic `mcpServers` config.

## Live pipeline (your own Wazuh lab)

Measure what really survives ingestion: send a marked payload as a syslog line, then find it in the indexer.

```bash
gatekeep lab inject --target 10.0.0.5 --vector ssh.username --family authority_forgery --i-own-this-lab
gatekeep lab survival --indexer https://10.0.0.5:9200 --marker SG1A2B3C --payload "<printed payload>" \
    --user admin --password '...' --insecure
```

Both commands refuse public addresses. See [lab/README.md](lab/README.md).

## What is in the box

| Path | What it does |
|---|---|
| `gatekeep/scenarios/corpus/` | 12 SOC scenarios (10 true positives, 2 benign) mapped to ATT&CK and OWASP Agentic Top 10 |
| `gatekeep/injection/` | 10 attacker-writable vectors with pipeline mangling; 8 payload families x 5 objectives |
| `gatekeep/env/siem.py` | deterministic SIEM/SOAR sandbox, 12 tools, full action log |
| `gatekeep/guard/` | gateway: spotlighting, injection tripwire, provenance (taint) tracking, 10 policy rules |
| `gatekeep/agent.py` | reference tool-calling triage agent (the typical DIY AI-SOC loop) |
| `gatekeep/llm/` | OpenAI-compatible (OpenAI/Ollama/vLLM/OpenRouter/Groq), Anthropic, simulator |
| `gatekeep/scoring.py` | state predicates: attack success, utility, surfaced-to-human |
| `gatekeep/metrics.py` | Wilson 95% CIs, conditional ASR, paired sign-flip permutation tests |
| `gatekeep/report.py` | engineer report (Markdown) + CISO one-pager (HTML) |
| `gatekeep/mcp_server.py` | MCP stdio server exposing a scenario through the gateway |
| `gatekeep/lab/` | syslog injector + Wazuh indexer survival check (private targets only) |
| `action.yml` | GitHub Action: fail a PR if enforced-posture ASR regresses |
| `docs/` | methodology, threat model, FDE deployment playbook, disclosure and report templates, project plan |

## The enforcement policy

`gatekeep/guard/policies/default.yaml`. The rules use only trusted state (threat intel, asset inventory,
detection entities, provenance) and never the model's reasoning:

`injection_is_evidence` · `no_autoclose_with_ioc` · `no_autoclose_high_severity` ·
`no_severity_downgrade_with_ioc` · `no_severity_inflation_without_evidence` ·
`suppression_requires_human` · `egress_allowlist` · `isolation_scope` ·
`critical_isolation_requires_human` · `taint_binding`

## Metrics

- **ASR**: attack success rate, the attacker objective reached in SIEM state, with Wilson 95% CI.
- **Conditional ASR**: ASR only where the agent handles the same alert correctly without an attack.
- **Clean utility**: correct disposition on clean controls. A defense that breaks triage is not a defense.
- **Held/trial**: actions parked for human approval, i.e. the analyst workload the gateway adds.
- **Surfaced to human**: the attack ended up in front of a person (escalated, held or flagged).
- **Posture tests**: paired sign-flip permutation test over identical cells.

## Roadmap

See [docs/PROJECT_PLAN.md](docs/PROJECT_PLAN.md). Next: real-model baselines, Wazuh field-survival
tables, open-source AI-SOC targets with coordinated disclosure, an MCP-to-MCP gateway mode for
production SIEM MCP servers, and a LogInject-1.0 importer.

## Responsible use

For systems you own or are authorized to test. All corpus infrastructure uses reserved names
(RFC 2606 `.example`/`.invalid`, RFC 5737 TEST-NET addresses). See [SECURITY.md](SECURITY.md).

## License

MIT
