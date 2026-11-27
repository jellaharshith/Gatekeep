# Forward-deployed playbook: gatekeep at a customer

Target: from first call to a CISO-ready report in 5 working days, with install itself under 30 minutes.

## Day 0: Scoping call (45 min)

Ask:
1. Which AI agents touch alerts? Vendor product, DIY (which LLM, which framework), or both?
2. What can each agent **do** without a human? Close, suppress, isolate, ticket, webhook, email?
3. Which log sources feed it? (Map each one to gatekeep vectors.)
4. Where do approvals happen today (SOAR, ticketing, chat)?
5. Test environment available? (Never run injection tests against production telemetry.)
6. Written authorization: scope, systems, dates, contacts, stop conditions.

Output: signed rules of engagement and a vector list.

## Day 1: Install (30 min)

```bash
pip install gatekeep            # or: pip install git+https://github.com/<you>/gatekeep
gatekeep demo                   # proves the toolchain on their box
cp gatekeep/guard/policies/default.yaml customer-policy.yaml
```

Edit `customer-policy.yaml`: the egress allowlist (their SOAR/chat hosts), severity floors, and which
rules are deny vs hold. Their risk appetite decides this, not ours.

## Day 2: Baseline

- DIY agents: wire their model into `gatekeep run --models ...` with their system prompt (fork `agent.py`).
- MCP-capable agents: `gatekeep serve-mcp` per scenario. Script the loop.
- Vendor products: test through their ingestion path in the test tenant with `gatekeep lab inject`.

## Day 3: Enforced posture

Re-run with `--postures none,advisory,enforced --policy customer-policy.yaml`. Review every held action
with their analysts: is this hold acceptable workload? Tune, re-run.

## Day 4: Field survival + custom scenarios

Run `lab inject` / `lab survival` on their real pipeline in the test tenant. Write 2-3 scenarios from
their own top alert types.

## Day 5: Report and handover

- `report.html` for leadership, `report.md` for engineering, and `docs/ENGAGEMENT_REPORT_TEMPLATE.md` filled in.
- Add the GitHub Action to their agent repo so every prompt, model or tool change is gated.
- Debrief: top 3 risks, policy decisions made, and what remains unsolved (be explicit).

## Product feedback loop

After each engagement, record: new vectors seen, rules that needed customer-specific tuning, and
integration pain. Repeated patterns become product features, not one-off scripts.
