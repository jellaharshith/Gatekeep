# gatekeep: zero-to-done project plan

Goal: a public repo, a results write-up and at least one coordinated disclosure that together prove
AI-security depth (attacks, evals, defenses) and forward-deployed skill (deploying into a messy
customer stack, integrations, explaining risk to a CISO).

Budget assumption: about 10-12 hours a week for 10 weeks. Each phase has a definition of done (DoD).
Do not start a phase until the previous DoD is met.

---

## Phase 0: Repo live (day 1)

- [ ] Create a GitHub repo `gatekeep`, push this code, enable Actions.
- [ ] `pip install -e ".[dev]" && pytest -q && gatekeep demo` locally.
- [ ] Pin the repo on your profile. Add topics: `ai-security`, `prompt-injection`, `soc`, `owasp-agentic`.

**DoD:** CI is green on GitHub and `runs/demo/report.html` opens.

## Phase 1: Understand and own the code (week 1)

- [ ] Read every module. Write a 1-paragraph docstring in your own words at the top of each file
      you change, so you can defend every design choice in an interview.
- [x] Add 2 scenarios of your own from your AI-SOC LAB experience (for example Kerberoasting with an
      attacker-chosen SPN; an S3 bucket name in a CloudTrail event).
- [x] Add 1 payload family you invent (for example "analyst-persona": text that impersonates a
      prior analyst note). Add a test for it.

**DoD:** 12+ scenarios, 8+ families, tests green, and you can explain the taint-binding rule on a whiteboard.

## Phase 2: Real-model baseline (weeks 2-3)

- [ ] Ollama on the ThinkPad: `qwen3:8b`, `llama3.1:8b` (tool-calling capable). Pilot with `--sample 60`.
- [ ] One hosted model (cheap tier) with `--workers 4`. Track spend; stop at your budget.
- [ ] Full run with `--repeats 3` for the two best-behaved models.
- [ ] Read 20 transcripts by hand: 10 successes under `none`, 10 under `advisory`. Write down failure
      modes the predicates miss. Fix the predicates or add scenarios.
- [ ] Commit `results/` summaries (not raw transcripts with API metadata) and `report.md`.

**DoD:** a table with ASR ± CI per model and posture, clean utility, held/trial, and the paired test p-values.

## Phase 3: Real pipeline (weeks 4-5)

- [ ] Stand up Wazuh single-node in Docker (see `lab/README.md`), enable the syslog listener.
- [ ] For each supported vector and family: `gatekeep lab inject` then `gatekeep lab survival`. Record
      which fields carry the payload (`full_log`, decoded fields), truncation and charset changes.
- [ ] Update `gatekeep/injection/vectors.py` `max_len`/`transform` from your measurements, and cite them.
- [ ] Optional: build `gatekeep/env/wazuh.py` that turns a real Wazuh alert JSON into a Scenario.

**DoD:** a "field survival" table measured on a real pipeline, with the Wazuh version noted.

## Phase 4: Real targets and disclosure (weeks 6-7)

Candidate open-source AI SOC agents (verify each is active and its license allows testing):
UTMStack `soc-ai` plugin, AiSOC, wazuh-openclaw-autopilot, or any MCP-based SOC agent on GitHub.

- [ ] Run each one **in your own lab** against `gatekeep serve-mcp` or through its own ingestion path.
- [ ] For each confirmed issue: minimal reproduction, impact (which tool action), affected version.
- [ ] Report privately via the project's SECURITY.md or GitHub private vulnerability reporting using
      `docs/DISCLOSURE_TEMPLATE.md`. Give 90 days. Never publish details before the fix or the deadline.
- [ ] Offer the maintainers the fix (a policy layer or a PR).

**DoD:** at least 1 report acknowledged by a maintainer (GHSA/CVE if they issue one).

## Phase 5: FDE packaging (week 8)

- [ ] Use `action.yml` in a demo repo: a PR that weakens the prompt fails the gate. Record a GIF.
- [ ] Do a mock customer engagement with `docs/DEPLOYMENT_PLAYBOOK.md` on your Wazuh lab and fill in
      `docs/ENGAGEMENT_REPORT_TEMPLATE.md` as if for a CISO.
- [ ] Stretch: MCP-to-MCP gateway mode (gatekeep proxies a real SIEM MCP server and applies the policy).

**DoD:** a 30-minute install path someone else followed successfully (ask a classmate).

## Phase 6: Publish (weeks 9-10)

- [ ] Blog post or arXiv-style paper: threat model, method, results, limits. Credit LogInject,
      Landauer et al., FinAgent Red-Team, AgentDojo, OWASP ASI.
- [ ] Hugging Face dataset of scenarios + a small leaderboard.
- [ ] Submit a talk: local BSides, an OWASP chapter, or the DEF CON AI Village CFP.
- [ ] 3-minute demo video: attack lands under `none`, gets blocked under `enforced`, CI gate fails a bad PR.

**DoD:** public write-up linked from the README and your resume.

---

## Resume bullet (fill in real numbers only)

> Built gatekeep, an open-source red-team benchmark and tool-layer enforcement gateway for AI SOC agents:
> measured __% action-level attack success across __ models and __ scenarios; enforcement cut it to
> __% at __ held actions/trial; disclosed __ issues to __ open-source AI-SOC projects.

## Interview talking points

1. Why score on state, not text: an agent can refuse in words and still call the tool.
2. Why conditional ASR: an attack "succeeding" on an agent that can't triage the clean alert is noise.
3. Why enforcement beats prompting: rules read trusted state only, so a fooled model can't talk past them.
4. The trade-off: every hold is analyst time. Show held/trial next to ASR, and tune the policy per customer.
5. Limits: simulator ≠ model; sandbox ≠ production; fabricate/alert-fatigue attacks are only rate-limited, not solved.

## Rules for yourself

- Real numbers only. Never publish simulator output as a result.
- Your own lab only. The lab commands refuse public targets; keep it that way.
- Disclose privately first. Credit prior work clearly.
