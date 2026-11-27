# Coordinated disclosure template

Send privately: GitHub "Report a vulnerability" (private advisory), the project's SECURITY.md contact,
or a maintainer email. Never in a public issue.

---

**Subject:** Security report: log-borne prompt injection lets attacker-written telemetry drive `<tool>` in `<project>`

Hi `<maintainer>`,

I'm a security researcher testing AI SOC agents with an open-source benchmark (gatekeep). I found an issue
in `<project>` `<version / commit>` and am reporting it privately first.

**Summary.** Text an external attacker can place in `<field, e.g. the SSH username of a failed login>`
reaches the triage agent's context unmodified. With it, the agent `<closed a true-positive alert /
created a suppression rule / isolated an unrelated host / posted alert data to an external URL>`
without human approval.

**Impact.** `<e.g. an attacker can hide an intrusion from the SOC by generating one failed login>`.
Maps to OWASP Agentic ASI01 (goal hijack) and ASI02 (tool misuse).

**Reproduction (lab only).**
1. Deploy `<project>` per the README, `<config>`.
2. `<exact command / log line>`
3. Observe `<tool call / state change>` in `<log or UI>`.

Transcript and state diff attached. Tested only on my own lab deployment; no third-party systems were involved.

**Suggested fix.** Enforce high-impact actions at the tool layer using trusted state only, for example:
never auto-close alerts whose entities match threat intel; bind isolation targets to detection entities;
egress allowlist for webhooks; treat instruction-like text in attacker-writable fields as an indicator of
attack. I'm happy to send a PR.

**Timeline.** I plan to publish a write-up 90 days from today (`<date>`) or when a fix ships, whichever
is first, and I'm happy to coordinate. Please let me know if you'd like a CVE/GHSA and how you'd like to
be credited.

Thanks,
`<name>` · `<contact>`
