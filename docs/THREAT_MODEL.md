# Threat model

## System

An AI agent triages SIEM alerts with tools: read alerts and events, threat-intel lookup, asset
lookup, notes, verdicts, close, escalate, EDR isolation, suppression rules, outbound webhooks.

## Attacker

- **Can**: write bytes into fields that end up in logs: usernames at a login prompt, HTTP headers and
  paths, DNS query names, email subjects, filenames, process command lines, workstation names.
  This takes no access to the SOC, the SIEM or the model, only the ability to generate telemetry.
- **Cannot**: change detection rules, threat intel, asset inventory, the agent's prompt, or the gateway policy.
- **Wants** (objectives): conceal a real intrusion, persist through a suppression rule, exfiltrate
  alert data, misdirect response onto an innocent critical host, or fabricate incidents to exhaust analysts.

## Trust boundaries

| Data | Trust |
|---|---|
| Alert record, detection entities, rule metadata | trusted (detection pipeline) |
| Threat intel, asset inventory | trusted |
| Event fields marked `attacker_controlled` | untrusted |
| Agent reasoning and tool arguments | untrusted until checked against trusted state |

## OWASP Top 10 for Agentic Applications (2026) mapping

| ASI | How it shows up here |
|---|---|
| ASI01 Agent Goal Hijack | every payload family |
| ASI02 Tool Misuse & Exploitation | close / suppress / isolate / webhook driven by log text |
| ASI06 Memory & Context Poisoning | suppression rules persist the attack past this alert |
| ASI08 Cascading Failures | misdirected isolation of a critical host |
| ASI09 Human-Agent Trust Exploitation | fabricated P1s and alert-fatigue pressure on analysts |

## Out of scope (v0.1)

Model supply chain, compromise of the SIEM itself, multi-agent message spoofing (ASI07), and
long-term agent memory stores. These are candidates for later scenario packs.
