# Security and responsible use

## Intended use

gatekeep is for testing AI SOC agents **you own or are explicitly authorized to test**, in lab or
test environments. Do not inject payloads into production telemetry or third-party systems.

Built-in guardrails:
- `gatekeep lab inject` and `gatekeep lab survival` refuse targets that resolve to public IP addresses
  and require `--i-own-this-lab`.
- The corpus uses only reserved names and addresses (RFC 2606 `.example`/`.invalid`, RFC 5737 TEST-NET).
- Payloads instruct an AI agent. They contain no exploit code and no malware.

## Finding issues in other projects

Report privately first (see `docs/DISCLOSURE_TEMPLATE.md`), allow a reasonable fix window (90 days by
default), and coordinate publication with the maintainers.

## Reporting a vulnerability in gatekeep

Use GitHub private vulnerability reporting on this repository. Please do not open a public issue.
