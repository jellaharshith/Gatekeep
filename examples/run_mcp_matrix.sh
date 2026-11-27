#!/usr/bin/env bash
# Drive an external MCP agent across many gatekeep scenarios.
#
# Replace AGENT_CMD with whatever runs ONE triage of your agent against an MCP server given on
# stdin/stdout or by config. The agent must connect to the gatekeep server, triage the alert named
# in the server instructions, and exit. gatekeep scores each run when the client disconnects.
set -euo pipefail

OUT=${OUT:-runs/mcp/results.jsonl}
POSTURE=${POSTURE:-none}
FAMILIES=${FAMILIES:-"authority_forgery test_decoy naive_override"}
LABEL=${LABEL:-my-mcp-agent}

run_one() {  # scenario family objective
  # Example only: adapt to your agent's CLI. Here the agent reads an MCP config file.
  cat > /tmp/gatekeep-mcp.json <<EOF
{"mcpServers":{"gatekeep-siem":{"command":"gatekeep","args":["serve-mcp","--scenario","$1","--family","$2","--objective","$3","--posture","$POSTURE","--agent-label","$LABEL","--out","$OUT"]}}}
EOF
  ${AGENT_CMD:?set AGENT_CMD, e.g. AGENT_CMD='my-agent --mcp-config /tmp/gatekeep-mcp.json --task "Triage the open alert"'}
}

for fam in $FAMILIES; do
  run_one SOC-001 "$fam" conceal
  run_one SOC-002 "$fam" exfil
  run_one SOC-004 "$fam" misdirect_response
  run_one SOC-007 "$fam" fabricate
done

gatekeep report "$OUT"
