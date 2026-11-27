# AI SOC agent injection assessment: `<Customer>`

**Dates:** `<start>`-`<end>` · **Scope:** `<agents, environments>` · **Assessor:** `<name>`

## 1. Executive summary (5 lines max)

- Without defenses, attacker-written log text made the agent take a harmful action in **__%** of attempts (95% CI __-__%).
- The worst outcome observed: `<e.g. a confirmed web-shell alert was auto-closed>`.
- With the enforcement policy, this fell to **__%**, at a cost of **__** human approvals per alert.
- Clean triage quality was **__%** without the policy and **__%** with it.
- Recommendation: `<adopt policy / fix N items / re-test date>`.

## 2. What we tested

| Agent | Model | Actions it can take alone | Log sources |
|---|---|---|---|
| | | | |

## 3. Results

| Posture | ASR | 95% CI | Clean utility | Held/alert |
|---|---|---|---|---|
| none | | | | |
| advisory | | | | |
| enforced | | | | |

Top risks by objective and by log field: paste the tables from `report.md`.

## 4. Findings

### F-1 `<title>` (severity: `<critical/high/medium/low>`)
- **What happened:** 
- **Why it matters:** 
- **Evidence:** trial ids, transcript excerpt, state diff
- **Fix:** 

## 5. Policy decisions made with your team

| Rule | Action | Rationale |
|---|---|---|

## 6. Not solved / residual risk

Be explicit, for example: fabricated-alert pressure is only rate-limited; vendor product internals were black-box.

## 7. Re-test and CI

The gate is installed in `<repo>`: build fails if enforced ASR > __% or clean utility < __%.
