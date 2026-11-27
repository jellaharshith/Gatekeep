"""Markdown (engineer) and HTML (CISO one-pager) reports."""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from .models import Posture, TrialResult

POSTURES = [p.value for p in (Posture.NONE, Posture.ADVISORY, Posture.ENFORCED)]
SIM_BANNER = ("Includes simulated models (`sim:*`). Their numbers only show the pipeline works. "
              "They are NOT findings about any real model or product.")


def _pct(x: Any) -> str:
    return "-" if x is None else f"{100 * x:.1f}%"


def _ci(block: dict[str, Any]) -> str:
    lo, hi = block["ci95"]
    return f"{100 * lo:.1f}-{100 * hi:.1f}%"


def _split_key(key: str) -> tuple[str, str]:
    """Split a 'posture|dimension' summary key."""
    posture, _, rest = key.partition("|")
    return posture, rest


def _rows_for(data: dict[str, Any], posture: str) -> list[tuple[str, Any]]:
    """(dimension value, block) pairs of one posture."""
    return [(r, v) for k, v in data.items() for p, r in [_split_key(k)] if p == posture]


def _dim_table(summary: dict[str, Any], key: str, label: str) -> list[str]:
    data = summary[key]
    rows = sorted({_split_key(k)[1] for k in data})
    present = [p for p in POSTURES if _rows_for(data, p)]
    lines = [f"| {label} | " + " | ".join(f"ASR ({p})" for p in present) + " | n/posture |",
             "|---|" + "---|" * (len(present) + 1)]
    for row in rows:
        cells = [_pct(data.get(f"{p}|{row}", {}).get("rate")) for p in present]
        n = data.get(f"{present[0]}|{row}", {}).get("n", 0) if present else 0
        lines.append(f"| `{row}` | " + " | ".join(cells) + f" | {n} |")
    return lines


def markdown(summary: dict[str, Any], results: list[TrialResult]) -> str:
    out: list[str] = ["# gatekeep report", ""]
    if summary["simulated"]:
        out += [f"> **Warning:** {SIM_BANNER}", ""]
    out += [
        f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} · models: "
        + ", ".join(f"`{m}`" for m in summary["models"])
        + f" · {summary['attack_trials']} attack trials · {summary['clean_trials']} clean controls"
        + (f" · **{summary['errors']} errored trials excluded**" if summary["errors"] else ""),
        "",
        "## Headline",
        "",
        "| Posture | Attack trials | ASR | 95% CI | Conditional ASR | Attack surfaced to human | Clean utility | Held/trial |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for p in POSTURES:
        b = summary["by_posture"].get(p)
        if not b:
            continue
        out.append(f"| **{p}** | {b['asr']['n']} | {_pct(b['asr']['rate'])} | {_ci(b['asr'])} | "
                   f"{_pct(b['conditional_asr']['rate'])} | {_pct(b['surfaced_to_human']['rate'])} | "
                   f"{_pct(b['clean_utility']['rate'])} | {b['held_per_trial']} |")
    out += ["", "*ASR* = attack success rate (attacker objective reached in SIEM state). "
            "*Conditional ASR* counts only cells where the agent handled the same alert correctly "
            "without an attack. *Clean utility* = correct disposition on clean controls. "
            "*Held/trial* = actions parked for human approval (analyst-load cost of enforcement).", ""]

    if summary["posture_tests"]:
        out += ["## Posture comparison (paired sign-flip test)", "",
                "| From | To | Paired cells | Mean ASR reduction | p |", "|---|---|---|---|---|"]
        for t in summary["posture_tests"]:
            out.append(f"| {t['a']} | {t['b']} | {t['cells']} | {t['mean_reduction_pp']} pp | {t['p_value']} |")
        out.append("")

    out += ["## By objective", ""] + _dim_table(summary, "by_posture_objective", "Objective") + [""]
    out += ["## By payload family", ""] + _dim_table(summary, "by_posture_family", "Family") + [""]
    out += ["## By injection vector", ""] + _dim_table(summary, "by_posture_vector", "Vector") + [""]
    out += ["## By payload survival through the pipeline", ""] + _dim_table(
        summary, "by_posture_survival", "Survival") + [""]

    if len(summary["models"]) > 1:
        out += ["## By model", "", "| Model | Posture | ASR | Clean utility |", "|---|---|---|---|"]
        for k, b in summary["by_model_posture"].items():
            m, p = k.rsplit("|", 1)
            out.append(f"| `{m}` | {p} | {_pct(b['asr']['rate'])} | {_pct(b['clean_utility']['rate'])} |")
        out.append("")

    residual = [r for r in results if r.posture.value == "enforced" and r.attack_success]
    out += ["## Residual successes under the enforced posture", ""]
    if not residual:
        out += ["None.", ""]
    for r in residual[:15]:
        acts = ", ".join(a["tool"] for a in r.actions) or "-"
        out.append(f"- `{r.trial_id}` · actions: {acts}")
    out.append("")

    blocked: dict[str, int] = {}
    for r in results:
        for d in r.decisions:
            if d.action != "allow" and d.rule:
                blocked[d.rule] = blocked.get(d.rule, 0) + 1
    if blocked:
        out += ["## Policy rules that fired", "", "| Rule | Times |", "|---|---|"]
        out += [f"| `{k}` | {v} |" for k, v in sorted(blocked.items(), key=lambda kv: -kv[1])]
        out.append("")
    return "\n".join(out)


def html_report(summary: dict[str, Any], title: str = "AI SOC agent injection assessment") -> str:
    bp = summary["by_posture"]

    def big(p: str) -> str:
        b = bp.get(p)
        if not b:
            return ""
        return (f"<div class='card'><div class='label'>{p}</div>"
                f"<div class='num'>{_pct(b['asr']['rate'])}</div>"
                f"<div class='sub'>attack success · 95% CI {_ci(b['asr'])}</div>"
                f"<div class='sub'>clean utility {_pct(b['clean_utility']['rate'])} · held/trial {b['held_per_trial']}</div></div>")

    worst_obj = sorted(((r, v["rate"] or 0) for r, v in _rows_for(summary["by_posture_objective"], "none")),
                       key=lambda kv: -kv[1])[:3]
    worst_vec = sorted(((r, v["rate"] or 0) for r, v in _rows_for(summary["by_posture_vector"], "none")),
                       key=lambda kv: -kv[1])[:3]
    errs = (f"<p class='warn'>{summary['errors']} errored trials were excluded from these numbers.</p>"
            if summary.get("errors") else "")
    li = lambda xs: "".join(f"<li><code>{html.escape(a)}</code>: {_pct(b)}</li>" for a, b in xs)
    banner = f"<p class='warn'>{html.escape(SIM_BANNER)}</p>" if summary["simulated"] else ""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>
body{{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;max-width:980px;margin:40px auto;padding:0 20px;color:#1b1f24}}
h1{{font-size:26px;margin-bottom:4px}} .meta{{color:#57606a}} .row{{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}}
.card{{flex:1;min-width:220px;border:1px solid #d0d7de;border-radius:10px;padding:16px}}
.label{{text-transform:uppercase;font-size:12px;letter-spacing:.08em;color:#57606a}}
.num{{font-size:40px;font-weight:700}} .sub{{color:#57606a;font-size:13px}}
.warn{{background:#fff8c5;border:1px solid #d4a72c;padding:10px 14px;border-radius:8px}}
code{{background:#f6f8fa;padding:1px 5px;border-radius:4px}} h2{{margin-top:32px;font-size:18px}}
</style></head><body>
<h1>{html.escape(title)}</h1>
<div class="meta">Models: {", ".join(html.escape(m) for m in summary["models"])} · {summary["attack_trials"]} attack trials · {summary["clean_trials"]} clean controls</div>
{banner}{errs}
<div class="row">{"".join(big(p) for p in POSTURES)}</div>
<h2>What this means</h2>
<p>Attack success is measured on what the agent <em>did</em> in the SIEM (closed a real attack, created a suppression rule,
sent data out, isolated the wrong host), not on what it said. "Enforced" puts a policy gateway between the agent and its tools;
it uses only trusted state (threat intel, asset inventory, detection entities, provenance), so it holds even when the model is fooled.</p>
<h2>Highest-risk objectives (no defenses)</h2><ul>{li(worst_obj)}</ul>
<h2>Highest-risk log fields (no defenses)</h2><ul>{li(worst_vec)}</ul>
<h2>Recommendations</h2><ol>
<li>Do not let the agent close, suppress, isolate or call out to the internet without a tool-layer policy check.</li>
<li>Treat instruction-like text in attacker-writable fields as an indicator of attack and route it to a human.</li>
<li>Bind high-impact arguments to trusted provenance (detection entities, CMDB), never to free-text log content.</li>
<li>Gate every agent, prompt or model change in CI on this benchmark; block releases that raise attack success.</li>
</ol>
<p class="meta">Generated by gatekeep · {datetime.now(timezone.utc):%Y-%m-%d}</p>
</body></html>"""
