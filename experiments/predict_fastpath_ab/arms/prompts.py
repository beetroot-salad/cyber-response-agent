"""Prompt builders for arms A/B/C.

Kept minimal and self-contained — we are NOT trying to reproduce the live
predict prompt in full. The experiment is asking: "given priors of varying
strength + a small alert summary, does each arm pick the right lead?"
That's a tighter question than "does the live prompt scaffold work."
"""

from __future__ import annotations

import json
import textwrap
from typing import Any

# ---------------------------------------------------------------------------
# Shared system prompts
# ---------------------------------------------------------------------------

_BASE_SYSTEM = """\
You are PREDICT — the lead-selection step of a security alert investigation
loop. Your only job: pick exactly one lead from the playbook's available leads
that best discriminates between the candidate hypotheses for this alert.

Output requirement: emit a single line containing exactly:

    selected_lead: <lead-slug>

No prose. No explanation. No YAML fence. The slug must come from the
"Available leads" list in the user prompt.
"""

_PRIMED_SYSTEM = _BASE_SYSTEM + """

Treat the past-investigation prior in the user prompt as your baseline. Use
the prior's `recommended_lead` unless the alert specifically contradicts it
(novel field, conflicting key attribute, or new entity classification not
seen in the precedent).
"""

_HAIKU_SCREEN_SYSTEM = """\
You are PREDICT-SCREEN — a fast validation step. The user prompt contains a
strong prior recommendation from a past investigation.

Decide one of:
- Emit  `selected_lead: <prior-recommended-lead>`  if the alert matches the
  prior cleanly and you have no concrete reason to override.
- Emit  `selected_lead: ESCALATE`  if the alert has a discriminating field
  the prior doesn't cover, or any specific signal that the prior's lead
  would be wrong.

Output a single line. No prose, no explanation.
"""


def _alert_brief(alert: dict, signature_id: str) -> str:
    keys = ["data", "syscheck", "rule", "agent"]
    summary = {k: alert.get(k) for k in keys if alert.get(k)}
    return f"signature_id: {signature_id}\nalert:\n{json.dumps(summary, indent=2)}"


def _prologue_brief(prologue: dict) -> str:
    return "prologue:\n" + json.dumps(prologue, indent=2)


def _leads_list(catalog: list[str]) -> str:
    return "Available leads:\n" + "\n".join(f"  - {l}" for l in sorted(catalog))


def _prior_block(prior_strength: str, gate_decision: dict) -> str:
    """Render the past-investigation priors block injected into A/B/C."""
    if prior_strength == "none":
        return "## Past-investigation priors\n(no matches at any tier)"
    verdict = gate_decision.get("verdict", "moderate")
    if verdict == "exact":
        cases = gate_decision.get("matched_cases", [])
        rec = gate_decision.get("selected_lead")
        return textwrap.dedent(f"""
            ## Past-investigation priors
            Match strength: EXACT (all 11 IFF conditions hold)
            Matched precedent cases: {cases}
            recommended_lead: {rec}
            Per past investigations of this exact prologue topology + key
            attributes, the strongest discriminating lead at this position
            was `{rec}`.
        """).strip()
    if verdict == "strong":
        cands = gate_decision.get("candidate_leads", [])
        cases = gate_decision.get("matched_cases", [])
        return textwrap.dedent(f"""
            ## Past-investigation priors
            Match strength: STRONG (topology + outcome + lead-fidelity pass;
            key-attribute alignment incomplete)
            Matched precedent cases: {cases}
            candidate_leads (one of these is the historical pick): {cands}
        """).strip()
    if verdict == "moderate":
        return textwrap.dedent("""
            ## Past-investigation priors
            Match strength: MODERATE (topology overlap only; no key-attribute
            alignment confirmed)
            No specific lead recommendation.
        """).strip()
    return "## Past-investigation priors\n(weak/none — scaffold from first principles)"


# ---------------------------------------------------------------------------
# Per-arm builders
# ---------------------------------------------------------------------------


def build_arm_a(
    *, alert: dict, prologue: dict, signature_id: str,
    lead_catalog: list[str], gate_decision: dict, prior_strength: str,
) -> tuple[str, str]:
    """Arm A — control Sonnet. Today's prior block (vague — no recommendation)."""
    user = "\n\n".join([
        _alert_brief(alert, signature_id),
        _prologue_brief(prologue),
        _leads_list(lead_catalog),
        _prior_block(prior_strength, gate_decision),
    ])
    return _BASE_SYSTEM, user


def build_arm_b(
    *, alert: dict, prologue: dict, signature_id: str,
    lead_catalog: list[str], gate_decision: dict, prior_strength: str,
) -> tuple[str, str]:
    """Arm B — primed Sonnet. Strong-prior block + 'use as baseline' system."""
    user = "\n\n".join([
        _alert_brief(alert, signature_id),
        _prologue_brief(prologue),
        _leads_list(lead_catalog),
        _prior_block(prior_strength, gate_decision),
    ])
    return _PRIMED_SYSTEM, user


def build_arm_c(
    *, alert: dict, prologue: dict, signature_id: str,
    lead_catalog: list[str], gate_decision: dict, prior_strength: str,
) -> tuple[str, str]:
    """Arm C — Haiku screen-predict. Only useful when the gate found a strong/exact prior."""
    user = "\n\n".join([
        _alert_brief(alert, signature_id),
        _prologue_brief(prologue),
        _leads_list(lead_catalog),
        _prior_block(prior_strength, gate_decision),
    ])
    return _HAIKU_SCREEN_SYSTEM, user
