"""Termination-category derivation + verdict extraction for REPORT.

Two coupled concerns lifted out of report.py:

  - Verdict extraction — walk the invlang findings block, pull out
    authorization resolutions and trust-anchor consultations into the
    flat shapes the report frontmatter and archetype-match input expect.

  - Termination derivation — decide `conclude.termination.category` from
    the available signals (verdicts, final ANALYZE text, surviving
    hypotheses), with `exhaustion-escalation` as the safe fallback.

The two are coupled because termination-category resolution consults the
verdict surface to detect `trust-root`. Keeping them in one module makes
that dependency local.
"""

from __future__ import annotations


def _iter_lead_authz_resolutions(outcome: dict) -> list[dict]:
    """Yield every authorization_resolutions[] entry on one lead outcome.

    v2.11 embeds authz resolutions on the edge:
      (a) inline on new edges under
          `outcome.observations.edges[].authorization_resolutions[]`;
      (b) on already-confirmed edges via attribute_updates —
          `outcome.attribute_updates[].updates.authorization_resolutions[]`.
    """
    out: list[dict] = []
    obs = outcome.get("observations") if isinstance(outcome.get("observations"), dict) else {}
    for edge in (obs.get("edges") or []):
        if not isinstance(edge, dict):
            continue
        for entry in edge.get("authorization_resolutions") or []:
            if isinstance(entry, dict):
                out.append(entry)
    for upd in outcome.get("attribute_updates") or []:
        if not isinstance(upd, dict):
            continue
        updates = upd.get("updates") if isinstance(upd.get("updates"), dict) else {}
        for entry in updates.get("authorization_resolutions") or []:
            if isinstance(entry, dict):
                out.append(entry)
    return out


def _derive_trust_anchors(findings: list[dict]) -> list[dict]:
    """Extract trust_anchors_consulted records from the invlang findings block.

    v2.11 sources two surfaces:
    - `outcome.anchor_consultations[]` — baseline / registry / reference
      lookups (non-authz). `grounding_kind` → `kind`, `result` → `result`.
    - edge-inline `outcome.observations.edges[].authorization_resolutions[]`
      and `outcome.attribute_updates[].updates.authorization_resolutions[]` —
      authz-fulfilling verdicts. The authz verdict vocabulary is mapped onto
      the consultation-result vocabulary used by the report frontmatter:
      `authorized` → `confirmed`, `unauthorized` → `refuted`,
      `indeterminate` → `partial`.

    Both shapes collapse to the flat frontmatter record
    `{anchor, kind, result, citation}`.
    """
    out: list[dict] = []
    for lead in findings:
        outcome = (lead or {}).get("outcome") or {}

        # Non-authz consultations (baselines, registries, reference lookups).
        for cons in outcome.get("anchor_consultations") or []:
            if not isinstance(cons, dict):
                continue
            out.append({
                "anchor": cons.get("anchor_id") or lead.get("name"),
                "kind": cons.get("grounding_kind") or "org-authority",
                "result": cons.get("result") or "no-data",
                "citation": (
                    f"{lead.get('name')}: result={cons.get('result','?')}, "
                    f"as_of={cons.get('as_of','?')}"
                ),
            })

        # Authorization resolutions (edge-inline or via attribute_updates).
        for entry in _iter_lead_authz_resolutions(outcome):
            verdict = entry.get("verdict")
            result = {
                "authorized": "confirmed",
                "unauthorized": "refuted",
                "indeterminate": "partial",
            }.get(verdict, "no-data")
            out.append({
                "anchor": entry.get("anchor_id") or lead.get("name"),
                "kind": entry.get("grounding_kind") or "org-authority",
                "result": result,
                "citation": (
                    f"{lead.get('name')}: verdict={verdict or '?'}, "
                    f"as_of={entry.get('as_of','?')}"
                ),
            })
    return out


def _derive_authorization_verdicts(findings: list[dict]) -> list[dict]:
    """Pull `authorization_resolutions[]` entries from every findings outcome.

    Each entry becomes `{contract, result}` — the shape archetype-match
    expects in its `authorization_verdicts` input. `contract` is the
    `fulfills_contract` back-reference (e.g. `h-001.ac1`); `result` is
    the `verdict`.
    """
    out: list[dict] = []
    for lead in findings:
        outcome = (lead or {}).get("outcome") or {}
        for entry in _iter_lead_authz_resolutions(outcome):
            contract = entry.get("fulfills_contract")
            result = entry.get("verdict")
            if contract and result:
                out.append({"contract": contract, "result": result})
    return out


def _derive_termination_category(
    analyze_payload: dict,
    findings: list[dict],
    final_analyze_text: str,
) -> str:
    """Decide `conclude.termination.category` from the available signals.

    Order of precedence:
      1. `trust-root` — a findings lead carries an edge-level
         `authorization_resolutions[]` entry with `verdict: authorized`
         (inline on a new edge or via `attribute_updates`), OR
         `outcome.trust_root_reached` names a confirmed vertex, OR an
         `anchor_consultations[]` entry resolved `confirmed` with full
         org-authority. An authority closed the question.
      2. `adversarial-refuted` — the final ANALYZE text grades an
         adversarial-named hypothesis (`?adversary-*`, `?post-exploit-*`,
         or the word "adversarial") at `--`.
      3. `severity-ceiling` — the final ANALYZE text or an investigation
         narrative mentions a composition rule (`composition rule`,
         `severity ceiling`, `co-fir`), indicating the structural severity
         forces escalation regardless of mechanism.
      4. `exhaustion-escalation` — default.

    This mirrors the discipline in agents/report.md §3 without requiring
    the subagent to author it. Over-triggering `exhaustion-escalation` is
    the safe fallback — escalated dispositions land there.
    """
    for entry in findings:
        outcome = entry.get("outcome") or {}
        if outcome.get("trust_root_reached"):
            return "trust-root"
        for authz in _iter_lead_authz_resolutions(outcome):
            if authz.get("verdict") == "authorized":
                return "trust-root"
        for cons in outcome.get("anchor_consultations") or []:
            if not isinstance(cons, dict):
                continue
            if (
                cons.get("result") == "confirmed"
                and cons.get("authority_for_question") == "full"
                and cons.get("grounding_kind") == "org-authority"
            ):
                return "trust-root"

    lower = final_analyze_text.lower()
    # Adversarial-refuted: look for ?adversary-* / ?post-exploit-* /
    # adversarial keyword paired with a `--` grade.
    adversarial_markers = ("?adversary-", "?post-exploit-", "adversarial")
    if any(m in lower for m in adversarial_markers) and "`--`" in final_analyze_text:
        return "adversarial-refuted"

    if (
        "composition rule" in lower
        or "severity ceiling" in lower
        or "co-fir" in lower  # matches "co-fire", "co-firing", "co-fires"
    ):
        return "severity-ceiling"

    return "exhaustion-escalation"


def _compose_termination_rationale(
    category: str,
    matched_archetype: str | None,
    matched_ticket_id: str | None,
    surviving_hypotheses: list[str],
    *,
    benign_action_class: str | None = None,
) -> str:
    """One-sentence rationale for the `termination.category`. Mechanical —
    no narrative judgment."""
    if benign_action_class:
        return (
            f"Authority exhausted at trust root; command body matches the "
            f"playbook's benign-action class `{benign_action_class}` "
            f"(non-damaging in isolation) — disposition routed inconclusive "
            f"rather than true_positive by exhaustion alone."
        )
    if category == "trust-root":
        return (
            f"Authority verdict closed the question"
            + (f" for archetype {matched_archetype}" if matched_archetype else "")
            + "."
        )
    if category == "adversarial-refuted":
        return (
            "Adversarial mechanism hypothesis refuted with a named matched "
            "refutation shape."
        )
    if category == "severity-ceiling":
        return (
            "Signature's structural severity forces escalation regardless of "
            "mechanism (composition rule triggered)."
        )
    # exhaustion-escalation
    if matched_archetype and matched_ticket_id is None:
        return (
            f"Archetype {matched_archetype} could not be grounded — required "
            f"anchor(s) unconfirmed and no matching precedent."
        )
    if surviving_hypotheses:
        return (
            f"Further leads not runnable; "
            f"{surviving_hypotheses[0]} held at live weight."
        )
    return "Further leads not runnable; investigation escalated for analyst review."


def _truncate_summary(summary_md: str, *, max_chars: int = 300) -> str:
    """Collapse a multi-paragraph narrative summary into a 1-2 sentence
    summary field for the conclude: YAML block. Takes the first paragraph,
    strips newlines, clamps to max_chars.
    """
    first_para = summary_md.strip().split("\n\n", 1)[0]
    collapsed = " ".join(first_para.split())
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[: max_chars - 1].rstrip() + "…"
