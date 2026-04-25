"""ANALYZE phase handler.

Interprets gather observations against the scaffolding PREDICT set up
(hypotheses, predictions, authz contracts) and decides whether the
investigation is terminal. Does NOT decide what to investigate next — that is
PREDICT's job. ANALYZE's routing decision is binary: `continue` → PREDICT |
`halt` → REPORT.

The ANALYZE subagent (agents/analyze.md, model=sonnet) emits a single
envelope with a top-level `analyze:` key (v2.12). The envelope carries
per-lead resolutions, authority verdicts, authorization closures, impact
grades, anomalies, data wishes, and the routing trailer. The handler
synthesizes a prose `## ANALYZE (loop N)` section from the envelope and
appends it to investigation.md.

Handler responsibilities:
    - computes `loop_n` from ctx.history (count of PREDICT entries)
    - preloads per-lead raw SIEM payloads from
      `ctx.outputs[Phase.GATHER]["raw_details_paths"]` into a
      `<raw_details>` block alongside `<alert>` + `<investigation>`
    - invokes the subagent via the shared `_subagent.invoke_subagent` wrapper
    - parses the `analyze:` envelope via `parse_analyze_envelope`
    - back-fills `unresolved_prescribed_set` from `ctx.outputs[Phase.GATHER]`
      when the subagent didn't compute it
    - renders a prose `## ANALYZE (loop N)` section from the envelope and
      appends to investigation.md, pre-validated via `validate_companion()`
    - returns PhaseResult(next_phase, payload) with a backwards-compat
      payload shape (route, termination_category, disposition, confidence,
      matched_archetype, surviving_hypotheses, unresolved_prescribed_set)

Input (Context):
    ctx.run_dir, ctx.signature_id, ctx.history, ctx.alert,
    ctx.outputs[Phase.GATHER] (carries prescribed_leads, executed_leads,
    raw_details_paths)

Output:
    PhaseResult
      - route=halt      → Phase.REPORT
      - route=continue  → Phase.PREDICT
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._context_loader import (
    format_alert_block,
    format_current_gather_block,
    format_investigation_block,
    load_alert,
    load_investigation_md,
    load_run_salt,
)
from scripts.handlers._output_parser import (
    AnalyzeEnvelope,
    AnalyzeOutputError,
    parse_analyze_envelope,
)
from scripts.handlers._subagent import (
    invoke_subagent as _shared_invoke,
)


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_ANALYZE_TIMEOUT_SECONDS", "300")
)


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


def _invoke_subagent(prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS) -> str:
    """Module-level wrapper over the shared subagent dispatcher.

    Kept as a module-level function so tests can monkeypatch it with
    `monkeypatch.setattr(analyze_handler, "_invoke_subagent", stub)`.
    """
    return _shared_invoke("analyze", prompt, timeout=timeout)


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def _compute_loop_n(ctx: Context) -> int:
    """Infer the current loop number from ctx.history.

    loop_n is the count of PREDICT entries observed — every loop begins
    with PREDICT, so the most recent PREDICT closes the current loop.
    Fallback to 1 for safety.
    """
    return sum(1 for p in ctx.history if p == Phase.PREDICT.value) or 1


def _load_raw_details(ctx: Context) -> str:
    """Read the per-lead raw payloads gather-handler wrote to disk and
    concatenate them into a `<raw_details>` block for the analyze prompt.

    `ctx.outputs[Phase.GATHER]["raw_details_paths"]` carries the absolute
    paths. Returns an empty string when no paths are present (screen-matched
    flows, pre-v2.12 runs, or gather leads that produced no raw payload).
    """
    gather_out = ctx.outputs.get(Phase.GATHER)
    if not isinstance(gather_out, dict):
        return ""
    paths = gather_out.get("raw_details_paths") or []
    if not paths:
        return ""
    lines = ["<raw_details>"]
    for p in paths:
        path = Path(p)
        try:
            body = path.read_text()
        except FileNotFoundError:
            continue
        lines.append(f"  <lead id=\"{path.stem}\">")
        lines.append(body)
        lines.append(f"  </lead>")
    lines.append("</raw_details>")
    return "\n".join(lines)


def _assemble_prompt(ctx: Context) -> str:
    """Build the analyze subagent prompt with all deterministic context inline.

    The subagent receives alert.json, investigation.md, and the per-lead
    raw SIEM payloads (under `<raw_details>`) preloaded — no Read tool
    calls required. Archetype context is not preloaded; archetype labeling
    moved to the REPORT phase.
    """
    loop_n = _compute_loop_n(ctx)
    alert = load_alert(ctx.run_dir)
    salt = load_run_salt(ctx.run_dir)
    investigation_md = load_investigation_md(ctx.run_dir)

    blocks = [
        f"run_dir={ctx.run_dir}\nloop_n={loop_n}\nsignature_id={ctx.signature_id}",
        format_alert_block(alert, salt),
        format_investigation_block(investigation_md, mode="analyze"),
    ]
    gather_out = ctx.outputs.get(Phase.GATHER)
    if isinstance(gather_out, dict):
        current_gather = format_current_gather_block(gather_out.get("leads") or [])
        if current_gather:
            blocks.append(current_gather)
    raw_details_block = _load_raw_details(ctx)
    if raw_details_block:
        blocks.append(raw_details_block)
    return "\n\n".join(blocks)


# ---------------------------------------------------------------------------
# Routing payload (backwards-compat projection from the envelope)
# ---------------------------------------------------------------------------


def _routing_payload(envelope: AnalyzeEnvelope) -> dict[str, Any]:
    """Flatten the envelope's routing trailer + interpretation fields into
    the payload shape REPORT / PREDICT consume.

    Preserved keys (pre-v2.12 compat):
        route, termination_category, disposition, confidence,
        matched_archetype, surviving_hypotheses (on halt)
        route, unresolved_prescribed_set (on continue)

    New keys (v2.12):
        resolutions_by_lead, trust_anchor_by_lead, legitimacy_by_lead,
        impact_by_lead, anomalies, data_wishes
    """
    r = envelope.routing
    route = r["decision"]
    out: dict[str, Any] = {"route": route}
    if route == "halt":
        out["termination_category"] = r["termination_category"]
        out["disposition"] = r["disposition"]
        out["confidence"] = r["confidence"]
        out["matched_archetype"] = r.get("matched_archetype")
        out["surviving_hypotheses"] = r.get("surviving_hypotheses", [])
    else:
        ups = r.get("unresolved_prescribed_set")
        if ups:
            out["unresolved_prescribed_set"] = ups

    # Expose the envelope's structured fields so REPORT can consume them
    # without re-parsing investigation.md. These are pass-through: the
    # handler does not re-validate them here (invlang_validate will when
    # REPORT writes the findings block, or earlier via validate_companion
    # when the handler appends its prose section).
    out["resolutions_by_lead"] = envelope.resolutions_by_lead
    out["trust_anchor_by_lead"] = envelope.trust_anchor_by_lead
    out["legitimacy_by_lead"] = envelope.legitimacy_by_lead
    out["impact_by_lead"] = envelope.impact_by_lead
    out["anomalies"] = envelope.anomalies
    out["data_wishes"] = envelope.data_wishes
    return out


def _backfill_unresolved_prescribed_set(
    payload: dict[str, Any], ctx: Context,
) -> dict[str, Any]:
    """On continue, compute unresolved_prescribed_set from GATHER payload if
    the subagent didn't emit it. Even if gather-composite's scope-check is
    bypassed, ANALYZE still surfaces the gap so PREDICT can re-prescribe.
    """
    if payload.get("route") != "continue":
        return payload
    if payload.get("unresolved_prescribed_set"):
        return payload
    gather_out = ctx.outputs.get(Phase.GATHER)
    if not isinstance(gather_out, dict):
        return payload
    prescribed = gather_out.get("prescribed_leads")
    executed = gather_out.get("executed_leads")
    if not isinstance(prescribed, list) or not isinstance(executed, list):
        return payload
    executed_set = set(executed)
    unresolved = [lead for lead in prescribed if lead not in executed_set]
    if unresolved:
        payload["unresolved_prescribed_set"] = unresolved
    return payload


# ---------------------------------------------------------------------------
# Prose section composition
# ---------------------------------------------------------------------------


_WEIGHT_ORDER = {"++": 0, "+": 1, "-": 2, "--": 3}


def _compose_section(envelope: AnalyzeEnvelope, loop_n: int) -> str:
    """Render the envelope as a `## ANALYZE (loop N)` prose section.

    Resolutions render as an assessment list keyed by hypothesis id; the
    `reasoning` string on each resolution is the human-readable rationale.
    Anomalies + data_wishes replace the old prose Self-report block.
    """
    lines = [f"## ANALYZE (loop {loop_n})", ""]

    # Collect all resolution entries across leads; order by hypothesis id.
    # Assessments read better flat (one entry per hypothesis) than grouped
    # by lead — a hypothesis graded on multiple leads shows up as multiple
    # lines with distinct lead_refs, which matches the audit-trail intent.
    lines.append("**Assessment:**")
    assessment_lines: list[str] = []
    for lead_ref, entries in envelope.resolutions_by_lead.items():
        for e in entries:
            hid = e.get("hypothesis_id", "?")
            w = e.get("weight", "?")
            reasoning = e.get("reasoning", "")
            assessment_lines.append(
                f"- {hid} ({w}) via {lead_ref} — {reasoning}"
            )
    if not assessment_lines:
        assessment_lines.append("- (no resolutions this loop)")
    lines.extend(assessment_lines)

    # Authority verdicts, when any.
    if envelope.trust_anchor_by_lead:
        lines.append("")
        lines.append("**Authority verdicts:**")
        for lead_ref, r in envelope.trust_anchor_by_lead.items():
            verdict = r.get("verdict", "?")
            reasoning = r.get("reasoning", "")
            lines.append(f"- {lead_ref}: {verdict} — {reasoning}")

    # Routing.
    r = envelope.routing
    lines.append("")
    if r["decision"] == "halt":
        lines.append(
            f"**Route:** halt → termination_category: {r['termination_category']}, "
            f"disposition: {r['disposition']}, confidence: {r['confidence']}"
        )
        sh = r.get("surviving_hypotheses") or []
        if sh:
            lines.append(f"**Surviving hypotheses:** {', '.join(sh)}")
    else:
        lines.append("**Route:** continue")
        ups = r.get("unresolved_prescribed_set") or []
        if ups:
            lines.append(f"**Unresolved prescribed:** {', '.join(ups)}")

    # Anomalies + data wishes (replacing the old Self-report block).
    if envelope.anomalies or envelope.data_wishes:
        lines.append("")
        lines.append("**Self-report:**")
        if envelope.anomalies:
            lines.append("- Anomalies:")
            for a in envelope.anomalies:
                lines.append(f"  - {a}")
        if envelope.data_wishes:
            lines.append("- Data wishes:")
            for d in envelope.data_wishes:
                lines.append(f"  - {d}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Invlang findings synthesis
# ---------------------------------------------------------------------------


_PROLOGUE_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.DOTALL)


def _first_prologue_vertex_id(investigation_md: str) -> str | None:
    """Return the first `v-*` id declared in any prologue block of the
    companion, or None if no prologue block is present.

    Used as the default `target` for synthesized `findings[]` lead entries
    when the gather envelope doesn't specify one. Non-SCREEN flows don't
    prescribe a target vertex per lead — the lead is investigating the
    alert's subject vertex, which is always v-001 in practice.
    """
    for body in _PROLOGUE_BLOCK_RE.findall(investigation_md):
        try:
            doc = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        vertices = doc.get("prologue", {}).get("vertices") or []
        for v in vertices:
            if isinstance(v, dict) and isinstance(v.get("id"), str):
                return v["id"]
    return None


def _hypothesis_name_to_id_map(investigation_md: str) -> dict[str, str]:
    """Build a `{name → id}` map from every `hypothesize:` block in the
    companion.

    The analyze subagent is observed to emit `hypothesis_id: "?name"`
    (playbook name) when PREDICT did not declare a matching `h-*` entry,
    and sometimes even when it did — the prose-first bias of the prompt
    drifts toward names. Resolutions whose `hypothesis_id` is a name
    get translated to the matching declared ID when one exists; entries
    that resolve to nothing get dropped from the synthesized findings
    so the invlang validator doesn't reject the write.

    Both `name` and `id` are keyed — calling `.get(value, value)` falls
    through cleanly whether the subagent emitted the name or the ID.
    """
    mapping: dict[str, str] = {}
    for body in _PROLOGUE_BLOCK_RE.findall(investigation_md):
        try:
            doc = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        hypotheses = doc.get("hypothesize", {}).get("hypotheses") or []
        for h in hypotheses:
            if not isinstance(h, dict):
                continue
            hid = h.get("id")
            name = h.get("name")
            if isinstance(hid, str) and hid:
                # ID is its own key — lets `.get(value, None)` work whether
                # the subagent emitted the ID or the name.
                mapping[hid] = hid
                if isinstance(name, str) and name:
                    mapping[name] = hid
    return mapping


def _translate_trust_anchor_to_consultation(
    entry: dict[str, Any],
) -> dict[str, Any] | None:
    """Map an analyze-envelope trust_anchor_result entry onto invlang's
    `outcome.anchor_consultations[]` shape (see schema §Lead outcome).

    The envelope carries {asks, verdict, reasoning}. Anchor consultations
    require {anchor_id, anchor_kind, grounding_kind, result, as_of,
    authority_for_question}. We translate what we can and leave the rest
    to downstream validators — a malformed consultation is preferable to
    silent loss of the trust-anchor signal.
    """
    if not isinstance(entry, dict):
        return None
    asks = entry.get("asks") or []
    anchor_id = asks[0] if asks else None
    verdict = entry.get("verdict")
    # Minimal result mapping: authorized → confirmed, unauthorized → refuted,
    # indeterminate → partial. Schema rule #11 requires anchor_kind +
    # grounding_kind; we use "policy" / "org-authority" as conservative
    # defaults (policy checks against an authority anchor).
    result_map = {
        "authorized": "confirmed",
        "unauthorized": "refuted",
        "indeterminate": "partial",
    }
    out: dict[str, Any] = {
        "anchor_id": anchor_id or "unspecified",
        "anchor_kind": "policy",
        "grounding_kind": entry.get("grounding_kind") or "org-authority",
        "result": result_map.get(verdict, "partial"),
        "as_of": entry.get("as_of"),
        "authority_for_question": entry.get("authority_for_question") or anchor_id or "unspecified",
    }
    if entry.get("reasoning"):
        out["reasoning"] = entry["reasoning"]
    return out


_STRONG_AUTHORITY_KINDS = {"siem-event", "runtime-audit", "authoritative-source"}


def _prologue_authoritative_edges(investigation_md: str) -> list[str]:
    """Return every edge id in the prologue whose authority.kind is in the
    strong-authority set. Used as the default `supporting_edges` for
    `++`/`--` resolutions when the envelope does not name specific edges
    — invlang structural rule requires at least one authoritative edge on
    any non-circumstantial grade, and the lead-level evidence is always
    at least as authoritative as the prologue edges it confirms.
    """
    edge_ids: list[str] = []
    for body in _PROLOGUE_BLOCK_RE.findall(investigation_md):
        try:
            doc = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        edges = doc.get("prologue", {}).get("edges") or []
        for e in edges:
            if not isinstance(e, dict):
                continue
            eid = e.get("id")
            kind = (e.get("authority") or {}).get("kind", "")
            if isinstance(eid, str) and kind in _STRONG_AUTHORITY_KINDS:
                edge_ids.append(eid)
    return edge_ids


def _synthesize_findings_block(
    envelope: AnalyzeEnvelope,
    gather_leads: list[dict[str, Any]],
    loop_n: int,
    default_target: str,
    hypothesis_name_to_id: dict[str, str] | None = None,
    default_supporting_edges: list[str] | None = None,
) -> str:
    """Build the `findings:` invlang YAML block for this loop, combining
    gather's envelope leads with analyze's per-lead interpretation.

    Required lead fields per validator: id, loop, name, target,
    query_details, outcome, resolutions. `outcome: {}` and `resolutions: []`
    are valid when empty — this keeps the synthesis simple for leads with
    no structured observations.

    Returns an empty string when there are no gather leads to ground
    (SCREEN-matched flow or missing gather envelope).
    """
    if not gather_leads:
        return ""

    findings: list[dict[str, Any]] = []
    for lead in gather_leads:
        lead_id = lead.get("id")
        if not isinstance(lead_id, str):
            continue

        query = lead.get("query") or {}
        # The envelope `query` carries {system, template, query, time_window,
        # substitutions} — which matches the schema's `query_details` shape
        # (see schema §Lead). Pass through as-is.
        query_details = query if isinstance(query, dict) else {}

        # Per-lead outcome: start with any structured observations gather
        # emitted, then overlay analyze's interpretation fields.
        outcome: dict[str, Any] = {}
        obs = lead.get("observations")
        if isinstance(obs, dict):
            outcome["observations"] = obs
        attr_updates = lead.get("attribute_updates")
        if isinstance(attr_updates, list) and attr_updates:
            outcome["attribute_updates"] = attr_updates
        consultations = lead.get("consultations")
        if isinstance(consultations, list) and consultations:
            outcome["anchor_consultations"] = consultations

        # Analyze-authored: trust-anchor verdicts → anchor_consultations[].
        trust = envelope.trust_anchor_by_lead.get(lead_id)
        if isinstance(trust, dict):
            consult = _translate_trust_anchor_to_consultation(trust)
            if consult is not None:
                outcome.setdefault("anchor_consultations", []).append(consult)

        # Analyze-authored: legitimacy closures → attribute_updates on the
        # edge with authorization_resolutions[]. The envelope's per-lead
        # entries carry {edge_id, contract_id, verdict, grounding_kind,
        # authority_for_question, as_of, reasoning}. We translate to
        # invlang's authorization_resolutions shape and stash under
        # attribute_updates targeting the edge.
        for legit in envelope.legitimacy_by_lead.get(lead_id, []):
            if not isinstance(legit, dict):
                continue
            edge_id = legit.get("edge_id")
            if not isinstance(edge_id, str):
                continue
            authz_entry = {
                "verdict": legit.get("verdict", "indeterminate"),
                "fulfills_contract": legit.get("contract_id", ""),
                "anchor_kind": "policy",
                "anchor_id": legit.get("authority_for_question", "unspecified"),
                "grounding_kind": legit.get("grounding_kind", "org-authority"),
                "authority_for_question": "full",
                "as_of": legit.get("as_of"),
                "resolved_by_lead": lead_id,
            }
            if legit.get("reasoning"):
                authz_entry["reasoning"] = legit["reasoning"]
            attr_upd = {
                "target": edge_id,
                "updates": {"authorization_resolutions": [authz_entry]},
            }
            outcome.setdefault("attribute_updates", []).append(attr_upd)

        # Analyze-authored: impact grades → outcome.impact_resolutions.
        for ir in envelope.impact_by_lead.get(lead_id, []):
            if not isinstance(ir, dict):
                continue
            # Map envelope shape (prediction_ref, dimension, verdict,
            # grounding_kind, authority_for_question, as_of, reasoning)
            # onto schema shape. The schema's `matched_predicate` +
            # `observed_value` aren't in the envelope; omit.
            outcome.setdefault("impact_resolutions", []).append({
                "prediction_ref": ir.get("prediction_ref"),
                "dimension": ir.get("dimension"),
                "verdict": ir.get("verdict", "indeterminate"),
                "grounded_by_lead": lead_id,
                "grounding_kind": ir.get("grounding_kind", "telemetry-baseline"),
                "authority_for_question": ir.get(
                    "authority_for_question", "full",
                ),
                "as_of": ir.get("as_of"),
                "reasoning": ir.get("reasoning"),
            })

        # Analyze-authored: top-level resolutions (hypothesis grades).
        # Envelope entries carry {hypothesis_id, weight,
        # matched_prediction_ids, matched_refutation_ids, reasoning}.
        # Schema expects {hypothesis, before, after, matched_prediction_ids,
        # matched_refutation_ids, reasoning, ...}. Translate.
        #
        # `hypothesis_id` translation — the analyze subagent is observed to
        # emit playbook names (e.g. `?monitoring-probe`) instead of declared
        # h-ids when PREDICT didn't create a matching record. Resolve via
        # the companion-derived name→id map; drop resolutions whose
        # reference doesn't land on any declared hypothesis (silently —
        # they'd fail rule-#?-id-references at validate time otherwise).
        id_map = hypothesis_name_to_id or {}
        resolutions: list[dict[str, Any]] = []
        for r in envelope.resolutions_by_lead.get(lead_id, []):
            if not isinstance(r, dict):
                continue
            raw_ref = r.get("hypothesis_id", "")
            resolved_id = id_map.get(raw_ref) if id_map else raw_ref
            if not resolved_id:
                # Unknown reference — skip rather than poison the findings
                # block with an undeclared hypothesis id.
                continue
            weight = r.get("weight", "")
            res: dict[str, Any] = {
                "hypothesis": resolved_id,
                "after": weight,
                "matched_prediction_ids": r.get(
                    "matched_prediction_ids", [],
                ),
                "reasoning": r.get("reasoning", ""),
            }
            mrefs = r.get("matched_refutation_ids")
            if mrefs:
                res["matched_refutation_ids"] = mrefs
            # invlang structural rule: ++/-- grades require supporting_edges
            # with at least one authoritative edge. The subagent does not
            # name specific edges (that's graph-level plumbing, not weighing
            # evidence), so the handler defaults to the prologue's
            # authoritative edge list when the grade is committed.
            if weight in ("++", "--"):
                supplied = r.get("supporting_edges") or []
                if not supplied and default_supporting_edges:
                    res["supporting_edges"] = list(default_supporting_edges)
                elif supplied:
                    res["supporting_edges"] = list(supplied)
            resolutions.append(res)

        entry: dict[str, Any] = {
            "id": lead_id,
            "loop": loop_n,
            "name": lead.get("name", ""),
            "target": lead.get("target") or default_target,
            "query_details": query_details,
            "outcome": outcome,
            "resolutions": resolutions,
        }
        findings.append(entry)

    body = yaml.safe_dump({"findings": findings}, sort_keys=False)
    return "```yaml\n" + body + "```\n"


# ---------------------------------------------------------------------------
# Validate + append
# ---------------------------------------------------------------------------


def _validate_and_write(ctx: Context, new_section: str) -> None:
    """Append `new_section` to investigation.md after running
    `validate_companion` as a library check.
    """
    hooks_scripts = str(SOC_AGENT_ROOT / "hooks")
    if hooks_scripts not in sys.path:
        sys.path.insert(0, hooks_scripts)
    from scripts.invlang_validate import validate_companion  # type: ignore

    inv_path = ctx.run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    proposed = (
        current
        + ("\n" if current and not current.endswith("\n") else "")
        + new_section
    )

    errors = validate_companion(proposed, current if current else None)
    if errors:
        raise OrchestrationError(
            "ANALYZE invlang validation failed:\n" + "\n".join(errors)
        )

    inv_path.write_text(proposed)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def handle(ctx: Context) -> PhaseResult:
    loop_n = _compute_loop_n(ctx)
    prompt = _assemble_prompt(ctx)
    raw = _invoke_subagent(prompt)

    try:
        # loop_n is computed handler-side from ctx.history; we don't enforce
        # it against the subagent's emitted `analyze.loop` because retries
        # and recovery paths legitimately drift. The envelope's loop field
        # is an audit-trail carry-through.
        envelope = parse_analyze_envelope(raw)
    except AnalyzeOutputError as exc:
        raise OrchestrationError(
            f"analyze subagent: envelope shape violation — {exc}"
        ) from exc

    payload = _routing_payload(envelope)
    payload = _backfill_unresolved_prescribed_set(payload, ctx)

    # Compose investigation.md section: prose assessment + invlang findings
    # block. The findings block is synthesized from gather's envelope (which
    # the handler stashed in ctx.outputs[Phase.GATHER]["leads"]) plus
    # analyze's interpretation envelope, merged here — gather-handler did
    # not write any invlang YAML, so analyze-handler authors the complete
    # `findings[]` lead block for this loop.
    section = _compose_section(envelope, loop_n)

    gather_out = ctx.outputs.get(Phase.GATHER)
    gather_leads: list[dict[str, Any]] = []
    if isinstance(gather_out, dict):
        raw_leads = gather_out.get("leads") or []
        if isinstance(raw_leads, list):
            gather_leads = [x for x in raw_leads if isinstance(x, dict)]
    investigation_md = load_investigation_md(ctx.run_dir)
    default_target = _first_prologue_vertex_id(investigation_md) or ""
    hypothesis_id_map = _hypothesis_name_to_id_map(investigation_md)
    default_supporting_edges = _prologue_authoritative_edges(investigation_md)
    findings_block = _synthesize_findings_block(
        envelope, gather_leads, loop_n, default_target,
        hypothesis_name_to_id=hypothesis_id_map,
        default_supporting_edges=default_supporting_edges,
    )
    if findings_block:
        section = section + "\n" + findings_block

    _validate_and_write(ctx, section)

    next_phase = (
        Phase.REPORT if payload["route"] == "halt" else Phase.PREDICT
    )
    return PhaseResult(next_phase=next_phase, payload=payload)
