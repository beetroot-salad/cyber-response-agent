"""Impact-axis invlang checks (spec rules #29–#31) + CONCLUDE two-axis block.

Covers the lead-level impact_predictions[] / impact_resolutions[]
primitive:
- prediction structure: id pattern, required fields, one observable per
  claim (rule #29)
- resolution back-refs, dimension match, grounding-kind enum, required
  fields (rule #30)
- closure at CONCLUDE (rule #31)
- CONCLUDE.impact_verdict + impact_severity + deferred_impact_predictions
  shape
"""

from __future__ import annotations

from typing import Any

from hooks.scripts.invlang_common import (
    _CONCLUDE_IMPACT_VERDICTS,
    _IMPACT_DIMENSIONS,
    _IMPACT_GROUNDING_KINDS,
    _IMPACT_PREDICTION_ID_RE,
    _IMPACT_RES_REQUIRED_FIELDS,
    _IMPACT_SEVERITIES,
    _IMPACT_VERDICTS,
    _collect_impact_prediction_refs,
)

# Required fields on every impact_predictions[] entry.
_IMPACT_PRED_REQUIRED_FIELDS = (
    "id",
    "dimension",
    "claim",
    "on_match",
    "on_mismatch",
    "on_indeterminate",
    "escalation_on",
)

# Compound-claim detector (mirrors
# invlang_checks_hypothesis._COMPOUND_CLAIM_PATTERNS): one observable per
# predicate; AND/OR/; compounds must be split into separate entries.
_COMPOUND_CLAIM_PATTERNS: tuple[tuple[str, str], ...] = (
    ("; ", "semicolon-separated clauses"),
    (" AND ", "'AND' conjunction between clauses"),
    (" OR ", "'OR' conjunction between clauses"),
)


def _check_impact_prediction_structure(merged: dict[str, Any]) -> list[str]:
    """Rule #29 — impact_predictions[] entries have id + fields + one-observable claim.

    - `id` matches `^ip\\d+$` and is unique within the lead.
    - Required fields (`dimension`, `claim`, `on_match`, `on_mismatch`,
      `on_indeterminate`, `escalation_on`) are present.
    - `dimension` is one of the four axes.
    - `claim` does not pack multiple observables (same compound detector
      used for hypothesis predictions).
    """
    errors: list[str] = []
    for lead in merged.get("findings", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        preds = lead.get("impact_predictions")
        if preds is None:
            continue
        if not isinstance(preds, list):
            errors.append(f"lead {lid}: impact_predictions must be a list")
            continue
        seen_ids: set[str] = set()
        for i, pred in enumerate(preds):
            ctx = f"lead {lid} impact_predictions[{i}]"
            if not isinstance(pred, dict):
                errors.append(f"{ctx}: entry must be a mapping")
                continue

            missing = [f for f in _IMPACT_PRED_REQUIRED_FIELDS if f not in pred]
            if missing:
                errors.append(f"{ctx}: missing required field(s): {sorted(missing)}")

            ipid = pred.get("id")
            if isinstance(ipid, str):
                if not _IMPACT_PREDICTION_ID_RE.match(ipid):
                    errors.append(
                        f"{ctx}: id {ipid!r} does not match pattern ^ip\\d+$ "
                        f"(e.g. ip1, ip2)"
                    )
                elif ipid in seen_ids:
                    errors.append(f"{ctx}: duplicate id {ipid!r} within lead")
                else:
                    seen_ids.add(ipid)

            dimension = pred.get("dimension")
            if dimension is not None and dimension not in _IMPACT_DIMENSIONS:
                errors.append(
                    f"{ctx}: dimension {dimension!r} not in "
                    f"{sorted(_IMPACT_DIMENSIONS)}"
                )

            claim = pred.get("claim")
            if isinstance(claim, str):
                for token, description in _COMPOUND_CLAIM_PATTERNS:
                    if token in claim:
                        errors.append(
                            f"{ctx}: claim contains {description} ({token!r}). "
                            f"Impact predictions name one observable per "
                            f"claim — split compound AND/OR/semicolon claims "
                            f"into separate impact_predictions[] entries."
                        )
                        break  # one complaint per prediction
    return errors


def _check_impact_resolution_backrefs(merged: dict[str, Any]) -> list[str]:
    """Rule #30 — impact_resolutions[] entries resolve, match dimension, enforce grounding.

    - `prediction_ref` resolves to some declared impact_predictions[] id
      somewhere in the companion (keyed `l-{lead_id}.ip{n}`).
    - `dimension` matches the referenced prediction's `dimension`.
    - `verdict` is in {within, exceeds, indeterminate}.
    - `grounding_kind` is in {telemetry-baseline, business-owner-attestation,
      dlp-policy} — past-case is forbidden (impact is per-instance reasoning).
    - Required fields `authority_for_question`, `as_of`, `reasoning` present.

    The `prediction_ref` field itself is a bare `ip{n}` on the emitting
    lead in the spec example (see schema.md lines 577–580). The closure
    rule (#31) uses the cross-lead key `l-{id}.ip{n}`; this back-ref
    check accepts either the bare form (when the resolving lead also
    owns the prediction) or the fully-qualified form.
    """
    errors: list[str] = []
    # Build {bare_id → qualified_id} map by lead so we can resolve bare
    # references within the same lead.
    by_lead: dict[str, set[str]] = {}
    all_qualified = _collect_impact_prediction_refs(merged)
    for qual in all_qualified:
        if "." not in qual:
            continue
        lid, ipid = qual.rsplit(".", 1)
        by_lead.setdefault(lid, set()).add(ipid)

    # Build ip → dimension index (qualified → dimension)
    dimension_by_ref: dict[str, str] = {}
    for lead in merged.get("findings", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id")
        if not isinstance(lid, str):
            continue
        for ip in lead.get("impact_predictions") or []:
            if not isinstance(ip, dict):
                continue
            ipid = ip.get("id")
            dim = ip.get("dimension")
            if isinstance(ipid, str) and isinstance(dim, str):
                dimension_by_ref[f"{lid}.{ipid}"] = dim

    for lead in merged.get("findings", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome") if isinstance(lead.get("outcome"), dict) else {}
        for i, r in enumerate(outcome.get("impact_resolutions") or []):
            ctx = f"lead {lid} outcome.impact_resolutions[{i}]"
            if not isinstance(r, dict):
                errors.append(f"{ctx}: entry must be a mapping")
                continue

            missing = [f for f in _IMPACT_RES_REQUIRED_FIELDS if f not in r]
            if missing:
                errors.append(f"{ctx}: missing required field(s): {sorted(missing)}")

            pref = r.get("prediction_ref")
            qualified: str | None = None
            if isinstance(pref, str) and pref:
                if "." in pref:
                    qualified = pref
                else:
                    # Bare form — resolve against this lead.
                    if isinstance(lid, str):
                        qualified = f"{lid}.{pref}"
                if qualified is None or qualified not in all_qualified:
                    errors.append(
                        f"{ctx}: prediction_ref {pref!r} does not resolve to any "
                        f"declared impact_predictions[] id in the companion"
                    )
                    qualified = None
            elif "prediction_ref" in r:
                errors.append(f"{ctx}: prediction_ref must be a non-empty string")

            dim = r.get("dimension")
            if qualified is not None and dim is not None:
                expected = dimension_by_ref.get(qualified)
                if expected is not None and dim != expected:
                    errors.append(
                        f"{ctx}: dimension {dim!r} does not match the referenced "
                        f"prediction's dimension {expected!r}"
                    )

            verdict = r.get("verdict")
            if verdict is not None and verdict not in _IMPACT_VERDICTS:
                errors.append(
                    f"{ctx}: verdict {verdict!r} not in "
                    f"{sorted(_IMPACT_VERDICTS)}"
                )

            grounding = r.get("grounding_kind")
            if grounding is not None and grounding not in _IMPACT_GROUNDING_KINDS:
                errors.append(
                    f"{ctx}: grounding_kind {grounding!r} not in "
                    f"{sorted(_IMPACT_GROUNDING_KINDS)} — impact_resolutions "
                    f"forbid 'past-case' (impact is per-instance reasoning, "
                    f"not category-of-event)"
                )
    return errors


def _check_impact_closure(merged: dict[str, Any]) -> list[str]:
    """Rule #31 — every impact_predictions[] either resolves or is deferred.

    At CONCLUDE, every declared `impact_predictions[]` id must appear
    as some `impact_resolutions[].prediction_ref` OR in
    `conclude.deferred_impact_predictions[]` with a non-empty rationale.
    Mirrors rule #26 (deferred_authorizations).
    """
    conclude = merged.get("conclude")
    if not isinstance(conclude, dict):
        return []  # closure only enforced when CONCLUDE is present

    declared = _collect_impact_prediction_refs(merged)
    if not declared:
        return []

    resolved: set[str] = set()
    for lead in merged.get("findings", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id") if isinstance(lead.get("id"), str) else None
        outcome = lead.get("outcome") if isinstance(lead.get("outcome"), dict) else {}
        for r in outcome.get("impact_resolutions") or []:
            if not isinstance(r, dict):
                continue
            pref = r.get("prediction_ref")
            if not isinstance(pref, str) or not pref:
                continue
            if "." in pref:
                resolved.add(pref)
            elif lid is not None:
                resolved.add(f"{lid}.{pref}")

    deferred_entries = conclude.get("deferred_impact_predictions") or []
    deferred: dict[str, str] = {}
    errors: list[str] = []
    if deferred_entries and not isinstance(deferred_entries, list):
        errors.append(
            "conclude.deferred_impact_predictions must be a list of "
            "{prediction_ref, rationale} mappings"
        )
        deferred_entries = []
    for i, entry in enumerate(deferred_entries):
        if not isinstance(entry, dict):
            errors.append(
                f"conclude.deferred_impact_predictions[{i}] must be a mapping"
            )
            continue
        pref = entry.get("prediction_ref")
        rationale = entry.get("rationale")
        if not isinstance(pref, str) or not pref:
            errors.append(
                f"conclude.deferred_impact_predictions[{i}]: prediction_ref "
                f"required and must be a non-empty string of shape l-{{id}}.ip{{n}}"
            )
            continue
        if not (isinstance(rationale, str) and rationale.strip()):
            errors.append(
                f"conclude.deferred_impact_predictions[{i}]: rationale required "
                f"and must be a non-empty string"
            )
            continue
        deferred[pref] = rationale

    for ref in sorted(declared):
        if ref in resolved:
            continue
        if ref in deferred:
            continue
        errors.append(
            f"impact_prediction {ref!r}: declared but has no fulfilling "
            f"impact_resolutions[] entry and is not listed in "
            f"conclude.deferred_impact_predictions[]. Resolve at ANALYZE or "
            f"defer with a rationale at CONCLUDE."
        )
    return errors


def _check_conclude_two_axis(merged: dict[str, Any]) -> list[str]:
    """CONCLUDE block: validate impact_verdict / impact_severity / deferred.

    - `impact_verdict` ∈ {none, within, exceeds, indeterminate}.
    - `impact_severity` ∈ {null, low, moderate, high}.
    - `impact_severity` is required iff `impact_verdict` ∈ {exceeds, indeterminate}.
    - `deferred_impact_predictions` list entries carry prediction_ref + rationale.
    """
    conclude = merged.get("conclude")
    if not isinstance(conclude, dict):
        return []
    errors: list[str] = []

    verdict = conclude.get("impact_verdict")
    if "impact_verdict" in conclude and verdict not in _CONCLUDE_IMPACT_VERDICTS:
        errors.append(
            f"conclude.impact_verdict {verdict!r} not in "
            f"{sorted(v for v in _CONCLUDE_IMPACT_VERDICTS)}"
        )

    severity = conclude.get("impact_severity")
    if "impact_severity" in conclude and severity not in _IMPACT_SEVERITIES:
        errors.append(
            f"conclude.impact_severity {severity!r} not in "
            f"{sorted(s for s in _IMPACT_SEVERITIES if s is not None)} (or null)"
        )

    if verdict in ("exceeds", "indeterminate"):
        if severity is None:
            errors.append(
                f"conclude.impact_verdict is {verdict!r} but impact_severity is "
                f"null — severity is required when impact_verdict ∈ "
                f"{{'exceeds', 'indeterminate'}}."
            )
    else:
        # verdict is none / within / unset → severity must be null or absent
        if severity is not None and "impact_severity" in conclude:
            errors.append(
                f"conclude.impact_severity is {severity!r} but impact_verdict is "
                f"{verdict!r} — severity must be null when impact_verdict ∈ "
                f"{{'none', 'within'}}."
            )

    return errors
