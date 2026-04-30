"""Authorization-as-edge-attribute checks.

Covers the authorization_contract / authorization_resolutions primitive
plus the affirmative true_positive disposition gate. Rule numbering
reflects the v2.15 consolidation — several checks formerly numbered
#19–#22 are now spec-level sub-cases of unified reference-resolution
rule (#7) or schema-validity rule (#1). Check function names are kept
stable for grep-friendly cross-references in tests, prompts, and
external docs:

- contract edge_ref resolution: spec rule #7 (was #19)
- resolution fulfills_contract back-reference: spec rule #7 (was #20)
- benign-disposition gating: spec rule #21
- attribute_updates target shape: spec rules #1 (exclusivity) + #7
  (resolution); was #22
- affirmative true_positive disposition: spec rule #36 (v2.14, rewritten v2.16)
"""

from __future__ import annotations

from typing import Any

from hooks.scripts.invlang_common import (
    _AUTHORIZATION_CONTRACT_ID_RE,
    _AUTHORIZATION_VERDICTS,
    _collect_contract_ids,
    _collect_declared_edge_ids,
    _collect_declared_ids,
    _iter_resolutions,
)
from hooks.scripts.invlang_walkers import (
    compute_final_status,
    compute_final_weight,
    iter_hypotheses,
)


def _check_authorization_contract_edge_ref(merged: dict[str, Any]) -> list[str]:
    """Spec rule #19: hypothesis.authorization_contract[].edge_ref resolves.

    Each entry's `edge_ref` must be the literal `proposed` (referring to
    the hypothesis's own `proposed_edge`) or an `e-*` id declared
    elsewhere in the companion. Each entry's `id` must match `^ac\\d+$`.
    """
    errors: list[str] = []
    declared_edges = _collect_declared_edge_ids(merged)
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        contracts = h.get("authorization_contract") or []
        if not isinstance(contracts, list):
            errors.append(f"hypothesis {hid}: authorization_contract must be a list")
            continue
        for i, c in enumerate(contracts):
            if not isinstance(c, dict):
                errors.append(
                    f"hypothesis {hid}: authorization_contract[{i}] must be a mapping"
                )
                continue
            raw_id = c.get("id")
            cid = raw_id if isinstance(raw_id, str) else f"[{i}]"
            if raw_id is None:
                errors.append(
                    f"hypothesis {hid}: authorization_contract[{i}] missing id "
                    f"(required, must match ^ac\\d+$)"
                )
            elif not isinstance(raw_id, str):
                errors.append(
                    f"hypothesis {hid}: authorization_contract[{i}] id must be a string "
                    f"matching ^ac\\d+$ (got {raw_id!r})"
                )
            elif not _AUTHORIZATION_CONTRACT_ID_RE.match(raw_id):
                errors.append(
                    f"hypothesis {hid}: authorization_contract {cid!r} id does not "
                    f"match pattern ^ac\\d+$ (e.g. ac1, ac2)"
                )
            edge_ref = c.get("edge_ref")
            if edge_ref is None:
                errors.append(
                    f"hypothesis {hid}: authorization_contract {cid!r} missing edge_ref"
                )
                continue
            if edge_ref == "proposed":
                continue
            if not isinstance(edge_ref, str):
                errors.append(
                    f"hypothesis {hid}: authorization_contract {cid!r} edge_ref must be "
                    f"'proposed' or an e-* id (got {edge_ref!r})"
                )
                continue
            if not edge_ref.startswith("e-"):
                errors.append(
                    f"hypothesis {hid}: authorization_contract {cid!r} edge_ref "
                    f"{edge_ref!r} must be 'proposed' or an e-* id"
                )
                continue
            if edge_ref not in declared_edges:
                errors.append(
                    f"hypothesis {hid}: authorization_contract {cid!r} edge_ref "
                    f"{edge_ref!r} is not a declared edge in this companion"
                )
    return errors


def _check_authorization_resolution_backrefs(merged: dict[str, Any]) -> list[str]:
    """Spec rule #20: authorization_resolutions[].fulfills_contract resolves.

    Every `fulfills_contract` must be of shape `h-{id}.ac{n}` where the
    named hypothesis exists and its `authorization_contract` contains an
    entry with that id. The verdict must also be in the authz vocabulary.
    """
    errors: list[str] = []
    contract_ids = _collect_contract_ids(merged)
    for location, _target_id, r, _lead_idx, _entry_idx in _iter_resolutions(merged):
        if "verdict" not in r:
            errors.append(
                f"{location}: authorization_resolutions entry missing verdict "
                f"(required, must be one of {sorted(_AUTHORIZATION_VERDICTS)})"
            )
        else:
            verdict = r.get("verdict")
            if not isinstance(verdict, str):
                errors.append(
                    f"{location}: authorization_resolutions.verdict must be a "
                    f"string (got {verdict!r})"
                )
            elif verdict not in _AUTHORIZATION_VERDICTS:
                errors.append(
                    f"{location}: authorization_resolutions.verdict {verdict!r} "
                    f"not in {sorted(_AUTHORIZATION_VERDICTS)}"
                )
        back = r.get("fulfills_contract")
        if back is None:
            errors.append(
                f"{location}: authorization_resolutions entry missing fulfills_contract"
            )
            continue
        if not isinstance(back, str) or "." not in back:
            errors.append(
                f"{location}: authorization_resolutions.fulfills_contract {back!r} "
                f"must be of shape 'h-{{id}}.ac{{n}}'"
            )
            continue
        if back not in contract_ids:
            errors.append(
                f"{location}: authorization_resolutions.fulfills_contract {back!r} "
                f"does not resolve to any declared hypothesis + contract entry"
            )
    return errors


def _check_authorization_gated_disposition(merged: dict[str, Any]) -> list[str]:
    """Spec rule #21: conclude.disposition is gated by contract resolutions.

    For every hypothesis with weight ∈ {++, +} and status ∈ {confirmed,
    active}, every declared `authorization_contract` must have at least
    one fulfilling `authorization_resolutions` entry. Then:

    - disposition=benign requires every contract to have ≥1 verdict=authorized
      (unfulfilled contracts and non-authorized verdicts are incompatible with
      benign — the investigation must escalate instead).
    - Any contract resolved with verdict=unauthorized → disposition must not
      be benign.
    - Any contract with only verdict=indeterminate → disposition must not be
      benign.

    v2.11 drops the supersede chain — every fulfilling entry is counted.
    Absence from `conclude.deferred_authorizations` already caps closure
    (rule #26); this rule only checks the gating when disposition is set.
    """
    errors: list[str] = []
    conclude = merged.get("conclude")
    if not isinstance(conclude, dict):
        return errors
    disposition = conclude.get("disposition")
    if disposition is None:
        return errors

    # Aggregate verdicts per contract from every fulfilling entry walked
    # by _iter_resolutions (edge-inline + attribute_updates embeds).
    verdicts_by_contract: dict[str, list[str]] = {}
    for _location, _target_id, r, _lead_idx, _entry_idx in _iter_resolutions(merged):
        cref = r.get("fulfills_contract")
        verdict = r.get("verdict")
        if not isinstance(cref, str) or not isinstance(verdict, str):
            continue
        verdicts_by_contract.setdefault(cref, []).append(verdict)

    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        contracts = h.get("authorization_contract") or []
        if not contracts:
            continue
        final_weight = compute_final_weight(merged, hid)
        if final_weight not in ("++", "+"):
            continue
        status = compute_final_status(merged, hid)
        if status not in ("active", "confirmed"):
            continue

        for c in contracts:
            if not isinstance(c, dict):
                continue
            ac_id = c.get("id")
            if not isinstance(ac_id, str):
                continue
            contract_ref = f"{hid}.{ac_id}"
            verdicts = verdicts_by_contract.get(contract_ref, [])
            has_authorized = "authorized" in verdicts
            has_unauthorized = "unauthorized" in verdicts
            has_indeterminate = "indeterminate" in verdicts

            if disposition == "benign":
                if not verdicts:
                    errors.append(
                        f"hypothesis {hid}: authorization_contract {ac_id} on a "
                        f"live-weight hypothesis has no fulfilling "
                        f"authorization_resolutions entry, but "
                        f"conclude.disposition is 'benign'. Resolve the contract "
                        f"against its declared anchor, or escalate."
                    )
                elif has_unauthorized:
                    errors.append(
                        f"hypothesis {hid}: authorization_contract {ac_id} has a "
                        f"resolution with verdict 'unauthorized' but "
                        f"conclude.disposition is 'benign'. Escalate instead."
                    )
                elif has_indeterminate and not has_authorized:
                    errors.append(
                        f"hypothesis {hid}: authorization_contract {ac_id} has only "
                        f"'indeterminate' resolution(s); conclude.disposition is "
                        f"'benign'. Escalate instead."
                    )
                elif not has_authorized:
                    errors.append(
                        f"hypothesis {hid}: authorization_contract {ac_id} fulfilled "
                        f"with verdict(s) {sorted(set(verdicts))} — none are "
                        f"'authorized' — yet conclude.disposition is 'benign'. "
                        f"Benign requires every contract on a live-weight "
                        f"hypothesis to resolve 'authorized'."
                    )
    return errors


def _check_attribute_updates_target_shape(merged: dict[str, Any]) -> list[str]:
    """Spec rule #22: every attribute_updates entry has exactly one target.

    Target is `v-{id}` or `e-{id}`, and the id exists in the companion.
    Existence is also covered by the generic id-reference check; this
    rule additionally enforces shape (target key present, single id,
    correct prefix).
    """
    errors: list[str] = []
    declared_ids = _collect_declared_ids(merged)
    for lead in merged.get("findings", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for i, upd in enumerate(lead.get("outcome", {}).get("attribute_updates") or []):
            ctx = f"lead {lid} attribute_updates[{i}]"
            if not isinstance(upd, dict):
                errors.append(f"{ctx}: entry must be a mapping")
                continue
            if "vertex" in upd and "target" not in upd:
                errors.append(
                    f"{ctx}: uses legacy `vertex:` field — use `target: v-{{id}} | e-{{id}}`"
                )
                continue
            target = upd.get("target")
            if not isinstance(target, str) or not target:
                errors.append(
                    f"{ctx}: missing `target:` (required, must be v-{{id}} or e-{{id}})"
                )
                continue
            if not (target.startswith("v-") or target.startswith("e-")):
                errors.append(
                    f"{ctx}: target {target!r} must start with 'v-' or 'e-'"
                )
                continue
            if target not in declared_ids:
                errors.append(
                    f"{ctx}: target {target!r} does not resolve to a declared id"
                )
            if "updates" not in upd or not isinstance(upd.get("updates"), dict):
                errors.append(
                    f"{ctx}: missing or non-mapping `updates` field"
                )
    return errors


def _check_affirmative_true_positive(merged: dict[str, Any]) -> list[str]:
    """Spec rule #36: conclude.disposition=true_positive requires ++ on a survivor.

    `disposition: true_positive` is a *positive* claim about adversarial
    activity — it must be backed by affirmative grading evidence, not by
    absence of benign confirmation. The structural signal of affirmative
    evidence is a final weight of `++` on at least one surviving
    hypothesis: `++` requires a severe lead resolution citing an
    authoritative edge (rule #6 + edge-authority discipline), so the
    grading is bound to concrete observation, not to "no benign anchor
    came back."

    The rule fires when `conclude.disposition` is `true_positive`. It
    walks `conclude.surviving_hypotheses[]` (or, when absent, every
    declared hypothesis) and requires that at least one referenced
    hypothesis has final weight `++` (computed via
    `compute_final_weight`).

    Empirically motivated: 4 production runs (documented in
    `tasks/analyze-true-positive-routing.md`) routed `true_positive`
    while no surviving hypothesis was graded `++` — every survivor was
    at `+` or null, i.e. no severe-lead refutation/confirmation had
    landed. The weight-only rule rejects those envelopes structurally.

    History: v2.14 introduced this rule as a two-part check (adversarial-
    classification token + ++). The lexical token list desynced from
    playbook-canonical hypothesis names (e.g. the 5710 playbook's
    `?credentials-used-outside-registered-actor` is semantically
    adversarial but lacked an allowlisted prefix), producing brittle
    false rejections of legitimately-graded true_positive routings.
    v2.16 drops the classification check; the affirmative-evidence
    signal is fully captured by the `++` weight requirement, and the
    "wrong-named survivor routed true_positive" failure mode is caught
    by Tier-2 report judges plus the existing legitimacy-contract
    discipline (rule #21 forces `benign` on authorized contracts, so
    a survivor whose contracts all resolve `authorized` cannot reach
    `true_positive` without contradicting #21).
    """
    errors: list[str] = []
    conclude = merged.get("conclude")
    if not isinstance(conclude, dict):
        return errors
    if conclude.get("disposition") != "true_positive":
        return errors

    # Index hypotheses by id.
    h_by_id: dict[str, dict[str, Any]] = {}
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if isinstance(hid, str):
            h_by_id[hid] = h

    # Restrict to surviving_hypotheses[] when present; otherwise scan all
    # declared. Either way the condition is: ≥1 ++ in the candidate set.
    raw_surviving = conclude.get("surviving_hypotheses")
    if isinstance(raw_surviving, list) and raw_surviving:
        candidates = [hid for hid in raw_surviving if isinstance(hid, str)]
    else:
        candidates = list(h_by_id.keys())

    qualifying: list[str] = []
    sub_pp: list[str] = []  # declared but graded < ++
    missing: list[str] = []

    for hid in candidates:
        if hid not in h_by_id:
            missing.append(hid)
            continue
        weight = compute_final_weight(merged, hid)
        if weight == "++":
            qualifying.append(hid)
        else:
            sub_pp.append(f"{hid}({weight or 'null'})")

    if qualifying:
        return errors  # rule satisfied

    pieces: list[str] = []
    if missing:
        pieces.append(f"surviving_hypotheses references undeclared id(s) {missing}")
    if sub_pp:
        pieces.append(f"surviving but weight < ++: {sub_pp}")
    detail = "; ".join(pieces) or "no surviving hypothesis declared"
    errors.append(
        f"conclude.disposition is 'true_positive' but no surviving hypothesis "
        f"has final weight ++ ({detail}). 'true_positive' requires affirmative "
        f"evidence of adversarial activity — a severe-lead grading on at "
        f"least one survivor — not absence of benign confirmation. If no "
        f"survivor is graded ++, the honest disposition is 'unclear'."
    )
    return errors
