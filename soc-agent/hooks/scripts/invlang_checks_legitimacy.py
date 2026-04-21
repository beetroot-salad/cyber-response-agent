"""Legitimacy-as-edge-attribute checks (spec rules #15–#22).

Covers the legitimacy_contract / legitimacy_resolutions primitive:
- contract edge_ref resolution
- resolution fulfills_contract back-reference
- benign-disposition gating
- attribute_updates / legitimacy_resolutions target shape
- asks / verdict coherence
- kind / asks coherence (telemetry-baseline vs. org-authority)
- supersede-chain integrity
- resolution requires authorization-class TAR
"""

from __future__ import annotations

from typing import Any

from hooks.scripts.invlang_common import (
    _LEGITIMACY_CONTRACT_ID_RE,
    _LEGITIMACY_VERDICTS,
    _LR_ID_RE,
    LeadResolution,
    _collect_contract_ids,
    _collect_declared_edge_ids,
    _collect_declared_ids,
    _collect_lead_resolutions,
    _compute_effective_resolutions,
    _iter_resolutions,
)
from hooks.scripts.invlang_walkers import (
    compute_final_status,
    compute_final_weight,
    iter_hypotheses,
)
from schemas.enums import VALID_ASKS, VALID_LEGITIMACY_VERDICTS


def _check_legitimacy_contract_edge_ref(merged: dict[str, Any]) -> list[str]:
    """Spec rule #19: hypothesis.legitimacy_contract[].edge_ref resolves.

    Each entry's `edge_ref` must be the literal `proposed` (referring to
    the hypothesis's own `proposed_edge`) or an `e-*` id declared
    elsewhere in the companion.
    """
    errors: list[str] = []
    declared_edges = _collect_declared_edge_ids(merged)
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        contracts = h.get("legitimacy_contract") or []
        if not isinstance(contracts, list):
            errors.append(f"hypothesis {hid}: legitimacy_contract must be a list")
            continue
        for i, c in enumerate(contracts):
            if not isinstance(c, dict):
                errors.append(f"hypothesis {hid}: legitimacy_contract[{i}] must be a mapping")
                continue
            raw_id = c.get("id")
            cid = raw_id if isinstance(raw_id, str) else f"[{i}]"
            if raw_id is None:
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract[{i}] missing id "
                    f"(required, must match ^lc\\d+$)"
                )
            elif not isinstance(raw_id, str):
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract[{i}] id must be a string "
                    f"matching ^lc\\d+$ (got {raw_id!r})"
                )
            elif not _LEGITIMACY_CONTRACT_ID_RE.match(raw_id):
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} id does not "
                    f"match pattern ^lc\\d+$ (e.g. lc1, lc2)"
                )
            edge_ref = c.get("edge_ref")
            if edge_ref is None:
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} missing edge_ref"
                )
                continue
            if edge_ref == "proposed":
                continue
            if not isinstance(edge_ref, str):
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} edge_ref must be "
                    f"'proposed' or an e-* id (got {edge_ref!r})"
                )
                continue
            if not edge_ref.startswith("e-"):
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} edge_ref "
                    f"{edge_ref!r} must be 'proposed' or an e-* id"
                )
                continue
            if edge_ref not in declared_edges:
                errors.append(
                    f"hypothesis {hid}: legitimacy_contract {cid!r} edge_ref "
                    f"{edge_ref!r} is not a declared edge in this companion"
                )
    return errors


def _check_legitimacy_resolution_backrefs(merged: dict[str, Any]) -> list[str]:
    """Spec rule #20: legitimacy_resolutions[].fulfills_contract resolves.

    Every `fulfills_contract` must be of shape `h-{id}.lc{n}` where the
    named hypothesis exists and its `legitimacy_contract` contains an
    entry with that id.
    """
    errors: list[str] = []
    contract_ids = _collect_contract_ids(merged)
    for location, eid, r, _lead_idx, _entry_idx in _iter_resolutions(merged):
        if "verdict" not in r:
            errors.append(
                f"{location} {eid}: legitimacy_resolutions entry missing verdict "
                f"(required, must be one of {sorted(_LEGITIMACY_VERDICTS)})"
            )
        else:
            verdict = r.get("verdict")
            if not isinstance(verdict, str):
                errors.append(
                    f"{location} {eid}: legitimacy_resolutions.verdict must be a "
                    f"string (got {verdict!r})"
                )
            elif verdict not in _LEGITIMACY_VERDICTS:
                errors.append(
                    f"{location} {eid}: legitimacy_resolutions.verdict {verdict!r} "
                    f"not in {sorted(_LEGITIMACY_VERDICTS)}"
                )
        back = r.get("fulfills_contract")
        if back is None:
            errors.append(
                f"{location} {eid}: legitimacy_resolutions entry missing fulfills_contract"
            )
            continue
        if not isinstance(back, str) or "." not in back:
            errors.append(
                f"{location} {eid}: legitimacy_resolutions.fulfills_contract {back!r} "
                f"must be of shape 'h-{{id}}.lc{{n}}'"
            )
            continue
        if back not in contract_ids:
            errors.append(
                f"{location} {eid}: legitimacy_resolutions.fulfills_contract {back!r} "
                f"does not resolve to any declared hypothesis + contract entry"
            )
    return errors


def _check_legitimacy_gated_disposition(merged: dict[str, Any]) -> list[str]:
    """Spec rule #21: conclude.disposition is gated by contract resolutions.

    For every hypothesis with weight ∈ {++, +} and status ∈ {confirmed,
    active}, every declared `legitimacy_contract` must have at least one
    `legitimacy_resolutions` entry fulfilling it. Then:

    - disposition=benign requires every contract to have ≥1 verdict=authorized
      (unfulfilled contracts and non-authorized verdicts are incompatible with
      benign — the investigation must escalate instead).
    - Any contract resolved with verdict=unauthorized → disposition must not
      be benign.
    - Any contract with only verdict=indeterminate → disposition must not be
      benign.

    The spec names `unclear` as the escalation disposition, but the surrounding
    system also uses `inconclusive` / `escalated` in the same slot. Rather than
    hard-code a single value, this rule enforces the load-bearing invariant —
    benign is gated on authorized — and lets any non-benign disposition stand
    for the escalation cases. Tighter disposition-vocabulary alignment is a
    separate cleanup.
    """
    errors: list[str] = []
    conclude = merged.get("conclude")
    if not isinstance(conclude, dict):
        return errors
    disposition = conclude.get("disposition")
    if disposition is None:
        return errors

    # Aggregate verdicts per contract from the EFFECTIVE resolution set —
    # superseded entries are excluded so the agent's final read of each
    # contract reflects the latest lead's verdict, not every historical
    # take. Rule #20 (back-ref) separately walks the full list so orphans
    # aren't hidden by supersession.
    effective = _compute_effective_resolutions(_collect_lead_resolutions(merged))
    verdicts_by_contract: dict[str, list[str]] = {}
    for r in effective:
        verdicts_by_contract.setdefault(r.contract_ref, []).append(r.verdict)

    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        contracts = h.get("legitimacy_contract") or []
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
            lc_id = c.get("id")
            if not isinstance(lc_id, str):
                continue
            contract_ref = f"{hid}.{lc_id}"
            verdicts = verdicts_by_contract.get(contract_ref, [])
            has_authorized = "authorized" in verdicts
            has_unauthorized = "unauthorized" in verdicts
            has_indeterminate = "indeterminate" in verdicts

            if disposition == "benign":
                if not verdicts:
                    errors.append(
                        f"hypothesis {hid}: legitimacy_contract {lc_id} on a live-weight "
                        f"hypothesis has no fulfilling legitimacy_resolutions entry, "
                        f"but conclude.disposition is 'benign'. Resolve the contract "
                        f"against its declared anchor, or escalate."
                    )
                elif has_unauthorized:
                    errors.append(
                        f"hypothesis {hid}: legitimacy_contract {lc_id} has a "
                        f"resolution with verdict 'unauthorized' but "
                        f"conclude.disposition is 'benign'. Escalate instead."
                    )
                elif has_indeterminate and not has_authorized:
                    errors.append(
                        f"hypothesis {hid}: legitimacy_contract {lc_id} has only "
                        f"'indeterminate' resolution(s); conclude.disposition is "
                        f"'benign'. Escalate instead."
                    )
                elif not has_authorized:
                    errors.append(
                        f"hypothesis {hid}: legitimacy_contract {lc_id} fulfilled with "
                        f"verdict(s) {sorted(set(verdicts))} — none are 'authorized' — "
                        f"yet conclude.disposition is 'benign'. Benign requires every "
                        f"contract on a live-weight hypothesis to resolve 'authorized'."
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
    for lead in merged.get("gather", []) or []:
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


def _check_asks_verdict_shape(merged: dict[str, Any]) -> list[str]:
    """`trust_anchor_result.asks` discriminator gates the `verdict` field.

    - `asks: authorization` ⇒ `verdict` is required and must be in
      `VALID_LEGITIMACY_VERDICTS`. The lead is answering "is this
      sanctioned?" and must commit to an answer.
    - `asks: expectation` ⇒ `verdict` must be absent. Baselines don't
      authorize (image-baseline, username-frequency), so a verdict would
      be a category error.

    Presence of `asks` itself is not required on legacy anchor consultations
    that predate the v2.9 shape; this rule only validates coherence when
    `asks` IS present.
    """
    errors: list[str] = []
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome", {}) if isinstance(lead.get("outcome"), dict) else {}
        tar = outcome.get("trust_anchor_result")
        if not isinstance(tar, dict):
            continue
        asks = tar.get("asks")
        if asks is None:
            continue  # legacy TAR without asks — nothing to check here
        if asks not in VALID_ASKS:
            errors.append(
                f"lead {lid}: trust_anchor_result.asks must be one of "
                f"{list(VALID_ASKS)}, got {asks!r}"
            )
            continue
        verdict = tar.get("verdict")
        if asks == "authorization":
            if verdict is None:
                errors.append(
                    f"lead {lid}: trust_anchor_result.asks is 'authorization' "
                    f"but verdict is missing — an authorization consultation "
                    f"must commit to one of {list(VALID_LEGITIMACY_VERDICTS)}"
                )
            elif verdict not in VALID_LEGITIMACY_VERDICTS:
                errors.append(
                    f"lead {lid}: trust_anchor_result.verdict {verdict!r} not in "
                    f"{list(VALID_LEGITIMACY_VERDICTS)}"
                )
        elif asks == "expectation":
            if verdict is not None:
                errors.append(
                    f"lead {lid}: trust_anchor_result.asks is 'expectation' but "
                    f"verdict={verdict!r} is set — baselines don't authorize. "
                    f"Use result:confirmed/refuted/unavailable for expectation-class "
                    f"anchors; omit verdict."
                )
    return errors


def _check_kind_asks_coherence(merged: dict[str, Any]) -> list[str]:
    """`kind: telemetry-baseline` ⇒ `asks: expectation`.

    Prevents a confused author from marking a telemetry baseline as an
    authorization-class anchor (e.g. writing
    `kind: telemetry-baseline, asks: authorization, verdict: authorized`)
    and passing all other rules. Baselines ground expectation — they can
    confirm the alert matches a learned pattern — but they cannot sanction
    an action.
    """
    errors: list[str] = []
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome", {}) if isinstance(lead.get("outcome"), dict) else {}
        tar = outcome.get("trust_anchor_result")
        if not isinstance(tar, dict):
            continue
        kind = tar.get("kind")
        asks = tar.get("asks")
        if kind == "telemetry-baseline" and asks is not None and asks != "expectation":
            errors.append(
                f"lead {lid}: trust_anchor_result.kind 'telemetry-baseline' "
                f"with asks {asks!r} — baselines only answer expectation. "
                f"Set asks: expectation, or use kind: org-authority for an "
                f"authorization-class anchor."
            )
    return errors


def _check_legitimacy_resolution_target_shape(merged: dict[str, Any]) -> list[str]:
    """Every `gather[].outcome.legitimacy_resolutions[].target` is v-*/e-* and declared.

    Mirrors `_check_attribute_updates_target_shape` — the lead-outcome
    `legitimacy_resolutions[]` sibling of `attribute_updates` follows the
    same target-shape contract: exactly one `target: v-{id} | e-{id}`, the
    id must be declared somewhere in the companion. Targets can differ
    from the lead's own `target` — a lead querying a vertex (e.g. an
    oncall roster) can still emit a resolution against an edge (the
    shell-spawn being authorized).
    """
    errors: list[str] = []
    declared_ids = _collect_declared_ids(merged)
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome", {}) if isinstance(lead.get("outcome"), dict) else {}
        for i, r in enumerate(outcome.get("legitimacy_resolutions") or []):
            ctx = f"lead {lid} legitimacy_resolutions[{i}]"
            if not isinstance(r, dict):
                errors.append(f"{ctx}: entry must be a mapping")
                continue
            if "vertex" in r and "target" not in r:
                errors.append(
                    f"{ctx}: uses legacy `vertex:` field — use `target: v-{{id}} | e-{{id}}`"
                )
                continue
            target = r.get("target")
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
    return errors


def _check_legitimacy_supersede_chain(merged: dict[str, Any]) -> list[str]:
    """Validate the supersede chain used by rule #21's effective-set filter.

    Rules enforced:
    - `lr-{n}` id pattern on any resolution that carries an `id` or is
      referenced by another entry's `supersedes`.
    - `supersedes: lr-X` requires `lr-X` to be declared elsewhere in the
      companion AND to fulfill the same `(fulfills_contract, target)` pair.
      Cross-contract or cross-target supersession is a category error —
      they describe different authorization questions.
    - No cycles in the supersede graph. A cycle means no effective verdict
      can be computed; halt with a diagnostic rather than producing a
      silent aggregation bug.

    Legacy edge-attached resolutions (`lr_id is None`) do not participate.
    """
    errors: list[str] = []
    all_res = _collect_lead_resolutions(merged)
    by_id: dict[str, LeadResolution] = {}
    for r in all_res:
        if r.lr_id is None:
            continue
        if r.lr_id in by_id:
            errors.append(
                f"{r.location}: legitimacy_resolutions id {r.lr_id!r} already "
                f"used at {by_id[r.lr_id].location!r} — ids must be unique "
                f"across all lead outcomes in the companion"
            )
        else:
            by_id[r.lr_id] = r

    for r in all_res:
        if r.lr_id is not None and not _LR_ID_RE.match(r.lr_id):
            errors.append(
                f"{r.location}: legitimacy_resolutions id {r.lr_id!r} does not "
                f"match pattern ^lr\\d+$ (e.g. lr1, lr2)"
            )

    for r in all_res:
        if r.supersedes is None:
            continue
        if r.lr_id is None:
            errors.append(
                f"{r.location}: resolution has supersedes={r.supersedes!r} "
                f"but carries no `id` of its own — a superseder must itself "
                f"be addressable so the chain can be audited"
            )
            continue
        prior = by_id.get(r.supersedes)
        if prior is None:
            errors.append(
                f"{r.location}: supersedes {r.supersedes!r} does not resolve "
                f"to any declared legitimacy_resolutions id"
            )
            continue
        if prior.contract_ref != r.contract_ref:
            errors.append(
                f"{r.location}: supersedes {r.supersedes!r} fulfills contract "
                f"{prior.contract_ref!r} but this resolution fulfills "
                f"{r.contract_ref!r} — supersession is contract-scoped"
            )
        if prior.target != r.target:
            errors.append(
                f"{r.location}: supersedes {r.supersedes!r} targets "
                f"{prior.target!r} but this resolution targets {r.target!r} "
                f"— supersession is target-scoped"
            )

    # Cycle detection via visited-set walks over supersede chains.
    for r in all_res:
        if r.supersedes is None or r.lr_id is None:
            continue
        visited = {r.lr_id}
        cur: str | None = r.supersedes
        while cur is not None:
            if cur in visited:
                errors.append(
                    f"{r.location}: supersede chain contains a cycle via "
                    f"{cur!r} — review the chain and remove the offending "
                    f"back-reference"
                )
                break
            visited.add(cur)
            nxt = by_id.get(cur)
            cur = nxt.supersedes if nxt else None

    return errors


def _check_resolution_requires_authorization_asks(merged: dict[str, Any]) -> list[str]:
    """A lead emitting `legitimacy_resolutions[]` must have `trust_anchor_result.asks: authorization`.

    Three failure modes, reported as distinct errors for debuggability:
    (a) the lead has no `trust_anchor_result` at all — resolutions are orphan
        because there is no consultation record to back them;
    (b) the TAR exists but has no `asks` — legacy consultation shape; adding
        a resolution requires upgrading to explicit `asks: authorization`;
    (c) `asks: expectation` but a resolution is present — a category error,
        baselines don't authorize.

    Only applies to the new lead-outcome path
    (`gather[].outcome.legitimacy_resolutions[]`). Legacy edge-attached
    resolutions are tolerated until C6.
    """
    errors: list[str] = []
    for lead in merged.get("gather", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        outcome = lead.get("outcome", {}) if isinstance(lead.get("outcome"), dict) else {}
        resolutions = outcome.get("legitimacy_resolutions") or []
        if not resolutions:
            continue
        tar = outcome.get("trust_anchor_result")
        if not isinstance(tar, dict):
            errors.append(
                f"lead {lid}: has legitimacy_resolutions[] but no trust_anchor_result "
                f"— resolutions must be backed by an explicit authority consultation "
                f"(add trust_anchor_result with asks: authorization and verdict:*)"
            )
            continue
        asks = tar.get("asks")
        if asks is None:
            errors.append(
                f"lead {lid}: has legitimacy_resolutions[] but trust_anchor_result.asks "
                f"is not set — add `asks: authorization` to the TAR"
            )
            continue
        if asks != "authorization":
            errors.append(
                f"lead {lid}: has legitimacy_resolutions[] but trust_anchor_result.asks "
                f"is {asks!r} — resolutions require asks: authorization"
            )
    return errors
