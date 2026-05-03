"""Hypothesis-discipline checks (rules #23–#30).

Covers the lean-hypothesis and sibling-rollup rules:
- sibling fork distinctness on parent_vertex.classification
- hypothesis persistence at REPORT
- matched_prediction_ids hypothesis-scope (no same-level sibling rollup)
- compound prediction claim rejection
- evaluation-prefixed classification rejection
- predictions leanness cap
- prediction subject one-hop scope
- refutation→prediction link requirement
"""

from __future__ import annotations

import re
from typing import Any

from hooks.scripts.invlang_common import (
    _index_hypothesis_id_field_ids,
)
from hooks.scripts.invlang_walkers import (
    compute_final_status,
    compute_final_weight,
    iter_hypotheses,
    parent_hypothesis_id,
)


def _check_hypothesis_fork_distinctness(merged: dict[str, Any]) -> list[str]:
    """Reject sibling hypotheses that share parent_vertex.classification.

    Two hypotheses that attach to the same confirmed vertex under the same
    parent refinement group must not share the same
    `proposed_edge.parent_vertex.classification`. Sharing a classification
    among co-attached siblings means the fork is cosmetic — the same
    causal upstream is being proposed twice under two ids, and no lead
    can discriminate between them because every prediction about
    "parent has classification X" resolves identically on both.

    Scope: grouping by `(parent_hypothesis_id, attached_to_vertex)` — a
    refinement child-of-h-001 and a refinement child-of-h-002 live in
    separate groups, as do hypotheses attached to different vertices.
    Missing fields are skipped silently; other rules flag malformed
    records.
    """
    errors: list[str] = []
    # group -> {classification: [hypothesis_id, ...]}
    groups: dict[tuple[str | None, Any], dict[Any, list[str]]] = {}
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        attached = h.get("attached_to_vertex")
        proposed = h.get("proposed_edge")
        if not isinstance(proposed, dict):
            continue
        parent_vertex = proposed.get("parent_vertex")
        if not isinstance(parent_vertex, dict):
            continue
        classification = parent_vertex.get("classification")
        if classification is None:
            continue
        key = (parent_hypothesis_id(hid), attached)
        groups.setdefault(key, {}).setdefault(classification, []).append(hid)

    for (parent_id, attached), by_cls in groups.items():
        for classification, hids in by_cls.items():
            if len(hids) < 2:
                continue
            where = (
                f"attached_to_vertex={attached!r}"
                if parent_id is None
                else f"parent={parent_id!r}, attached_to_vertex={attached!r}"
            )
            errors.append(
                f"hypotheses {sorted(hids)} share "
                f"proposed_edge.parent_vertex.classification={classification!r} "
                f"within the same sibling group ({where}). Sibling hypotheses "
                f"must fork on classification — two entries with the same "
                f"classification propose the same causal upstream and cannot "
                f"be discriminated by any lead. Collapse to one hypothesis, "
                f"or refine one of them to a distinct classification."
            )
    return errors


def _check_hypothesis_persistence(merged: dict[str, Any]) -> list[str]:
    """Rule 24 — no orphaned hypotheses at REPORT.

    When a `conclude:` block is present, every declared hypothesis must
    either have reached final weight `--` across the resolutions chain, or
    appear in `conclude.surviving_hypotheses[]`. A hypothesis neither
    terminally refuted nor listed as surviving has been silently dropped —
    the investigation cannot close without accounting for it.
    """
    conclude = merged.get("conclude")
    if not isinstance(conclude, dict):
        return []
    errors: list[str] = []
    raw_surviving = conclude.get("surviving_hypotheses") or []
    if not isinstance(raw_surviving, list):
        return [
            "conclude.surviving_hypotheses must be a list of hypothesis IDs "
            f"(got {type(raw_surviving).__name__})"
        ]
    surviving = {s for s in raw_surviving if isinstance(s, str)}
    seen: set[str] = set()
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str) or hid in seen:
            continue
        seen.add(hid)
        # Shelved hypotheses count as terminal — they were explicitly deferred.
        status = compute_final_status(merged, hid)
        if status == "shelved":
            continue
        final = compute_final_weight(merged, hid)
        if final == "--":
            continue
        if hid in surviving:
            continue
        errors.append(
            f"hypothesis {hid}: declared but neither terminally refuted "
            f"(final weight {final!r}) nor listed in "
            f"conclude.surviving_hypotheses[]. A hypothesis cannot be "
            f"silently dropped — either refute it with a matched refutation "
            f"shape or list it as surviving for escalation."
        )
    return errors


def _check_prediction_id_hypothesis_scope(merged: dict[str, Any]) -> list[str]:
    """Rule 25 — matched_prediction_ids must be hypothesis-scoped.

    Each id in `matched_prediction_ids[]` on a resolution for hypothesis H
    must appear in H's own declared `predictions[]` or `attribute_predictions[]`.
    Rule 5 enforces the equivalent for `matched_refutation_ids` on `--`
    resolutions; rule 25 closes the equivalent loophole for prediction IDs on
    every weight. Mis-citing a sibling's prediction ID is same-level sibling
    rollup — upgrading H on the strength of a peer's confirmed prediction.

    Per rule #33, the valid citation space for a resolution is the union of
    `p*` and `ap*` IDs on the target hypothesis — both represent things the
    lead's evidence can match against.
    """
    errors: list[str] = []
    declared = _index_hypothesis_id_field_ids(merged)
    for lead in merged.get("findings", []) or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for res in lead.get("resolutions", []) or []:
            if not isinstance(res, dict):
                continue
            hid = res.get("hypothesis")
            if not isinstance(hid, str):
                continue
            # Undeclared hypothesis is already flagged by the dangling-ref
            # check (rule 4); skip here to avoid double-reporting the same
            # root cause.
            if hid not in declared:
                continue
            matched = res.get("matched_prediction_ids") or []
            if not isinstance(matched, list):
                continue
            h_preds = declared[hid].get("predictions", set())
            h_attr_preds = declared[hid].get("attribute_predictions", set())
            valid = h_preds | h_attr_preds
            foreign = [m for m in matched if isinstance(m, str) and m not in valid]
            if foreign:
                errors.append(
                    f"lead {lid}: resolution for {hid} cites "
                    f"matched_prediction_ids {sorted(foreign)} that do not "
                    f"appear in {hid}'s declared predictions {sorted(h_preds) or '[]'} "
                    f"or attribute_predictions {sorted(h_attr_preds) or '[]'}. Each "
                    f"prediction ID on a resolution must belong to the target "
                    f"hypothesis — mis-citing a sibling's ID is same-level sibling rollup."
                )
    return errors


_COMPOUND_CLAIM_PATTERNS: tuple[tuple[str, str], ...] = (
    ("; ", "semicolon-separated clauses"),
    (" AND ", "'AND' conjunction between clauses"),
    (" OR ", "'OR' conjunction between clauses"),
)


def _check_compound_prediction_claim(merged: dict[str, Any]) -> list[str]:
    """Rule 26 — a predictions[].claim names one observable, not several.

    Packing multiple independent observable claims into one `claim` string
    (joined by `; `, ` AND `, or ` OR `) makes the prediction unrefutable:
    which conjunct failed? The discipline is one prediction per observable
    — split compound claims into separate predictions.

    Detects three unambiguous patterns. Lowercase `and`/`or` inside a
    single-observable disjunction (e.g. "pattern matches foo or bar") is
    tolerated; the corpus-observed compound failures all use the
    uppercase/semicolon form.

    Applies equivalently to `attribute_predictions[].claim` (rule #33 extends
    the one-observable discipline to the parent-vertex attribute surface).
    """
    errors: list[str] = []
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        # predictions[]
        for pred in h.get("predictions", []) or []:
            if not isinstance(pred, dict):
                continue
            claim = pred.get("claim")
            if not isinstance(claim, str):
                continue
            pid = pred.get("id", "?")
            for token, description in _COMPOUND_CLAIM_PATTERNS:
                if token in claim:
                    errors.append(
                        f"hypothesis {hid} prediction {pid}: claim contains "
                        f"{description} ({token!r}). A prediction names one "
                        f"observable with one predicted value; split "
                        f"compound claims into separate prediction entries."
                    )
                    break  # one complaint per prediction is enough
        # attribute_predictions[] — same discipline
        for apred in h.get("attribute_predictions", []) or []:
            if not isinstance(apred, dict):
                continue
            claim = apred.get("claim")
            if not isinstance(claim, str):
                continue
            apid = apred.get("id", "?")
            for token, description in _COMPOUND_CLAIM_PATTERNS:
                if token in claim:
                    errors.append(
                        f"hypothesis {hid} attribute_prediction {apid}: claim contains "
                        f"{description} ({token!r}). An attribute_prediction names one "
                        f"observable attribute assertion; split compound claims into "
                        f"separate entries."
                    )
                    break
    return errors


_ATTR_PRED_ID_RE = re.compile(r"^ap\d+$")
_VALID_ATTR_PRED_TARGETS = frozenset({"proposed_parent", "attached_vertex", "proposed_edge"})


def _check_attribute_prediction_structure(merged: dict[str, Any]) -> list[str]:
    """Rule 33 — structural validation of `attribute_predictions[]` entries.

    Each entry must have:
      - `id` matching `^ap\\d+$`, unique within the hypothesis
      - `target` ∈ {proposed_parent, attached_vertex, proposed_edge}
      - `attribute` — non-empty string
      - `claim`    — non-empty string (one observable; compound-split enforced by rule #26)

    The one-observable discipline for `claim` is enforced in
    `_check_compound_prediction_claim` (rule #26 extension).
    """
    errors: list[str] = []
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        entries = h.get("attribute_predictions")
        if entries is None:
            continue
        if not isinstance(entries, list):
            errors.append(
                f"hypothesis {hid}: attribute_predictions must be a list, got "
                f"{type(entries).__name__}"
            )
            continue

        seen_ids: set[str] = set()
        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                errors.append(
                    f"hypothesis {hid} attribute_predictions[{idx}]: entry must be "
                    f"a mapping, got {type(entry).__name__}"
                )
                continue

            # id
            apid = entry.get("id")
            if not isinstance(apid, str) or not _ATTR_PRED_ID_RE.match(apid):
                errors.append(
                    f"hypothesis {hid} attribute_predictions[{idx}]: `id` must match "
                    f"^ap\\d+$ (e.g. ap1), got {apid!r}"
                )
            elif apid in seen_ids:
                errors.append(
                    f"hypothesis {hid} attribute_predictions[{idx}]: duplicate id {apid!r} "
                    f"— attribute_prediction ids must be unique within the hypothesis"
                )
            else:
                seen_ids.add(apid)

            # target
            target = entry.get("target")
            if target not in _VALID_ATTR_PRED_TARGETS:
                errors.append(
                    f"hypothesis {hid} attribute_prediction {apid or '?'}: `target` must be one of "
                    f"{sorted(_VALID_ATTR_PRED_TARGETS)}, got {target!r}"
                )

            # attribute
            attribute = entry.get("attribute")
            if not isinstance(attribute, str) or not attribute.strip():
                errors.append(
                    f"hypothesis {hid} attribute_prediction {apid or '?'}: `attribute` must be "
                    f"a non-empty string naming the parent/edge attribute under assertion, "
                    f"got {attribute!r}"
                )

            # claim
            claim = entry.get("claim")
            if not isinstance(claim, str) or not claim.strip():
                errors.append(
                    f"hypothesis {hid} attribute_prediction {apid or '?'}: `claim` must be "
                    f"a non-empty string with one observable attribute assertion, got "
                    f"{claim!r}"
                )

    return errors


_EVALUATION_PREFIXES: tuple[str, ...] = (
    "authorized-",
    "unauthorized-",
    "legitimate-",
    "illegitimate-",
    "malicious-",
    "benign-",
    "sanctioned-",
    "unsanctioned-",
    "compromised-",
    "adversarial-",
)


def _check_classification_evaluation_prefix(merged: dict[str, Any]) -> list[str]:
    """Rule 27 — mechanism classifications carry no authorization/intent prefix.

    A hypothesis classification names an upstream *mechanism* — the kind of
    vertex (process, identity, scheduled-automation, runtime-exec-injection,
    …). Evaluation-packed prefixes (`authorized-`, `malicious-`, `compromised-`,
    `adversarial-`, …) smuggle the verdict into the label, biasing weight
    history before anchors resolve and producing sibling pairs that differ
    only on authority — a shape the `authorization_contract` primitive exists
    to collapse.

    Checked on both `proposed_edge.parent_vertex.classification` and the
    hypothesis `name` (which typically mirrors the classification as
    `?{classification}`).
    """
    errors: list[str] = []
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        classification = (
            h.get("proposed_edge", {})
             .get("parent_vertex", {})
             .get("classification")
        )
        if isinstance(classification, str):
            for prefix in _EVALUATION_PREFIXES:
                if classification.startswith(prefix):
                    errors.append(
                        f"hypothesis {hid}: classification "
                        f"{classification!r} starts with evaluation-packed "
                        f"prefix {prefix!r}. Classifications name a mechanism, "
                        f"not a verdict — move authorization into an "
                        f"authorization_contract on the hypothesis."
                    )
                    break
        name = h.get("name")
        if isinstance(name, str):
            stripped = name[1:] if name.startswith("?") else name
            for prefix in _EVALUATION_PREFIXES:
                if stripped.startswith(prefix):
                    errors.append(
                        f"hypothesis {hid}: name {name!r} starts with "
                        f"evaluation-packed prefix {('?' + prefix)!r}. Name "
                        f"the mechanism, not the verdict."
                    )
                    break
    return errors


_MAX_PREDICTIONS_PER_HYPOTHESIS = 2


def _check_predictions_leanness(merged: dict[str, Any]) -> list[str]:
    """Rule 28 — at most two predictions per hypothesis.

    Three or more predictions signals an unlean label: the subagent is
    enumerating properties of a narrative instead of selecting the 1–2
    that most cleanly discriminate this hypothesis from siblings. Split
    into child hypotheses or defer extras until a lead forces refinement.
    """
    errors: list[str] = []
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        preds = h.get("predictions") or []
        if not isinstance(preds, list):
            continue
        count = sum(1 for p in preds if isinstance(p, dict))
        if count > _MAX_PREDICTIONS_PER_HYPOTHESIS:
            errors.append(
                f"hypothesis {hid}: carries {count} predictions — lean "
                f"discipline caps at {_MAX_PREDICTIONS_PER_HYPOTHESIS}. "
                f"Split into child hypotheses or defer extras until a "
                f"lead forces refinement."
            )
    return errors


_VALID_PREDICTION_SUBJECTS = frozenset({
    "proposed_parent",
    "attached_vertex",
    "proposed_edge",
})


def _check_prediction_subject_scope(merged: dict[str, Any]) -> list[str]:
    """Rule 29 — a prediction's subject is within the hypothesis's one-hop scope.

    Each `predictions[].subject` must be one of `proposed_parent` (the newly-
    hypothesized upstream vertex), `attached_vertex` (the already-confirmed
    observed vertex), or `proposed_edge` (the edge between them). Any other
    value signals the prediction is really testing some entity outside the
    hypothesis's graph — typically a lead-in-disguise ("container has cron
    service installed", "auth-success edge appears later") that belongs to
    GATHER, not to the hypothesis.
    """
    errors: list[str] = []
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        for pred in h.get("predictions", []) or []:
            if not isinstance(pred, dict):
                continue
            pid = pred.get("id", "?")
            subject = pred.get("subject")
            if subject is None:
                errors.append(
                    f"hypothesis {hid} prediction {pid}: missing required "
                    f"`subject` field (one of "
                    f"{sorted(_VALID_PREDICTION_SUBJECTS)})"
                )
                continue
            if subject not in _VALID_PREDICTION_SUBJECTS:
                errors.append(
                    f"hypothesis {hid} prediction {pid}: subject "
                    f"{subject!r} is outside the hypothesis's one-hop graph "
                    f"scope (must be one of "
                    f"{sorted(_VALID_PREDICTION_SUBJECTS)}). A prediction about "
                    f"any other entity is a lead masquerading as a prediction "
                    f"— move it to GATHER."
                )
    return errors


def _check_integrity_peer_discipline(merged: dict[str, Any]) -> list[str]:
    """Rule #32 (v2.12 narrowed) — reject the invoker-identity anti-pattern.

    Flags sibling hypotheses that share proposed_edge structure AND have
    predictions that subset-or-equal one another, where at least one of
    the pair carries an `authorization_contract`.

    Rationale:
      A "peer hypothesis" that shares `attached_to_vertex`,
      `proposed_edge.relation`, and `proposed_edge.parent_vertex.type`
      with a contract-carrying sibling — AND whose predictions are
      contained in (or equal to) the sibling's — adds no observational
      signal. It's verdict-flipping re-labeled as a mechanism fork, the
      invoker-identity anti-pattern (see predict.md §Disciplines).

      A peer hypothesis IS valid when its predictions diverge on observable
      fields the contract-carrying hypothesis doesn't cover — that's
      Shape M (mechanism fork) not Shape A integrity peer.

    This rule does NOT mandate a waiver on every acting-entity contract.
    A single hypothesis with a contract and no peer is fine — integrity is
    implicit in the contract's anchor resolution. An optional
    `integrity_waived: <rationale>` remains valid as documentation; it is
    not required.
    """
    errors: list[str] = []
    hypotheses = list(iter_hypotheses(merged))

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for h in hypotheses:
        av = h.get("attached_to_vertex")
        proposed = h.get("proposed_edge") or {}
        relation = proposed.get("relation") if isinstance(proposed, dict) else None
        pv = proposed.get("parent_vertex") if isinstance(proposed, dict) else None
        ptype = pv.get("type") if isinstance(pv, dict) else None
        if not (isinstance(av, str) and isinstance(relation, str) and isinstance(ptype, str)):
            continue
        groups.setdefault((av, relation, ptype), []).append(h)

    for group in groups.values():
        if len(group) < 2:
            continue
        for i in range(len(group)):
            h1 = group[i]
            for j in range(i + 1, len(group)):
                h2 = group[j]
                has_contract = bool(h1.get("authorization_contract")) or bool(
                    h2.get("authorization_contract")
                )
                if not has_contract:
                    continue
                claims_1 = _prediction_claims(h1)
                claims_2 = _prediction_claims(h2)
                if not claims_1 or not claims_2:
                    continue
                if claims_1 <= claims_2 or claims_2 <= claims_1:
                    hid1 = h1.get("id") or "?"
                    hid2 = h2.get("id") or "?"
                    errors.append(
                        f"hypotheses {hid1} and {hid2}: share proposed_edge "
                        f"structure (same attached_to_vertex + relation + "
                        f"parent_vertex.type) and one hypothesis's prediction "
                        f"claims are a subset of the other's. This is the "
                        f"invoker-identity anti-pattern — the peer adds no "
                        f"observational signal beyond the authorization_contract. "
                        f"Collapse to one hypothesis, or give the peer predictions "
                        f"that discriminate on observable fields the "
                        f"contract-carrying hypothesis doesn't already cover "
                        f"(Shape M territory)."
                    )
    return errors


def _prediction_claims(h: dict[str, Any]) -> set[str]:
    """Collect normalized `predictions[].claim` strings for comparison."""
    claims: set[str] = set()
    for pred in h.get("predictions") or []:
        if isinstance(pred, dict):
            c = pred.get("claim")
            if isinstance(c, str) and c.strip():
                claims.add(c.strip().lower())
    return claims


def _prediction_signature(h: dict[str, Any]) -> set[tuple[str, str, str]]:
    """Collect a normalized prediction signature for sibling-divergence comparison.

    Combines `predictions[]` (subject, claim) and `attribute_predictions[]`
    (target+attribute, claim) into a single set of (kind-tag, subject, claim)
    tuples. Used by `_check_sibling_prediction_divergence`. Subjects /
    targets are normalized to empty string when missing — claim text is the
    discriminating axis; subject-only differences without claim divergence
    still count as a paraphrase fork.
    """
    sig: set[tuple[str, str, str]] = set()
    for pred in h.get("predictions") or []:
        if not isinstance(pred, dict):
            continue
        claim = pred.get("claim")
        if not isinstance(claim, str) or not claim.strip():
            continue
        subject = pred.get("subject")
        subject_s = subject.strip().lower() if isinstance(subject, str) else ""
        sig.add(("p", subject_s, claim.strip().lower()))
    for ap in h.get("attribute_predictions") or []:
        if not isinstance(ap, dict):
            continue
        claim = ap.get("claim")
        if not isinstance(claim, str) or not claim.strip():
            continue
        target = ap.get("target")
        attribute = ap.get("attribute")
        target_s = target.strip().lower() if isinstance(target, str) else ""
        attribute_s = attribute.strip().lower() if isinstance(attribute, str) else ""
        sig.add(("ap", f"{target_s}.{attribute_s}", claim.strip().lower()))
    return sig


def _check_sibling_prediction_divergence(merged: dict[str, Any]) -> list[str]:
    """Rule #35 (sibling prediction divergence) — paraphrase forks are rejected.

    Within a sibling group — hypotheses sharing
    `(parent_hypothesis_id, attached_to_vertex)` — no two siblings may
    declare identical prediction signatures (combining `predictions[]`
    and `attribute_predictions[]`). Identical signatures mean the two
    hypotheses propose the same observable expectations; ANALYZE has no
    discriminator to grade them differently and the fork is cosmetic.

    Generalises rule #32 (which is integrity-peer-specific and only
    fires on shared `proposed_edge` structure with at least one
    authorization_contract) to all sibling forks regardless of contract
    presence. Complements rule #23 — that rule blocks shared
    *classifications*; this one blocks shared *prediction signatures*.

    A hypothesis with an empty signature (no predictions, no
    attribute_predictions) is skipped — other rules (e.g. leanness,
    refutation linkage) flag that shape separately.
    """
    errors: list[str] = []
    # group key -> [(hypothesis_id, signature), ...]
    groups: dict[tuple[str | None, Any], list[tuple[str, frozenset[tuple[str, str, str]]]]] = {}
    for h in iter_hypotheses(merged):
        hid = h.get("id")
        if not isinstance(hid, str):
            continue
        sig = _prediction_signature(h)
        if not sig:
            continue
        attached = h.get("attached_to_vertex")
        key = (parent_hypothesis_id(hid), attached)
        groups.setdefault(key, []).append((hid, frozenset(sig)))

    for (parent_id, attached), members in groups.items():
        if len(members) < 2:
            continue
        # O(n^2) over a sibling group is fine — group sizes are 2-3 in practice.
        seen_pairs: set[tuple[str, str]] = set()
        for i in range(len(members)):
            hid_i, sig_i = members[i]
            for j in range(i + 1, len(members)):
                hid_j, sig_j = members[j]
                if sig_i != sig_j:
                    continue
                pair = tuple(sorted([hid_i, hid_j]))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                where = (
                    f"attached_to_vertex={attached!r}"
                    if parent_id is None
                    else f"parent={parent_id!r}, attached_to_vertex={attached!r}"
                )
                errors.append(
                    f"hypotheses {hid_i} and {hid_j}: declare identical "
                    f"prediction signatures (predictions + attribute_predictions) "
                    f"within the same sibling group ({where}). Sibling forks must "
                    f"differ on at least one prediction claim — identical "
                    f"signatures mean no lead can discriminate between them. "
                    f"Collapse to one hypothesis (with an authorization_contract "
                    f"if the open question is authorization), or rewrite one "
                    f"sibling's predictions on observables that genuinely diverge."
                )
    return errors


def _check_refutation_prediction_links(merged: dict[str, Any]) -> list[str]:
    """Rule 30 — every refutation_shape entry cites the predictions it refutes.

    `refutation_shape[].refutes_predictions` must be a non-empty list of
    ids declared on the same hypothesis, where the valid citation space is
    the union of `predictions[]` (`p*`) and `attribute_predictions[]` (`ap*`)
    per rule #33. A refutation that cites no prediction is a free-floating
    negation; a refutation citing an id not on the hypothesis is pointing
    across a sibling boundary (the kind of rollup rule 25 catches for
    resolutions).
    """
    errors: list[str] = []
    for h in iter_hypotheses(merged):
        hid = h.get("id", "?")
        declared_preds = {
            p.get("id")
            for p in (h.get("predictions") or [])
            if isinstance(p, dict) and isinstance(p.get("id"), str)
        }
        declared_attr_preds = {
            a.get("id")
            for a in (h.get("attribute_predictions") or [])
            if isinstance(a, dict) and isinstance(a.get("id"), str)
        }
        valid = declared_preds | declared_attr_preds
        for r in h.get("refutation_shape", []) or []:
            if not isinstance(r, dict):
                continue
            rid = r.get("id", "?")
            refutes = r.get("refutes_predictions")
            if refutes is None:
                errors.append(
                    f"hypothesis {hid} refutation {rid}: missing required "
                    f"`refutes_predictions` field — name the prediction "
                    f"id(s) this shape refutes."
                )
                continue
            if not isinstance(refutes, list) or not refutes:
                errors.append(
                    f"hypothesis {hid} refutation {rid}: "
                    f"`refutes_predictions` must be a non-empty list of "
                    f"prediction ids, got {refutes!r}."
                )
                continue
            foreign = [p for p in refutes if not isinstance(p, str) or p not in valid]
            if foreign:
                errors.append(
                    f"hypothesis {hid} refutation {rid}: refutes_predictions "
                    f"{sorted(str(f) for f in foreign)} do not appear in "
                    f"{hid}'s declared predictions {sorted(declared_preds) or '[]'} "
                    f"or attribute_predictions {sorted(declared_attr_preds) or '[]'}. "
                    f"A refutation can only overturn predictions on its own hypothesis."
                )
    return errors
