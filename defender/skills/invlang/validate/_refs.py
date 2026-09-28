"""Reference rules: does every id a row cites resolve to something the document declares?"""
from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any, NamedTuple

from .. import _walkers
from ..parser import (
    COMMITMENT_ID_RE,
    HYPOTHESIS_ID_RE,
    is_conclude_empty_marker,
)
from ..schema import (
    CompanionBody,
    FindingRecord,
    HypothesisRecord,
)
from ._diag import _DECLARE_IT_YOURSELF


def _check_lead_refs(companion: CompanionBody) -> list[str]:
    """`:L findings` is the sole site that declares a lead; every other mention must resolve
    to one.

    The projector opens a bucket for any lead id it meets, so only the name (which only a
    declaring row carries) separates a declaration from a typo or forward reference.
    """
    findings = _leads(companion)
    declared = {
        f["id"] for f in findings
        if isinstance(f.get("id"), str) and f.get("name")
    }
    errors: list[str] = []
    for f in findings:
        fid = f.get("id")
        if not isinstance(fid, str) or fid in declared:
            continue
        # One repair per shape: a comma-joined id is not a lead, so "declare it" would be
        # wrong advice there.
        repair = (
            " — a resolution is owned by exactly one lead; attribute it to one "
            "and name the others in `cites_leads`"
            if "," in fid else _DECLARE_IT_YOURSELF
        )
        errors.append(
            f"undeclared lead {fid!r}: referenced by a `:R` / `:T` row or a "
            f"lead sub-block, but no `:L findings` row declares it{repair}"
        )
    for row in _walkers.iter_grounded_resolutions(companion):
        owner = row.get("resolved_by_lead")
        for cited in row.get("cites_leads") or []:
            if cited not in declared:
                # Names the repair too: a harness-reserved id can be reached this way.
                errors.append(
                    f"`cites_leads` on the resolution owned by "
                    f"{owner or '<unattributed>'} names {cited!r}, which no "
                    f"`:L findings` row declares{_DECLARE_IT_YOURSELF}"
                )
            elif cited == owner:
                errors.append(
                    f"`cites_leads` on {owner}'s resolution cites {owner} "
                    f"itself — it names the other leads the verdict rests on"
                )
    return errors


def _declared_prediction_ids(hyp: HypothesisRecord) -> set[str]:
    """Both PREDICT blocks: the `⟺` annotation form cites `ap*` next to `p*`, so
    `:H h-NNN.attr_preds` declares matched-prediction ids just as `.preds` does."""
    return {p["id"] for p in hyp.get("predictions") or []} | {
        ap["id"] for ap in hyp.get("attribute_predictions") or []
    }


def _unresolved(cited: list[str], declared: set[str]) -> list[str]:
    # Deduped: one undeclared id is one defect however often it is cited.
    return [c for c in dict.fromkeys(cited) if c not in declared]


def _known_ids(declared: set[str]) -> str:
    return ", ".join(sorted(declared)) or "none"


#: The two blocks that declare a hypothesis, named in every undeclared-`h-*` error.
_HYPOTHESIS_DECLARING_BLOCKS = (
    "`:H hypothesize.hypotheses` or `:H l-NNN.new_hypotheses`"
)


def _undeclared_hypothesis(where: str, site: str, hid: str, declared: str) -> str:
    """`where` locates the row — `"lead l-001: "`, or empty for a document-level block —
    and `site` is the phrase naming the column that made the reference."""
    return (
        f"{where}{site} undeclared hypothesis {hid!r} — no "
        f"{_HYPOTHESIS_DECLARING_BLOCKS} row declares it (declared: {declared}); "
        f"a hypothesis born mid-run is declared by the lead that found it, "
        f"before anything references it"
    )


def _leads(companion: CompanionBody) -> list[FindingRecord]:
    """Every projected lead, non-dict entries dropped."""
    return [f for f in companion.get("findings") or [] if isinstance(f, dict)]


def _lead_prefix(lid: str) -> str:
    return f"lead {lid}: "


class _TestsToken(NamedTuple):
    """One entry of a `:L findings` `tests` cell, split into the namespaces that own it.

    The cell mixes hypotheses and commitments, so it is classified once, exhaustively, rather
    than regex-selected per reader (which let tokens matching neither reach no rule):

    * bare `h-001` / `h-001-002` -> `hypothesis`
    * bare `p2` / `ap1` / `r1` / `ac1` -> `commitment`
    * qualified `h-001.ac1` -> both
    * `lp1` -> `foreign`: a lead-scoped namespace these hypothesis-scoped rules cannot resolve
    * anything else -> none, and `_check_tested_id_namespaces` refuses it
    """

    raw: str
    hypothesis: str | None
    commitment: str | None
    foreign: bool = False


_LEAD_PRED_ID_RE = re.compile(r"lp\d+")


def _classify_tests_token(tok: str) -> _TestsToken:
    """One `tests` entry, resolved against every namespace the column can carry."""
    if HYPOTHESIS_ID_RE.fullmatch(tok):
        return _TestsToken(tok, tok, None)
    if COMMITMENT_ID_RE.fullmatch(tok):
        return _TestsToken(tok, None, tok)
    owner, dot, local = tok.rpartition(".")
    if dot and HYPOTHESIS_ID_RE.fullmatch(owner) and COMMITMENT_ID_RE.fullmatch(local):
        return _TestsToken(tok, owner, local)
    if _LEAD_PRED_ID_RE.fullmatch(tok):
        return _TestsToken(tok, None, None, foreign=True)
    return _TestsToken(tok, None, None)


def _tests_tokens(lead: FindingRecord) -> list[_TestsToken]:
    return [
        _classify_tests_token(tok)
        for tok in (lead.get("tests_hypotheses") or [])
        if isinstance(tok, str) and tok
    ]


def _cited_hypothesis_ids(lead: FindingRecord) -> Iterator[tuple[str, list[str]]]:
    """Every `h-*` a lead names in its `tests` column, paired with the phrase that says where.

    Includes the hypothesis half of a qualified `h-001.ac1`. Tokens in no namespace are left
    to `_check_tested_id_namespaces`.
    """
    cited = [tok.hypothesis for tok in _tests_tokens(lead) if tok.hypothesis]
    if cited:
        yield "`:L findings` tests", cited


def _hypothesis_references(
    companion: CompanionBody,
) -> Iterator[tuple[str, str, list[str]]]:
    """Every site that names an `h-*`, as `(where, site-phrase, ids-in-row-order)`."""
    for lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        if isinstance(hid, str):
            yield _lead_prefix(lid), "resolution moves", [hid]
    surviving = [
        row["hypothesis"]
        for row in (companion.get("conclude") or {}).get("surviving_hypotheses") or []
        if isinstance(row, dict) and isinstance(row.get("hypothesis"), str)
    ]
    if surviving:
        yield "", "`:T conclude.surviving` names", surviving
    for lead in _leads(companion):
        where = _lead_prefix(lead.get("id", "?"))
        for site, cited in _cited_hypothesis_ids(lead):
            yield where, site, cited


def _check_hypothesis_refs(
    companion: CompanionBody, *, deferred: frozenset[str] | None
) -> list[str]:
    """`:H hypothesize.hypotheses` and `:H l-NNN.new_hypotheses` are the sole sites that
    declare a hypothesis; every other mention of an `h-*` must resolve to one.

    Otherwise a phantom hypothesis could move to `++` silently and be reported live. Covers
    resolutions, a lead's `tests`, and `:T conclude.surviving`.

    `deferred` holds ids from `:H` declaration blocks the parser rejected; references to them
    are not reported again, since the parse warning already names the cause. `None` means a
    dropped declaration could not be mapped to ids, and stands the rule down entirely.
    """
    if deferred is None:
        return []
    declared = set(_walkers.all_hypotheses(companion))
    known = _known_ids(declared)
    resolvable = declared | deferred
    return [
        _undeclared_hypothesis(where, site, hid, known)
        for where, site, cited in _hypothesis_references(companion)
        for hid in _unresolved(cited, resolvable)
    ]


def _declared_commitments(hyp: HypothesisRecord) -> set[str]:
    """Every id a hypothesis's `:H h-NNN.<sub>` blocks declare, across all four namespaces."""
    return (
        _declared_prediction_ids(hyp)
        | {r["id"] for r in hyp.get("refutation_shape") or []}
        | {
            c["id"] for c in hyp.get("authorization_contract") or []
            if isinstance(c, dict) and c.get("id")
        }
    )


def _check_tested_commitment_refs(companion: CompanionBody) -> list[str]:
    """A `p*`/`ap*`/`r*`/`ac*` in `:L findings`' `tests` column resolves against a
    hypothesis that same row says it is testing.

    Scoped to the hypotheses the same row names, so a sibling's `p2` is not accepted; a row
    naming no hypothesis falls back to every declared one. `lp*` (lead-scoped) and tokens in
    no namespace are other rules' concern.
    """
    by_hyp = {
        hid: _declared_commitments(hyp)
        for hid, hyp in _walkers.all_hypotheses(companion).items()
    }
    errors: list[str] = []
    for lead in _leads(companion):
        tokens = _tests_tokens(lead)
        # Bare tokens only; a qualified `h-001.ac1` is checked below against its own
        # hypothesis, not the row's union.
        named = [tok.raw for tok in tokens if tok.hypothesis and not tok.commitment]
        if any(h not in by_hyp for h in named):
            # `_check_hypothesis_refs` reports the undeclared `h-*`; nothing to scope against.
            continue
        scope_ids = named or list(by_hyp)
        if not scope_ids:
            # No hypotheses at all (typically a rejected `:H` block, already reported).
            continue
        scope: set[str] = set()
        for h in scope_ids:
            scope |= by_hyp[h]
        cited = [tok.raw for tok in tokens if tok.commitment and not tok.hypothesis]
        for cid in _unresolved(cited, scope):
            errors.append(
                f"{_lead_prefix(lead.get('id', '?'))}`:L findings` tests commitment "
                f"{cid!r}, which none of the hypotheses it tests declares "
                f"({_known_ids(set(scope_ids))}) — a `p*`/`ap*` is declared by "
                f"`:H h-NNN.preds` / `.attr_preds`, an `r*` by `.refuts` and an `ac*` by "
                f"`.authz` (declared: {_known_ids(scope)})"
            )
        # Qualified tokens resolve against the hypothesis they name; an undeclared one is
        # `_check_hypothesis_refs`'s to report.
        for tok in tokens:
            if not (tok.hypothesis and tok.commitment) or tok.hypothesis not in by_hyp:
                continue
            if tok.commitment not in by_hyp[tok.hypothesis]:
                errors.append(
                    f"{_lead_prefix(lead.get('id', '?'))}`:L findings` tests commitment "
                    f"{tok.raw!r}, but {tok.hypothesis} does not declare "
                    f"{tok.commitment!r} (declared: {_known_ids(by_hyp[tok.hypothesis])}) "
                    f"— a qualified `h-NNN.<id>` resolves against the hypothesis it names, "
                    f"never against a sibling on the same row"
                )
    return errors


def _check_tested_id_namespaces(companion: CompanionBody) -> list[str]:
    """Every `:L findings` `tests` entry lands in a namespace some rule owns.

    Without this, a token like `h_888` matches neither the hypothesis nor the commitment rule
    and validates clean.
    """
    errors: list[str] = []
    for lead in _leads(companion):
        for tok in _tests_tokens(lead):
            if tok.hypothesis or tok.commitment or tok.foreign:
                continue
            errors.append(
                f"{_lead_prefix(lead.get('id', '?'))}`:L findings` tests {tok.raw!r}, which "
                f"is in no id namespace this format declares — write a hypothesis "
                f"(`h-001`, `h-001-002`), a commitment the tested hypotheses declare "
                f"(`p1`/`ap1`/`r1`/`ac1`), or the qualified form `h-001.ac1`"
            )
    return errors


def _check_prediction_refs(companion: CompanionBody) -> list[str]:
    """A resolution matches only the predictions and refutations its own hypothesis
    declared.

    The parser takes `matched_prediction_ids` from id-shaped head tokens without a lookup, so
    unchecked, a `++` could rest on a nonexistent prediction or a sibling's.
    """
    errors: list[str] = []
    declared_by_hyp = {
        hid: (
            _declared_prediction_ids(hyp),
            {r["id"] for r in hyp.get("refutation_shape") or []},
        )
        for hid, hyp in _walkers.all_hypotheses(companion).items()
    }
    for lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        entry = declared_by_hyp.get(hid) if isinstance(hid, str) else None
        if entry is None:
            # Undeclared hypothesis: `_check_hypothesis_refs` reports it once.
            continue
        preds, refuts = entry
        for pid in _unresolved(res.get("matched_prediction_ids") or [], preds):
            errors.append(
                f"lead {lid}: resolution of {hid} cites prediction {pid!r}, "
                f"which {hid} does not declare (`:H {hid}.preds` / "
                f"`.attr_preds` declare: {_known_ids(preds)}) — a resolution "
                f"matches only its own hypothesis's predictions"
            )
        for rid in _unresolved(res.get("matched_refutation_ids") or [], refuts):
            errors.append(
                f"lead {lid}: resolution of {hid} cites refutation {rid!r}, "
                f"which {hid} does not declare (`:H {hid}.refuts` declares: "
                f"{_known_ids(refuts)})"
            )
    return errors


def _parent_hypothesis_id(hid: str) -> str:
    """The hypothesis `hid` hangs under, or `""` for a top-level one.

    The relation lives only in the id: `h-001-002`'s parent is `h-001`.
    """
    head, _, _tail = hid.rpartition("-")
    return head if "-" in head else ""


#: A leading full stop that is punctuation, not a decimal point (`".5σ"` keeps its dot).
_LEADING_SENTENCE_STOP_RE = re.compile(r"^\.(?!\d)")


def _normalized_claim(claim: Any) -> str:
    """One claim, stripped of the differences that are not differences: case, inner
    whitespace, and the sentence punctuation the model varies freely.

    A leading full stop is kept only before a digit, so `.5σ` and `5σ` stay distinct while
    `". x"` and `"x"` do not (which would let one typed character evade rule #23). Iterated to
    a fixpoint because quotes and full stops can nest (`'enabled'.` vs `'enabled.'`).
    """
    if not isinstance(claim, str):
        return ""
    text = " ".join(claim.lower().split())
    while True:
        nxt = _LEADING_SENTENCE_STOP_RE.sub("", text.strip("\"'")).rstrip(" .").strip()
        if nxt == text:
            return text
        text = nxt


def _predicted_observables(hyp: HypothesisRecord) -> frozenset[str]:
    """A hypothesis's declared claims, normalized for comparison against a sibling's.

    Reads both prediction blocks; an `attr_preds` key includes its `target` and `attribute`.
    The `.preds` `subject` cell is not part of the identity: the same claim under a different
    subject still gives no lead a way to split the two.
    """
    out = set()
    for pred in hyp.get("predictions") or []:
        if isinstance(pred, dict) and (claim := _normalized_claim(pred.get("claim"))):
            out.add(claim)
    for ap in hyp.get("attribute_predictions") or []:
        # A blank claim is rule #33's to refuse; counting it would add a spurious fork error.
        if not isinstance(ap, dict) or not (claim := _normalized_claim(ap.get("claim"))):
            continue
        target = str(ap.get("target", "")).strip().lower()
        attribute = str(ap.get("attribute", "")).strip().lower()
        out.add(f"{target}.{attribute}={claim}")
    return frozenset(out)


#: Rule #23's diagnostic phrase, a named constant so tests can filter its messages without
#: copying prose that would silently stop matching if reworded.
_SIBLING_FORK_TAG = "predict the same observables"


def _check_fork_distinctness(companion: CompanionBody) -> list[str]:
    """Rule #23: siblings (hypotheses sharing a parent hypothesis and an anchor) must not
    predict the same observables.

    Keyed on the predicted observable, not the parent classification: the SKILL asks siblings
    to leave unsettled slots `??` and fork in their predictions. Only textual identity (after
    normalization) is testable; paraphrase stays the author's discipline.

    A hypothesis with no predictions yet is exempt, since its `.preds` block may arrive in a
    later append. Only live hypotheses (final weight not `--`) are compared: `:H` rows are
    immutable, so refuting one is the only repair, matching `_check_hypothesis_persistence`.
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    groups: dict[tuple[str, str], dict[frozenset[str], list[str]]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        if hid not in live:
            continue
        claims = _predicted_observables(hyp)
        if not claims:
            continue
        key = (_parent_hypothesis_id(hid), str(hyp.get("anchor") or ""))
        groups.setdefault(key, {}).setdefault(claims, []).append(hid)
    errors: list[str] = []
    for (_parent, anchor), by_claims in groups.items():
        for hids in by_claims.values():
            if len(hids) < 2:
                continue
            errors.append(
                f"hypotheses {', '.join(sorted(hids))} anchor on {anchor or '?'} and "
                f"{_SIBLING_FORK_TAG} — siblings must differ on at least one predicted "
                f"observable, the claim a lead splits them on. A different `?name` or "
                f"`parent_class` is not that difference: leave the slots the alert has not "
                f"settled `??` and write the difference as a prediction. If the two readings "
                f"share a cause and differ only on whether it was authorized, they are ONE "
                f"hypothesis with an `:H h-NNN.authz` contract"
            )
    return errors


def _check_refutation_scope(companion: CompanionBody) -> list[str]:
    """A refutation shape overturns ITS OWN hypothesis's predictions, and only those.

    Checks the `:H h-NNN.refuts` `refutes` column. A phantom scope matters: a `--` citing the
    refutation exempts the hypothesis from rule #34's prediction closure. Silent when the
    hypothesis declares no predictions (rule #23's lean shape).
    """
    errors: list[str] = []
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        shapes = hyp.get("refutation_shape") or []
        if not shapes:
            continue
        declared = _declared_prediction_ids(hyp)
        if not declared:
            continue
        for shape in shapes:
            rid = shape.get("id", "?")
            cited = [
                pid for pid in shape.get("refutes_predictions") or []
                # `none` / `n/a` is the empty-array marker, not a prediction id.
                if not is_conclude_empty_marker(pid)
            ]
            for pid in _unresolved(cited, declared):
                errors.append(
                    f"`:H {hid}.refuts` row {rid!r} refutes prediction {pid!r}, which "
                    f"{hid} does not declare (`:H {hid}.preds` / `.attr_preds` declare: "
                    f"{_known_ids(declared)}) — a refutation overturns its own "
                    f"hypothesis's predictions, and a `--` citing it inherits that scope"
                )
    return errors


def _check_authz_contract_ids(companion: CompanionBody) -> list[str]:
    """An `ac*` id is declared by AT MOST ONE LIVE hypothesis.

    `:R authz` names only the contract id, so two live hypotheses sharing `ac1` would both be
    discharged by one row, failing the benign gate open. `ac*` numbers across the document
    (unlike `p*`/`r*`).

    Live only, so a collision already on disk stays repairable by refuting one side (`:H` rows
    are immutable). That alone does not disambiguate the id; `_check_benign_authz` also scopes
    a shared id by anchor kind.
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    declared_by: dict[str, set[str]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        if hid not in live:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id")
            if isinstance(cid, str) and cid:
                declared_by.setdefault(cid, set()).add(hid)
    return [
        f"authz contract {cid!r} is declared by more than one live hypothesis "
        f"({', '.join(sorted(hids))}) — a `:R authz` row names only the contract it "
        f"fulfills, so one row would discharge all of them; number `ac*` across the "
        f"document, not per hypothesis (or refute one of them, if the evidence says so)"
        for cid, hids in declared_by.items()
        if len(hids) > 1
    ]
