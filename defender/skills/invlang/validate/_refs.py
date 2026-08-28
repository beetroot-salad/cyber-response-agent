"""Does every id a row cites resolve to something the document declares?

One family of `validate.py`'s rules, split out at 4038 lines: lead references, hypothesis
references, prediction and commitment citations, and the id namespaces that keep a token
in no namespace from reaching no rule at all.
"""
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

    The projector opens a bucket for any lead id it meets, so a typo, a forward reference, and
    a comma-joined pair of real ids (`l-004,l-005`) are indistinguishable from a declaration at
    projection time. Only a declared lead carries a name, so that is what separates the two.
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
        # ONE repair per shape, never both. A comma-joined id is not a lead at all, so
        # "declare it in a `:L findings` block" is advice that would have the author declare
        # `l-004,l-005` AS a lead — and printed right after the split-it hint it contradicts
        # the sentence before it. The harness-reserved sentence rides only on the shape it is
        # about (#964): an id the author may legitimately declare.
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
                # The SAME repair the declaring arm above carries, and for the same reason: a
                # `cites_leads` cell is one of the two ways MAIN reaches a harness-reserved id
                # whose declaring row the seed declined to write (#964), and a refusal that
                # named the fault without naming the move left that trap open on this path
                # alone.
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
    # Deduped: `[l-001 p1 + l-003 p1,p2 …]` cites p1 twice, and one undeclared id is one
    # defect however many times the head names it.
    return [c for c in dict.fromkeys(cited) if c not in declared]


def _known_ids(declared: set[str]) -> str:
    return ", ".join(sorted(declared)) or "none"


#: The two blocks that DECLARE a hypothesis. Named in every undeclared-`h-*` error, so the
#: author is told where the declaration goes rather than only that one is missing.
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
    """Every projected lead, non-dict entries dropped. THE way this module reads `findings`,
    so a hand-rolled walk cannot skip the guard the next one over remembers."""
    return [f for f in companion.get("findings") or [] if isinstance(f, dict)]


def _lead_prefix(lid: str) -> str:
    return f"lead {lid}: "


class _TestsToken(NamedTuple):
    """One entry of a `:L findings` `tests` cell, split into the namespaces that own it.

    The cell is MIXED — a lead names the hypotheses it discriminates AND the commitments it
    was run for — so a reader wanting one kind has to select. Selecting by regex in a
    comprehension is what let `h-001.ac1` fall out of BOTH selections and be checked by
    nothing (#932/#972 follow-up): it is not a bare `h-*` and not a bare `p*`/`ac*`, so the
    hypothesis rule skipped it and the commitment rule skipped it, on a live run whose lead
    named that contract and nothing else.

    Classifying once, exhaustively, is the fix. Every token lands in exactly one of four
    shapes and the fourth is REPORTED rather than dropped:

    * bare `h-001` / `h-001-002` -> `hypothesis`
    * bare `p2` / `ap1` / `r1` / `ac1` -> `commitment`
    * qualified `h-001.ac1` -> BOTH, and the pairing is what makes it checkable
    * `lp1` -> `foreign`: a real namespace, which this column's two rules cannot resolve
    * anything else -> none of them, and `_check_tested_id_namespaces` refuses it

    `foreign` is why the last arm can be a refusal at all. An `lp*` is scoped to a LEAD while
    both readers here scope to a HYPOTHESIS, so no hypothesis's declarations could resolve it
    and `_check_lead_prediction_structure` owns it where it lives. Recognized-but-unresolvable
    and unrecognized are different answers; collapsing them would either deny a legal `lp1` or
    wave through an `h_888`, which is exactly the pair the old shape gate could not separate.

    The qualified spelling is the one spec rule #7 blesses for `fulfills_contract`, and
    `_check_authz_contract_closure` already accepts it there — reusing its `rpartition`
    idiom rather than restating the split."""

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
    # Module-level and defined further down; function bodies resolve at call time.
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
    """Every `h-*` a LEAD names, paired with the phrase that says where.

    One site since #933 retired `:T shelved`: `:L findings`' `tests` column, which the parser
    splits to `tests_hypotheses` through `_split_csv` without ever looking the ids up.

    Reads the classified tokens rather than regex-filtering the raw cell, so the hypothesis
    HALF of a qualified `h-001.ac1` is a reference like any other. Previously this filtered on
    `HYPOTHESIS_ID_RE` alone and the qualified spelling matched nothing, so a lead whose
    `tests` cell was exactly `h-001.ac1` had its hypothesis reference checked by no rule at
    all — the shape `.defender-runs/turnN-A` l-003 actually wrote.

    A token in NO namespace is not smuggled in here as a hypothesis: `_check_tested_id_
    namespaces` owns it and names it for what it is, so `h_888` still cannot read as some
    other kind of id and pass. That is the residue the old docstring accepted as the price of
    the shape gate; classifying exhaustively is what stops it being a price.
    """
    cited = [tok.hypothesis for tok in _tests_tokens(lead) if tok.hypothesis]
    if cited:
        yield "`:L findings` tests", cited


def _hypothesis_references(
    companion: CompanionBody,
) -> Iterator[tuple[str, str, list[str]]]:
    """Every site that names an `h-*`, as `(where, site-phrase, ids-in-row-order)`.

    The census in one place, so "which sites reference a hypothesis" is a list to extend
    rather than a branch to remember to add.
    """
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

    `_check_lead_refs`'s analogue for the other id the projector opens no bucket for. A typo,
    a forward reference and a genuinely absent hypothesis are indistinguishable at projection
    time, so a phantom would move to `++` in silence and `_walkers.final_weights` would report
    it live.

    THREE sites reference an `h-*` and this owns all three: a resolution, a lead's `tests`,
    and `:T conclude.surviving`. The middle one is the one a run reaches first — a lead can
    claim to TEST a hypothesis nobody declared.

    `deferred` keeps the deference honest: a `:H` DECLARATION block the parser rejected (a
    stale header, an `attached_to` naming an edge) leaves every reference to it looking
    phantom, and the parse warning already names the cause. One defect, one error. It is keyed
    to the dropped IDS, not to the document, so an unrelated typo three leads away is still
    reported. `None` is the parser's "a dropped declaration could not be mapped to an id at
    all", and only that stands the rule down wholesale.
    """
    if deferred is None:
        return []
    declared = set(_walkers.all_hypotheses(companion))
    known = _known_ids(declared)
    # A dropped id is as good as a declared one HERE and only here: rule 1 already reported
    # the block that deleted it, and a second error would point away from the fix.
    resolvable = declared | deferred
    # `_unresolved` per site, the same dedup-then-filter the citation rule uses: one id
    # written twice in `tests` is one defect, not two.
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

    The other half of the mixed column: without it `tests=h-001,p9,ac9` names two commitments
    that do not exist and validates clean.

    Scoped to the hypotheses the SAME row names, not to the document. A `p2` means "h-001's
    p2" when the row tests h-001; resolving it against every hypothesis in the run would
    accept a sibling's `p2`, which is exactly the cross-citation `_check_prediction_refs`
    refuses one level down. A row naming no hypothesis at all has nothing to scope to, so it
    falls back to every declared hypothesis rather than inventing a stricter rule than the
    format states.

    NOT resolved here: an `lp*`, exempt after #933 projected `:L l-NNN.lead_preds` for a
    better reason than "nothing declares it". An `lp*` is scoped to a LEAD and this column is
    scoped to a HYPOTHESIS, so no hypothesis's declarations could resolve it;
    `_check_lead_prediction_structure` owns that namespace where it lives. It is now carried
    as `_TestsToken.foreign` rather than falling out of a regex — that exemption used to be a
    side effect of `COMMITMENT_ID_RE` not matching `lp1`, and the same silence is what hid
    `h_888` and the qualified `h-001.ac1`.

    An id in NO namespace is no longer a blind spot either: `_check_tested_id_namespaces`
    reports it by name, closing the residue the old shape gate accepted as the price of the
    mixed column.
    """
    by_hyp = {
        hid: _declared_commitments(hyp)
        for hid, hyp in _walkers.all_hypotheses(companion).items()
    }
    errors: list[str] = []
    for lead in _leads(companion):
        tokens = _tests_tokens(lead)
        # BARE tokens only. A qualified `h-001.ac1` names its own declarer, so it is scoped
        # below against that hypothesis rather than against the row's union — the union would
        # accept `h-001.ac1` because a SIBLING on the same row declares `ac1`, which is the
        # cross-citation this rule refuses one level down.
        named = [tok.raw for tok in tokens if tok.hypothesis and not tok.commitment]
        if any(h not in by_hyp for h in named):
            # An undeclared or dropped `h-*` on this row: `_check_hypothesis_refs` owns
            # that defect, and its commitments cannot be scoped until it is fixed.
            continue
        scope_ids = named or list(by_hyp)
        if not scope_ids:
            # Nothing to scope AGAINST — the row names no hypothesis and the document
            # declares none, which is the shape a rejected `:H` block leaves behind. Rule 1
            # already reported that block; reporting every commitment on top of it is the
            # second error for one defect the sibling rule's deference exists to prevent.
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
        # The qualified spelling carries its own scope, so it is resolved against the
        # hypothesis it names and no other. Skipped when that hypothesis is undeclared —
        # `_check_hypothesis_refs` owns THAT defect and reports it by id.
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

    The column is mixed — hypotheses and the commitments a lead was run for — and both
    readers of it used to SELECT their kind with a regex, which meant a token in neither
    namespace was skipped by both and validated clean. `h_888`, `H-888` and the qualified
    `h-001.ac1` all had that shape; the last one is not even a defect, and it went unchecked
    on a live run because nothing claimed it. `_classify_tests_token` resolves the three
    legal shapes, and this rule is what makes the fourth a finding instead of a silence.

    Measured before arming: across the 27 documents in the tree carrying invlang, 150 `tests`
    tokens resolve — 146 bare `h-*`, 2 bare commitments, 2 qualified — and after the
    qualified spelling is recognized, ZERO fall through. Error severity costs nothing on the
    current corpus and no shipped golden or worked example fires.
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

    The parser derives this reference by heuristic, not by lookup: `matched_prediction_ids` is
    just the id-shaped head tokens, never joined back to the declaring `:H h-NNN.preds` block.
    Unchecked, a typo, a forward reference and a *sibling's* `p1` all parse clean — a `++`
    could rest on a prediction that does not exist, or on one belonging to the hypothesis it is
    being weighed against.
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
            # `_check_hypothesis_refs` owns the undeclared-`h-*` defect, and with no
            # declaring block there is nothing to resolve these citations against. One
            # defect stays one error rather than three piled on the same row.
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

    `HYPOTHESIS_ID_RE` admits `h-001` and the hierarchical child `h-001-002`; only the second
    has a parent, and it is the id minus its last segment. Read off the id because that is
    where the dense form carries the relation — no row names a parent hypothesis.
    """
    head, _, _tail = hid.rpartition("-")
    return head if "-" in head else ""


#: A LEADING full stop that is sentence punctuation rather than a decimal point — the one
#: `_normalized_claim` may strip. `".5σ above baseline"` keeps its dot because a digit follows
#: it; `". the parent is systemd"` loses one, because otherwise a leading dot is a free way to
#: spell an observable a sibling already spelled and walk past rule #23.
_LEADING_SENTENCE_STOP_RE = re.compile(r"^\.(?!\d)")


def _normalized_claim(claim: Any) -> str:
    """One claim, stripped of the differences that are not differences: case, inner
    whitespace, and the sentence punctuation the model varies freely.

    A leading full stop is kept only in front of a DIGIT. `str.strip` takes a character SET,
    so stripping `" .\\"'"` from both ends also eats a decimal point — collapsing
    `".5σ above baseline"` into `"5σ above baseline"` and refusing a sibling pair that forks
    on a tenfold threshold. Keeping every leading dot instead is the opposite failure and the
    worse one: it fails OPEN, because `". failures arrive in bursts"` then normalizes apart
    from `"failures arrive in bursts"` and one typed character retires rule #23 on a pair that
    forks on nothing.

    TO A FIXPOINT, because one pass of a strip set is not one pass of the punctuation an
    author can nest. A quote sitting OUTSIDE the sentence period (`the unit is \'enabled\'.`
    beside `the unit is \'enabled.\'` — the same observable, punctuated two ways) is only
    exposed once the full stop is gone, and the stop under it only once the quote is. The loop
    terminates because every iteration strips or stops.
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

    BOTH prediction blocks, the way `_declared_prediction_ids` reads both: an `:H h-NNN
    .attr_preds` row is a predicted observable too — the most concrete kind — so a pair that
    forks only there is distinct and must not be refused. Its `target` and `attribute` join
    the key, since predicting a different attribute of a different vertex is a difference even
    when the claim text coincides.

    The `.preds` `subject` cell is deliberately NOT part of the identity: the same claim filed
    once under `proposed_parent` and once under `proposed_edge` still leaves no lead able to
    split the two rows.
    """
    out = set()
    for pred in hyp.get("predictions") or []:
        if isinstance(pred, dict) and (claim := _normalized_claim(pred.get("claim"))):
            out.add(claim)
    for ap in hyp.get("attribute_predictions") or []:
        # A BLANK claim contributes nothing rather than an empty-valued key. Rule #33 already
        # refuses the row; counting it here would turn two separately-defective hypotheses
        # into a spurious third error saying they are one fork.
        if not isinstance(ap, dict) or not (claim := _normalized_claim(ap.get("claim"))):
            continue
        target = str(ap.get("target", "")).strip().lower()
        attribute = str(ap.get("attribute", "")).strip().lower()
        out.add(f"{target}.{attribute}={claim}")
    return frozenset(out)


#: Rule #23's diagnostic identity — the phrase every message the fork check emits is built
#: from, and the only stable handle a test has for picking those messages out of
#: `validate_companion`'s flat list. A NAMED CONSTANT rather than a phrase two files happen to
#: spell the same way: a filter written as a copied phrase silently stops matching the day the
#: prose is reworded, which turns every `== []` assertion downstream of it into a pass the
#: suite earns by finding nothing — how a deleted rule looks from the outside.
_SIBLING_FORK_TAG = "predict the same observables"


def _check_fork_distinctness(companion: CompanionBody) -> list[str]:
    """Rule #23, which absorbed #35. Siblings — hypotheses sharing a parent hypothesis and an
    anchor — must not predict the same observables.

    Two spec rules described this check and neither had an implementation: #23 keyed on the
    parent classification, #35 ("sibling prediction divergence") on the prediction signature.
    #934 moved #23 onto the observable, which is what #35 already said, so they are one rule
    here and #23 is the number that ships (`docs/investigation-language.md`). #35's signature
    included `predictions[].subject`; this drops it, for the reason `_predicted_observables`
    records.

    The predicted observable is the axis, NOT `proposed_edge.parent_vertex.classification`
    (SKILL.md §Sibling-fork uniqueness). Keying on the classification is the natural spelling
    and the wrong one: the shape the SKILL now asks for is siblings that leave the slots the
    alert has not settled `??` and fork in their predictions, so a classification-keyed check
    would refuse exactly the well-formed fork and pass the malformed one that mints a tuple to
    carry a difference the predictions already carry.

    TEXTUAL identity is the floor, and the whole of what this can honestly test. Two claims can
    say the same thing in different words and no validator will know; that stays the author's
    discipline, which is why the message carries the rule rather than only naming the ids.

    A hypothesis declaring NO predictions is exempt rather than treated as an empty set that
    collides with its sibling's. The document is written by append: `:H hypothesize.hypotheses`
    and the `:H h-NNN.preds` blocks arrive as separate writes, so the group is legally
    predictionless between the two — refusing it would deny the write that is on its way to
    satisfying the rule.

    LIVE only, for the reason `_check_authz_contract_ids` records: `:H` rows are immutable, so
    a collision already on disk is unrepairable under a declared-set reading and every later
    write would be denied for a row the author may no longer touch. Refuting one of the two is
    the in-grammar repair.

    LIVE is final weight `--` alone, which is the whole of what retirement means since #933
    retired `:T shelved`: a run that is no longer carrying a sibling resolves it. The rule and
    `_check_hypothesis_persistence` (#24) read the same word the same way, which is the
    property that matters — the two used to be able to disagree about what the run was still
    carrying, and this is the rule that wedged on the disagreement.
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

    `:H h-NNN.refuts`'s `refutes` column is the third place a `p*`/`ap*` is named, and it was
    the one nothing resolved. `_check_prediction_refs` walks the resolution head — which ids a
    MOVE matched — and rule #5's half of it walks the `r*` a `--` cited. Neither reaches the
    other direction: what the refutation itself claims to overturn. So `r1|p9,ap9|"..."` on a
    hypothesis declaring neither parsed and validated clean, and the `--` that later cited `r1`
    rested on a scope nobody checked.

    The consequence is not confined to bookkeeping. A hypothesis reaches `refuted` through a
    `--`, and rule #34's prediction closure exempts a refuted hypothesis — so a
    refutation with a phantom scope is a way to discharge every prediction on a hypothesis
    without settling any of them. The exemption is right; the hole was upstream of it.

    Scoped to the DECLARING hypothesis for the reason `_check_prediction_refs` is: a sibling's
    `p2` is not this hypothesis's evidence in either direction, and a document-wide lookup
    would accept it. Silent when the hypothesis declares no predictions at all — a refutation
    on a predictionless hypothesis has nothing to name, which is the lean shape rule #23
    exempts rather than a defect this rule owns.
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
                # `none` / `n/a` is the format's empty-ARRAY marker, not a prediction id
                # (`docs/dense-investigation-format.md`), and `:H` rows are immutable — so
                # reading it as a citation refuses a row saying "this refutation overturns
                # nothing" with no repair the grammar can express.
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

    `:R authz` has no hypothesis column — the row names the contract it fulfills and nothing
    else — so the id carries the binding and every reader resolves it document-wide.
    `_check_benign_authz` discharges a contract by bare id, so two live hypotheses that each
    numbered their first contract `ac1` would BOTH be discharged by one row, failing a
    `disposition: benign` write gate open with no diagnostic.

    The rule is on the DECLARING side rather than a scoping rule on the resolving side, because
    scoping cannot be recovered from a row that never carried the hypothesis: the honest fix
    for an ambiguous id is to refuse it. Per-hypothesis numbering is the natural mistake here —
    `p*` and `r*` DO restart per hypothesis — so the error says which ids collide and that
    `ac*` numbers across the document.

    LIVE, not declared, and the scope is what makes the rule repairable. `investigation.md` is
    append-only and `:H` rows are immutable, so a collision already on disk cannot be edited
    away: under a declared-set reading every later write would be denied for a row the author
    may no longer touch, and `learning/core/persist.py` dead-letters the run. Refuting one of
    the two is an in-grammar, append-only move that ends the ambiguity honestly. Two live
    hypotheses is the case with no honest reading, and stays refused.

    Refuting does NOT make the id unambiguous — the `:R authz` row carries no hypothesis
    column, so the refuted declarer's row discharges the live declarer's same-numbered contract
    too. `_check_benign_authz` closes that by scoping a shared id to the ANCHOR KIND both sides
    carry; the exemption here leaves the author a repair and is not on its own sufficient.

    Only the cross-hypothesis collision reaches here: `_extend_by_id` keeps the first row per
    id when ONE `:H <h>.authz` block repeats an id, so the folded record carries one contract
    either way. That repeat is not silent — the projector warns on it, because keeping the
    first row DISCARDS the second contract's predicate.
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
