
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Container, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, NamedTuple

from defender._vocab import normalized_disposition
from . import _walkers, vocab
from ._cells import _row_cells, _row_dict, _split_cells, _split_cells_raw, _unquote
from ._types import Block, RowError
from .parser import (
    _CONCLUDE_SUBTABLE_FIELDS,
    COMMITMENT_ID_RE,
    HYPOTHESIS_ID_RE,
    ParseWarning,
    deferred_hypothesis_ids,
    is_conclude_empty_marker,
    iter_blocks,
    parse_dense_companion,
    scan_fences,
)
from .schema import (
    AuthorizationContract,
    CompanionBody,
    DeferralRecord,
    EdgeRecord,
    FindingRecord,
    HypothesisRecord,
    ImpactPrediction,
    VertexRecord,
)

STRONG_AUTH_KINDS = vocab.STRONG_AUTH_KINDS
STRONG_WEIGHTS = vocab.STRONG_WEIGHTS
CONFIRMED_WEIGHT = vocab.CONFIRMED_WEIGHT
REFUTED_WEIGHT = vocab.REFUTED_WEIGHT
_STRONG_AUTH_KINDS_STR = " / ".join(sorted(STRONG_AUTH_KINDS))

_YAML_FENCE_RE = re.compile(r"```ya?ml\b")

#: `Diagnostic.severity`'s closed set. Declared once, beside the type that carries it.
Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class Locus:
    """Where a diagnostic's offending row actually is, when there is one row to point at.

    `row_text` is the row as the author WROTE it — never a reconstruction. Both families that
    populate a locus read it from the document: a parse warning carries its row, and the
    `:R attr_updates` check walks blocks rather than folded records. `row_index` is the ordinal
    WITHIN the block, not a file line number, and only the parse warnings have it."""

    block: str
    row_text: str
    row_index: int | None = None


@dataclass(frozen=True)
class Diagnostic:
    """One validation failure. `message` is the prose the model sees; `locus` and `fix` are
    optional structure alongside it.

    Only the families that can name a single offending row populate `locus` — parse warnings
    and `:R attr_updates`. The document-global checks (append-only, lead and prediction refs,
    strong-move provenance, benign gating, loop close, surface) have no row to point at and
    leave it `None`; so do the vocab sub-checks over `:V`/`:E`/`:H`, whose rows cannot be
    rebuilt without the block's declared column list."""

    message: str
    locus: Locus | None = None
    fix: tuple[str, ...] = field(default_factory=tuple)
    #: `"error"` (the write is refused and nothing is written) or `"warning"` (the write LANDS
    #: and the row gates the NEXT one until it is repaired). Assigned per check family at
    #: diagnose time, never document content — so no migration exists for older bytes.
    #: A closed `Literal`, not a bare `str`: the partition is read THREE ways across three
    #: modules (`== "warning"` here, `!= "warning"` in `validate_companion` and in
    #: `_artifact_schema.validate_investigation`), so a mistyped value would not fail — it
    #: would file silently as error severity at every one of them.
    severity: Severity = "error"


def _plain(messages: list[str]) -> list[Diagnostic]:
    """Lift the checks that carry no row into `Diagnostic`s. Those checks stay on `list[str]`
    deliberately: they gain nothing from the type."""
    return [Diagnostic(m) for m in messages]


def _parse_diagnostic(w: ParseWarning) -> Diagnostic:
    """A parse warning already knows its block, ordinal and raw row — `w.format()` folds them
    into prose. Keep the prose and carry the structure alongside it."""
    return Diagnostic(
        message=f"parse error: {w.format()}",
        locus=Locus(block=w.block, row_text=w.row, row_index=w.row_index),
    )


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")




def _check_surface(proposed_text: str, current_text: str | None) -> list[str]:
    """The on-disk surface is ```invlang fences, and this is the family that says so.

    Two ways to miss it. Writing the block under a ```yaml fence is the loud one — the
    document says invlang and the fence says otherwise. Writing it under NO fence is the
    quiet one, and it is the one that cost a run: a model that closes its ORIENT fence,
    writes a paragraph of prose, then continues with `## PLAN` and its `:H` blocks without
    reopening produces a file that reads correctly to a human and parses to nothing.
    `parse_dense_companion` returns no hypotheses, so #23, #5's declaring half, #6 and #34
    all have nothing to look at and all pass in silence, and `_check_append_only` — which
    counts ```invlang pairs and refuses a DECREASE — sees no decrease, because the write
    added no pair rather than removing one. Every hypothesis-side gate stood down on a
    document whose PLAN was never validated (#932, run `live-867-old`).

    `parser.scan_fences` does the accounting and carries the reasons the complement is
    reported rather than raised, and why a trailing unterminated fence is exempt. What is
    decided HERE is the policy over it.

    **Scoped to what THIS write introduces**, by subtracting the baseline's orphans from the
    proposal's rather than refusing any unfenced header in the document. `investigation.md`
    is append-only: a file that already carries unfenced rows cannot have them fenced after
    the fact, so a whole-document reading would refuse every later write for bytes no repair
    can reach — the append-only wedge the v2.22 delta closed on rules #6 and #17. The
    subtraction is a MULTISET difference over the header lines, not a count comparison: a
    write that drops one committed orphan while adding two would otherwise net to "+1" and
    name the wrong line. It also survives `fix_row`, which rewrites a row in place and adds
    no header. With no baseline every unfenced header is new, which is the right reading for
    a first write.

    **A baseline that stopped MID-BLOCK is exempt entirely.** With an unterminated ```invlang
    on disk, `INVLANG_FENCE_RE` pairs it with the OPENING delimiter of the next append, so
    that append's own block reads as orphaned — and `append_block` sends exactly one fenced
    block per call, so the refusal would name a repair the model had already made and every
    retry would be refused the same way. `scan_fences(...).open_tail` is that state, read off
    the baseline.

    The repair is the one the author can take: re-send the block inside a ```invlang fence.
    Bytes already committed unfenced stay as prose and parse to nothing, which is what they
    already did; the correctly fenced copy is what lands.
    """
    errors: list[str] = []
    if _YAML_FENCE_RE.search(proposed_text):
        # Reported ALONGSIDE the unfenced-header half, not instead of it: returning here
        # would hide every orphan behind the yaml fence until the author fixed that first.
        errors.append(
            "non-invlang surface: investigation.md contains a ```yaml/```yml "
            "fenced block, but the on-disk surface is ```invlang (defender "
            "SKILL §dense format). Rewrite the block(s) as ```invlang."
        )
    if current_text is not None and scan_fences(current_text).open_tail is not None:
        return errors
    baseline = Counter(
        scan_fences(current_text).orphaned_headers if current_text is not None else ()
    )
    introduced: list[str] = []
    for line in scan_fences(proposed_text).orphaned_headers:
        if baseline[line]:
            baseline[line] -= 1
        else:
            introduced.append(line)
    if not introduced:
        return errors
    shown = ", ".join(repr(line.strip()) for line in introduced[:3])
    if len(introduced) > 3:
        shown += f", … ({len(introduced)} in all)"
    errors.append(
        f"non-invlang surface: this write adds {len(introduced)} block header(s) OUTSIDE "
        f"any ```invlang fence — {shown}. Content outside a fence is not parsed, so the "
        f"rows under those headers reach no validator rule and no corpus query: they are "
        f"invisible, not merely unchecked. This is what a `## PLAN` section written after a "
        f"closed fence looks like. Re-send the block with ```invlang on its own line before "
        f"the first header and ``` after the last row."
    )
    return errors




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
        hint = (
            " — a resolution is owned by exactly one lead; attribute it to one "
            "and name the others in `cites_leads`"
            if "," in fid else ""
        )
        errors.append(
            f"undeclared lead {fid!r}: referenced by a `:R` / `:T` row or a "
            f"lead sub-block, but no `:L findings` row declares it{hint}. Declare it "
            f"in a `:L findings` block and re-send — including a HARNESS-RESERVED id "
            f"whose declaring row is not on the page: the harness reserves the id so "
            f"you do not attach new work to it, and writing the row it is missing is "
            f"not reusing it"
        )
    for row in _walkers.iter_grounded_resolutions(companion):
        owner = row.get("resolved_by_lead")
        for cited in row.get("cites_leads") or []:
            if cited not in declared:
                errors.append(
                    f"`cites_leads` on the resolution owned by "
                    f"{owner or '<unattributed>'} names {cited!r}, which no "
                    f"`:L findings` row declares"
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


def _vertex_core(v: VertexRecord) -> tuple:
    return (v.get("type"), v.get("classification"), v.get("identifier"))


def auth_kind_of(e: EdgeRecord) -> str | None:
    """An `:E` row's authority kind, or `None`. PUBLIC because `frontier._edge_index` keys the
    lesson EDGE axis on it and a second `e["authority"]["kind"]` spelling could drift."""
    auth = e.get("authority")
    return auth.get("kind") if auth else None


def _edge_core(e: EdgeRecord) -> tuple:
    return (
        e.get("relation"),
        e.get("source_vertex"),
        e.get("target_vertex"),
        auth_kind_of(e),
    )


def _by_id_first(records, core_fn) -> dict[str, tuple]:
    idx: dict[str, tuple] = {}
    for r in records:
        rid = r.get("id")
        if isinstance(rid, str) and rid not in idx:
            idx[rid] = core_fn(r)
    return idx


def _check_append_only(
    proposed_text: str,
    current_text: str | None,
    proposed: CompanionBody | None,
    current: CompanionBody | None,
) -> list[str]:
    if current_text is None:
        return []
    errors: list[str] = []

    cur_fences = len(scan_fences(current_text).bodies)
    new_fences = len(scan_fences(proposed_text).bodies)
    if new_fences < cur_fences:
        errors.append(
            f"append-only violation: proposed content has {new_fences} ```invlang "
            f"block(s) but the on-disk file has {cur_fences} — existing blocks must "
            f"not be removed (defender SKILL §Authoring discipline: append only)"
        )

    if not current:
        return errors

    proposed = proposed or CompanionBody()
    for label, records_cur, records_new, core_fn in (
        ("vertex", _walkers.all_vertices(current), _walkers.all_vertices(proposed), _vertex_core),
        ("edge", _walkers.all_edges(current), _walkers.all_edges(proposed), _edge_core),
    ):
        cur_idx = _by_id_first(records_cur, core_fn)
        new_idx = _by_id_first(records_new, core_fn)
        for rid, core in cur_idx.items():
            if rid not in new_idx:
                errors.append(
                    f"append-only violation: committed {label} {rid} present "
                    f"on-disk is missing from the proposed write — existing "
                    f"records must not be removed"
                )
            elif new_idx[rid] != core:
                errors.append(
                    f"append-only violation: committed {label} {rid} was "
                    f"mutated in place ({core} → {new_idx[rid]}) — refine via a "
                    f"new :R attr_updates / observation row, never by rewriting "
                    f"the original declaration"
                )
    return errors




def _check_strong_move_provenance(companion: CompanionBody) -> list[str]:
    """Both halves of a strong move's provenance tuple, in one walk: WHICH observation it
    rests on, and WHICH pre-committed claim that observation settled. One walk so a row
    missing both reports both together.

    The citation half catches how the ids go missing in practice: the head is
    `[<lead> <ids…> <severity> ⟂ <edges>]` with severity positional-last, so a row that omits
    severity has its ids read as the severity and parses as citing nothing —
    `h-002 null → ++ [l-001 p1,p2,p3 ⟂ e-002]` writes three predictions and binds none.
    """
    auth_by_edge: dict[str, str] = {}
    for e in _walkers.all_edges(companion):
        eid = e.get("id")
        kind = auth_kind_of(e)
        if isinstance(eid, str) and isinstance(kind, str):
            auth_by_edge[eid] = kind

    errors: list[str] = []
    for lid, res in _walkers.iter_resolutions(companion):
        # Through `_resolution_move`, the one owner of "what did this row move the hypothesis
        # to". Read raw here and closed there, this gate and rule #6's would answer the same
        # question two ways — the disagreement `_resolution_move`'s docstring says it prevents.
        after = _resolution_move(res)
        if after not in STRONG_WEIGHTS:
            continue
        hyp = res.get("hypothesis", "?")
        if not (res.get("matched_prediction_ids") or res.get("matched_refutation_ids")):
            errors.append(
                f"lead {lid}: resolution of {hyp} to "
                f"{after!r} cites no prediction or refutation id — a strong (++/--) "
                f"move must name the `p*`/`ap*`/`r*` it turned on, in the "
                f"`[<lead> <ids> <severity> ⟂ <edges>]` head"
            )
        supporting = [s for s in (res.get("supporting_edges") or []) if isinstance(s, str)]
        if not supporting:
            errors.append(
                f"lead {lid}: resolution of {hyp} to {after!r} cites no "
                f"supporting edge — a strong (++/--) resolution must cite at "
                f"least one {_STRONG_AUTH_KINDS_STR} edge"
            )
            continue
        if not any(auth_by_edge.get(s) in STRONG_AUTH_KINDS for s in supporting):
            seen = sorted({auth_by_edge.get(s, "<unknown>") for s in supporting})
            errors.append(
                f"lead {lid}: resolution of {hyp} to {after!r} cites "
                f"{supporting} but none carry strong observational authority "
                f"(found: {seen}); ++/-- needs {_STRONG_AUTH_KINDS_STR}"
            )
    return errors




def _resolution_move(res: Any) -> str:
    """The bucket a `:T resolutions` row moved its hypothesis TO, or `""` for no move.

    Closed on `vocab.WEIGHT_BUCKETS` rather than open on "anything that is not a null
    spelling". The `after` cell is an unvalidated `\\S+` — `_RESOLUTION_LINE_RE` reads whatever
    token sits there and no check compares it to the bucket list — so an allow-by-default test
    makes an off-vocabulary token the CHEAPEST row in the language: `h-001 null → confirmed`
    settles every prediction it cites (rule #34), skips the strong-provenance gate (which fires
    on `STRONG_WEIGHTS`) and skips the `++` coverage gate (which fires on `CONFIRMED_WEIGHT`),
    where the honest `null` is refused for the predictions it leaves open. One typo, or one
    deliberate misspelling, is strictly better for the author than telling the truth.

    Both readers of "did this row move the hypothesis" take this answer, so the write gate
    (rule #6) and the closure gate (rule #34) cannot disagree about which citations count —
    the disagreement `_check_prediction_completeness` describes and nothing enforced.
    """
    if not isinstance(res, dict):
        return ""
    after = (res.get("after") or "").strip()
    return after if after in vocab.WEIGHT_BUCKETS else ""


#: A prediction id the row's own `⟺` annotation puts under a NEGATION — `¬p2`, or its ASCII
#: fallback `~p2`. `parser._extract_iff_literals` files it in `matched_prediction_ids` on
#: purpose: that field means "this lead TESTED the id", and polarity is attribution-neutral
#: (`test_invlang_parser.test_resolution_negated_iff_literal_still_attributes`). Rule #6 asks
#: a different question — did the prediction COME IN — and the two answers are opposite on
#: exactly this token, so the rule subtracts what the row says did not materialize rather than
#: the parser changing what the field means for everyone.
_NEGATED_LITERAL_RE = re.compile(r"[¬~]\s*(ap\d+|p\d+|r\d+)\b")


def _contradicted_predictions(res: Any) -> set[str]:
    """The `p*`/`ap*` a resolution's own annotation says did NOT materialize."""
    reasoning = res.get("reasoning") if isinstance(res, dict) else None
    if not isinstance(reasoning, str):
        return set()
    return {
        tok for tok in _NEGATED_LITERAL_RE.findall(reasoning.replace("<=>", "⟺"))
        if not tok.startswith("r")
    }


def _refutation_scopes(hyp: HypothesisRecord) -> dict[str, set[str]]:
    """Per `r*` this hypothesis declares, the `p*`/`ap*` its `refutes` cell names."""
    return {
        shape["id"]: {
            pid for pid in shape.get("refutes_predictions") or []
            if isinstance(pid, str) and pid and not is_conclude_empty_marker(pid)
        }
        for shape in hyp.get("refutation_shape") or []
        if isinstance(shape, dict) and isinstance(shape.get("id"), str)
    }


def _settled_predictions(companion: CompanionBody) -> dict[str, set[str]]:
    """Per hypothesis, the `p*`/`ap*` ids some resolution cited on a row that MOVED it.

    A `null → null` row that cites `p1` recorded that the lead looked, not that the prediction
    settled. See `_resolution_move` for why the move test is closed on the bucket vocabulary.

    A cited `r*` counts for the predictions IT names. `_check_strong_move_provenance` already
    reads `matched_refutation_ids` as the same half of a strong move's provenance tuple that
    `matched_prediction_ids` is — a refutation shape that was tested and failed to materialize
    settles the predictions it would have overturned — and reading only the `p*` side here
    leaves a `++` whose evidence is a dead refutation with exactly one spelling that clears
    the gate: citing the prediction as MATCHED, which is a claim the run did not make.

    A NEGATED literal does not settle its prediction. `matched_prediction_ids` means "this
    lead tested the id" and files `¬p2` alongside `p1`, which is right for attribution and
    inverted for this rule — so `⟺ p1 ∧ ¬p2` would otherwise clear a `++` on the strength of
    an annotation saying one of the two predictions did not come in.
    """
    matched: dict[str, set[str]] = {}
    hyps = _walkers.all_hypotheses(companion)
    scopes_by_hyp: dict[str, dict[str, set[str]]] = {}
    for _lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        if not isinstance(hid, str) or not _resolution_move(res):
            continue
        hyp = hyps.get(hid)
        if hid not in scopes_by_hyp:
            scopes_by_hyp[hid] = _refutation_scopes(hyp) if hyp is not None else {}
        scopes = scopes_by_hyp[hid]
        row: set[str] = {
            p for p in res.get("matched_prediction_ids") or [] if isinstance(p, str) and p
        }
        for rid in res.get("matched_refutation_ids") or []:
            row |= scopes.get(rid, set()) if isinstance(rid, str) else set()
        # THIS row's negations against THIS row's citations, before the union. Subtracting from
        # the accumulated set instead would let a later row's `¬p1` un-settle a prediction an
        # earlier move settled — the union only grows, which is what keeps the rule repairable
        # on an append-only document.
        matched.setdefault(hid, set()).update(row - _contradicted_predictions(res))
    return matched


def _confirmed_and_standing(companion: CompanionBody) -> dict[str, str]:
    """Per hypothesis STANDING at `++`, the FIRST lead whose resolution moved it there.

    THE HANDOFF between rules #6 and #34, and one definition so the two cannot both stand down
    on the same hypothesis. #6 owns a hypothesis standing at `++` and refuses every uncited
    prediction on it; #34 owns everything else not refuted and offers a deferral. Split across
    two spellings — one on "stands at `++`" and one on "some row moved it to `++`" — a
    hypothesis confirmed and later withdrawn falls in the gap between them, and its uncited
    predictions are never asked about by either.

    STANDING, not EVER `++`, because the second is not a fact an append-only document can
    repair. A `++` is a claim about the predictions declared when it was written, and
    `:H h-NNN.preds` is appended: the moment a later block declares one more, a row committed
    to disk becomes a `++` that does not cover its own hypothesis, and no write can reach back
    into it. Reading the withdrawal makes the repair the message offers a real one — appending
    `h-NNN ++ → +` says the run is no longer claiming full coverage, which is what an author
    who has just declared an untested prediction means.

    STANDING IS COUNTED, NOT ORDERED, and the counting is the whole of why this is correct.
    Each row is read for whether it ENTERS `++` (`after` is `++`, `before` is not) or LEAVES it
    (`before` is `++`, `after` is not); the two are edge-triggered, so a `++ → ++` restatement
    is neither. On a chain whose rows join up — every `before` the previous row's `after` —
    entries and exits alternate, so the net is 1 exactly when the last row left the hypothesis
    at `++` and 0 otherwise. That is the same answer a last-move-wins fold gives, computed
    without needing an order the projection does not carry.

    NOT `_walkers.final_weights`, and not a SET of "was it ever withdrawn" either. The walker
    resolves last-move-wins by LEAD-DECLARATION order, not by append order — its own docstring
    says so — so on any document with more than one lead a withdrawal attributed to an
    earlier-declared lead loses to a `++` attributed to a later-declared one, and the write the
    refusal asks for is silently ignored. A withdrawal SET fixes that and breaks the other
    direction: `++ → +` followed by `+ → ++` re-asserts the claim, and a set that only records
    "withdrawn once" stands the rule down for the rest of the document — a two-row exemption
    from #6 on a hypothesis the document still grades `++`. Counting is the reading that
    survives both, because it is order-free AND it hears the re-confirmation.

    A NULL `after` leaves too. `++ → null` and `++ → ∅` are legal weight cells and both say the
    run stopped standing behind the grade, which is exactly what `++ → +` says with a number on
    it. What follows is rule #34's business at CONCLUDE, where a non-refuted hypothesis owes
    every declared prediction a citation or a deferral — so leaving `++` moves the question, it
    never discards it.

    BOTH CELLS READ CLOSED, on `vocab.WEIGHT_CELL_VALUES`. An off-vocabulary `after` — the
    `h-001 ++ → confirmd` typo `_resolution_move`'s docstring calls the cheapest row in the
    language — moves nothing, so it must not count as leaving `++` either; read open, one
    misspelling switched this rule off and left only `_check_vocab_weights` speaking. The
    ENTRY side goes through `_resolution_move`, which is this module's one owner of "what did
    this row move the hypothesis to".

    KNOWN AND NOT REFUSED: a `++` entered and left inside the block that wrote it (`null → ++`
    and `++ → +` in one `:T resolutions`) is a grade that never stood, and this counts it out
    like any other exit. #34 still asks for the predictions at CONCLUDE, so nothing escapes
    accounting; what does persist is a `++` row on disk that
    `runtime/review/projector.ablation_target` still counts as a strong move. Refusing it wants
    its own rule about rows that annihilate within a block, not a special case here.

    ALSO KNOWN: an exit whose `before` cell is a LIE. `_check_vocab_weights` is the only other
    reader of `before` and it checks the token, never whether it is the weight the previous row
    left — so `h-001 ++ → +` written when nothing ever graded h-001 `++` cancels the real `++`
    that follows it, and the count reads zero. Clamping the count at zero would close it and
    reopen the wedge: the clamp is order-sensitive, and a withdrawal attributed to an
    earlier-declared lead would be discarded again. The closable form is a CONTINUITY rule on
    `before` — a resolution starts where the last one on that hypothesis left off — which makes
    the cell trustworthy for every reader rather than for this count alone.

    ALSO OUTSIDE IT: a `:H` row DECLARED at `++` that no resolution ever moves. No row enters,
    so the count is zero and the hypothesis is invisible to #6 and handed to #34, which offers
    it a deferral for every prediction it declared — a deferral beside a standing `++`, which
    is the shape the partition exists to prevent. That is a gap, not a design; closing it wants
    the `:H` weight seeded as the starting position, which is a change to what "moved" means
    for every rule that reads a resolution row.
    """
    confirmed: dict[str, str] = {}
    net: dict[str, int] = {}
    for lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        if not isinstance(hid, str):
            continue
        entered = _resolution_move(res) == CONFIRMED_WEIGHT
        if entered:
            confirmed.setdefault(hid, lid)
        # RAW like `_resolution_move` and `_check_vocab_weights`, the other two readers of
        # these cells, so one quoting convention governs all three; and edge-triggered, so
        # `++ → ++` is a restatement rather than a move.
        before = (res.get("before") or "").strip()
        after = (res.get("after") or "").strip()
        if entered and before != CONFIRMED_WEIGHT:
            net[hid] = net.get(hid, 0) + 1
        elif (
            before == CONFIRMED_WEIGHT
            and after != CONFIRMED_WEIGHT
            and after in vocab.WEIGHT_CELL_VALUES
        ):
            net[hid] = net.get(hid, 0) - 1
    return {hid: lid for hid, lid in confirmed.items() if net.get(hid, 0) > 0}


def _check_prediction_completeness(companion: CompanionBody) -> list[str]:
    """A hypothesis graded `++` has settled every prediction it declared, not only the ones
    the confirming lead happened to look at.

    `_check_strong_move_provenance` stops one line short of this. It refuses a `++` that cites
    NOTHING and accepts one that cites `p1` out of five — so a hypothesis reaches "confirmed"
    on whichever fifth of its own pre-commitments the lead found convenient, and the four it
    never looked at are never heard from again. Partial coverage is what `+` is for.

    The union is taken over EVERY resolution on the hypothesis, not only the `++` row: a
    prediction an earlier `+` move already settled is settled.

    BOTH sides of the comparison grow, which is what the rule has to survive. The cited side
    growing is harmless — a write that clears the gate clears it for good. The DECLARED side
    growing is not: `:H h-NNN.preds` arrives by append, so declaring one more prediction on a
    hypothesis already carrying a committed `++` turns that row into a `++` that no longer
    covers its own hypothesis, and `:H` rows cannot be rewritten. `_confirmed_and_standing` is
    what makes that repairable — the rule asks whether the hypothesis STANDS at `++`, so
    appending `h-NNN ++ → +` withdraws the claim and clears the refusal. Reading "some row
    once said `++`" instead leaves a document with no legal next write.

    `ap*` counts toward the set. `_declared_prediction_ids` is this module's one answer to
    "what did the hypothesis declare", and its other two readers take the union; rule #34 — the
    late closure gate this is the early half of — enumerates `p*` and `ap*` alike. Reading only
    `p*` here would let an author take an observable out of the gate by declaring it under
    `.attr_preds`, which is a formatting choice and not an evidentiary one.

    NOT the closure gate. Rule #34 asks the same question of every weight at CONCLUDE and
    offers `conclude.deferred_predictions[]` as the answer to "that one could not be checked".
    This fires at write time on a hypothesis STANDING at `++` alone and offers nothing,
    because a standing `++` has no outstanding prediction to defer — the grade IS the claim
    that there is none. The two halves of that partition are one predicate
    (`_confirmed_and_standing`) so they cannot drift apart; the pre-v2.22 spelling was "any row
    ever wrote `++`", under which a confirmed-then-downgraded hypothesis belonged to #6 and now
    belongs to #34.
    """
    confirmed_at = _confirmed_and_standing(companion)
    if not confirmed_at:
        # Before the two document-wide folds below, which are the whole remaining cost of this
        # check. The predicate above is one `iter_resolutions` walk whatever the answer, so no
        # hypothesis standing at `++` — every in-flight document up to the confirming lead,
        # every run that never confirms, and every run that withdrew — stops here.
        return []
    hyps = _walkers.all_hypotheses(companion)
    matched = _settled_predictions(companion)

    errors: list[str] = []
    for hid, lid in confirmed_at.items():
        hyp = hyps.get(hid)
        if hyp is None:
            # `_check_hypothesis_refs` owns the undeclared-`h-*` defect. REACHED, not
            # defensive: `_confirmed_and_standing` walks resolution rows and keys on the `h-*`
            # each row names, with no test against the declared set — so `h-999 null → ++`
            # beside a `:H` block that never declares h-999 arrives here. A phantom declares no
            # predictions, so the coverage question is vacuous and its answer misleading.
            continue
        declared = _declared_prediction_ids(hyp)
        cited = matched.get(hid, set())
        unmet = declared - cited
        if unmet:
            errors.append(
                f"lead {lid}: resolution of {hid} to {CONFIRMED_WEIGHT!r} leaves "
                f"{_known_ids(unmet)} unmatched — {CONFIRMED_WEIGHT!r} says every prediction "
                f"the hypothesis declared came in, and the resolutions on {hid} cite "
                f"{_known_ids(cited & declared)} of {_known_ids(declared)}; cite the rest in "
                f"a resolution that moves {hid}, or withdraw the coverage claim by appending "
                f"`{hid}  {CONFIRMED_WEIGHT} → +   [{lid} <ids> <severity> ⟂ <edges>]` to a "
                f"`:T resolutions` block — head filled in from the row that graded it — to "
                f"grade it partial coverage"
            )
    return errors


_ATTR_PRED_TARGETS = vocab.ATTR_PRED_TARGETS
_ATTR_PRED_ID_RE = re.compile(r"ap\d+")


def _check_attribute_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:H h-NNN.attr_preds` rows, checked for the three things the parser does not check.

    `_hyp_sub_attr_pred_row` `_require`s `id`, `target` and `attribute` to be non-blank and
    stops there — whatever those cells SAY, the row is projected. So `a1|the parent|colour|`
    parses clean and lands an attribute prediction whose id is outside the namespace every
    citation site resolves against, whose target names no object the hypothesis has, and whose
    claim predicts nothing.

    The id shape is the load-bearing one. `matched_prediction_ids` and
    `refutation_shape[].refutes_predictions` both resolve against the union
    `_declared_prediction_ids` builds, so an id spelled `a1` can be cited by nobody.

    UNIQUENESS is not checked here, because it cannot be violated by the time this reads the
    record. Rule #33's "unique within the hypothesis" is already enforced one level up in two
    places: `_warn_repeated_ids` makes a repeat WITHIN one `.attr_preds` block a parse error,
    and `_extend_by_id` keys accumulation by id, so a repeat ACROSS blocks never reaches the
    projected list — and must not be refused either, since re-emitting a sub-block with one row
    added is the documented append shape (`test_invlang_hypothesis_accumulation`). A check here
    would be dead code that read as live.

    NOT checked: the one-observable-per-entry clause. "Compound `AND` / `OR` predicates split
    into separate entries" is a judgment about what a sentence asserts, not a property of the
    row — a lexical `" and "` test would refuse "the process and its parent share a cgroup",
    which is one observable. Rule #29 leaves the same clause to the author on
    `impact_predictions[]`, for the same reason.
    """
    errors: list[str] = []
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        for ap in hyp.get("attribute_predictions") or []:
            if not isinstance(ap, dict):
                continue
            apid = ap.get("id") or "?"
            if not _ATTR_PRED_ID_RE.fullmatch(apid):
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: an attribute prediction is numbered "
                    f"`ap<n>` — `matched_prediction_ids` and `.refuts` resolve ids in that "
                    f"namespace, so one outside it can be cited by nothing"
                )
            # Lowercased, because `_predicted_observables` lowercases the same cell into rule
            # #23's fork key. Compared raw, `Proposed_Parent` is the canonical target to one
            # rule and an illegal one to the other, in the same pass over the same row.
            target = ap.get("target")
            if str(target).strip().lower() not in _ATTR_PRED_TARGETS:
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: target {target!r} is not one of "
                    f"{', '.join(_ATTR_PRED_TARGETS)} — the cell says which of the "
                    f"hypothesis's OWN objects carries the attribute, not which vertex id"
                )
            # `_normalized_claim`, not a bare `.strip()`: `"."` / `"..."` / `"''"` are
            # non-blank cells that carry no observable, and `_predicted_observables` already
            # drops them from rule #23's fork signature on that reading. Testing the RAW cell
            # here leaves a pair of siblings whose only predictions normalize to nothing
            # passing BOTH rules — this one because the cell is non-blank, #23 because the
            # signature is empty.
            if not _normalized_claim(ap.get("claim")):
                attribute = ap.get("attribute") or "?"
                errors.append(
                    f"`:H {hid}.attr_preds` row {apid!r}: empty `claim` — the row pre-commits "
                    f"to what {attribute!r} will read as, and a blank cell commits to nothing "
                    f"while still counting as a prediction rules #6 and #34 require settled"
                )
    return errors


#: `:H h-NNN.preds`' id namespace, the sibling of `_ATTR_PRED_ID_RE`. Spelled here rather
#: than imported because `parser._REF_ID_RE` is the CITATION side's owner — it decides which
#: head tokens are ids at all — and this is the DECLARATION side; what the two must agree on
#: is the shape, which a shared regex would hide behind an alternation covering `r*` too.
_PRED_ID_RE = re.compile(r"p\d+")


def _check_prediction_id_namespace(companion: CompanionBody) -> list[str]:
    """A `:H h-NNN.preds` row is numbered `p<n>`, for the reason rule #33 gives for `ap<n>`.

    Rule #33 armed the id-shape check on `.attr_preds` and left its sibling block unchecked,
    and the closure gate turned that gap from harmless into a dead end. `_hyp_sub_pred_row`
    `_require`s `id` and never looks at what it says, so `x1|proposed_parent|"..."` declares a
    prediction; `parser._REF_ID_RE` then refuses to read `x1` as an id in a resolution head,
    so no citation can ever reach it — while rule #34 counts it as a declared commitment and
    refuses the close with "cite x1 in a `:T resolutions` head", a repair the grammar cannot
    express. The only exit is a deferral saying the prediction could not be settled, which is
    not what happened.
    """
    return [
        f"`:H {hid}.preds` row {pid!r}: a prediction is numbered `p<n>` — a resolution head "
        f"reads only `p*`/`ap*`/`r*` as ids, so one outside the namespace can be cited by "
        f"nothing and rule #34 then refuses the close for a prediction no row can settle"
        for hid, hyp in _walkers.all_hypotheses(companion).items()
        for pred in hyp.get("predictions") or []
        if isinstance(pred, dict)
        for pid in [pred.get("id") or "?"]
        if not _PRED_ID_RE.fullmatch(pid)
    ]


def _check_vocab(value: Any, allowed: Any, errmsg: str) -> list[str]:
    if isinstance(value, str) and value and value not in allowed:
        return [errmsg]
    return []


def _cell(record: Mapping[str, object], key: str) -> str:
    """One cell of a projected row as stripped, UNQUOTED text, read by a column name held in a
    variable.

    A TypedDict `.get()` with a non-literal key is typed `object`, so a loop over a tuple of
    required columns cannot call `.strip()` on the result. Every projected cell is a `str`;
    stating that once here beats a cast at each of the sites that walk a column list.

    `_unquote`d because the two sides of the impact axis disagree about quoting and the checks
    have to see through it. `_impact_pred_row` unquotes `dim` and `claim`; the `:R impact` row
    beside it goes through `_canonicalize_resolution_row`, which copies every cell verbatim —
    so an author who wraps cells uniformly registers `confidentiality` and grades
    `"confidentiality"`, and the enum tests and the `dim`-vs-predicate comparison refuse a row
    whose values are all correct. It is a BELT over the parser's braces elsewhere rather than
    in place of them: `_lead_header_record` already unquotes its cells on the way in, and
    unquoting an unquoted cell is identity — so a projector that grows a new lead column still
    meets a closed-set comparison the way the rule means it.

    Stripped on BOTH sides of the unquote. Stripping only before it leaves the padding INSIDE a
    quoted cell, so `" confidentiality "` reads as a padded `confidentiality` — and the two
    halves of every comparison below then disagree about a value they spell identically, on
    committed rows neither side can rewrite. `is_conclude_empty_marker` reads a cell the same
    way, and for the same reason.
    """
    value = record.get(key)
    return _unquote(value.strip()).strip() if isinstance(value, str) else ""


_LEAD_PRED_ID_RE = re.compile(r"lp\d+")

#: The two destinations an `advance_to` may name that are not a lead. `CONCLUDE` ends the run;
#: `HYPOTHESIZE` sends it back for a mechanism the plan did not have.
#:
#: `docs/dense-investigation-format.md` §`:L` wrote `PREDICT` for the second in one worked
#: example. That is the PHASE name for the block `:H hypothesize.hypotheses` lives in, not a
#: third sentinel — spec rule #18 names these two, so the doc's example was corrected rather
#: than the enum widened. Widening it instead would have meant accepting two spellings of one
#: destination and, with `REPORT` beside `CONCLUDE` by the same argument, four.
_ROUTE_SENTINELS: tuple[str, ...] = ("CONCLUDE", "HYPOTHESIZE")

#: `:L l-NNN.lead_preds`' three content cells, each with what a BLANK one costs. The `if`
#: column projects as `condition` (`if` cannot be a TypedDict key); everything the author sees
#: uses the column spelling.
_LEAD_PRED_CELLS: tuple[tuple[str, str, str], ...] = (
    (
        "condition", "if",
        "the row pre-commits to WHICH result sends the run down this branch, and a blank cell "
        "branches on nothing",
    ),
    (
        "read_as", "read_as",
        "the row says what that result MEANS, and a blank cell commits to no reading — which "
        "is the whole reason a route is registered before the data lands rather than chosen "
        "after it",
    ),
    (
        "advance_to", "advance_to",
        "the row names WHERE that reading routes, and a blank cell routes nowhere",
    ),
)


def _check_lead_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:L l-NNN.lead_preds` rows — a lead's pre-committed ROUTE, checked for the four things
    that make a route followable.

    A route is not a prediction about the world; it is a prediction about the RUN. Nothing
    grades an `lp*`, no resolution head can cite one, and `_check_tested_commitment_refs`
    leaves an `lp*` alone. What it buys is that the interpretation was fixed before the data
    arrived — so the cells that matter are the ones that make it a commitment: a condition, the
    reading that condition licenses, and where that reading goes next. `_lead_pred_row`
    `_require`s only `id` and never looks at what any cell says, so `lp1|||` parses clean and
    lands a route committing to nothing.

    `advance_to` is a hard reference: a lead NAME some `:L findings` row declares, or a
    sentinel. Resolved against every declared lead INCLUDING the declaring one. The spec says
    "elsewhere in the companion", and the only ordering the dense surface carries is
    `:L findings` DOCUMENT ORDER — under which "elsewhere" can only mean "not this row", so
    enforcing it would refuse a self-route and nothing else. That is left alone deliberately:
    two loops may declare same-named leads under different ids, and there is no cell that says
    which one a name means, so a self-route test can be wrong where accepting one costs
    nothing. A destination that does not exist YET is refused, the way `_check_lead_refs`
    refuses a forward `l-*`: PLAN writes its `:L findings` rows before the routes that point
    at them, so the ordering the rule demands is the ordering PLAN already has.

    UNIQUENESS is not checked, for the reason `_check_attribute_prediction_structure` records
    at length: `_warn_repeated_ids` makes a repeat within one block a parse error and
    `_extend_by_id` keeps the first record per id across blocks, so a duplicate never reaches
    this list — and refusing the cross-block case would refuse the documented append shape.

    NOT checked: the ROUTE-COMPLIANCE clause. "Followed by another lead" would read as the
    next `:L findings` row in DOCUMENT ORDER — the ordering `_check_screen_structure`'s
    intermediate arm used for "the final lead in a SCREEN sequence" until v2.22 STRUCK it, and
    that strike is now a second reason not to arm this clause: it has the same shape, refusing
    a committed row for which lead FOLLOWS it. The CHANNEL blocks it independently: spec
    rule #18 asks for a WARNING, and there is no honest way to emit one here. A warn
    diagnostic without a `Locus` is dropped by
    `runtime/tools._addressable` and does nothing at all; a warn diagnostic WITH one FLAGS that
    row and blocks every later write until `fix_row` rewrites it — and both candidate rows must
    not be rewritten. The follower's `:L findings` row is a committed lead declaration, which
    the warn family has never been able to reach (`_tool_fix_row`: "the warn family walks
    `:R attr_updates` blocks and nothing else"). The `lead_preds` row is worse: letting a run
    edit its own pre-registration to match where it ended up destroys the only thing
    pre-registration is for. See the enforcement ramp for the deferral.
    """
    # Through `_cell`, which unquotes AND strips — `_lead_header_record` does neither to the
    # `name` it lands, while `advance_to` is unquoted by `_lead_pred_row` and stripped below.
    # Without one reading for both halves, a document that quotes its cells uniformly (or
    # pads one) is refused with a message listing the destination among the names it says do
    # not match. The declaring row is a committed `:L findings` row the author cannot rewrite,
    # so the refusal has no repair.
    #
    # ONE `_leads` walk, bound: the destination set and the loop below ask the same list.
    leads = _leads(companion)
    names = {
        _cell(f, "name") for f in leads
        if isinstance(f.get("name"), str) and f["name"]
    } - {""}
    destinations = names | set(_ROUTE_SENTINELS)
    errors: list[str] = []
    for lead in leads:
        lid = lead.get("id", "?")
        for lp in lead.get("predictions") or []:
            if not isinstance(lp, dict):
                continue
            lpid = lp.get("id") or "?"
            where = f"`:L {lid}.lead_preds` row {lpid!r}"
            if not _LEAD_PRED_ID_RE.fullmatch(lpid):
                errors.append(
                    f"{where}: a lead-level route is numbered `lp<n>` — the namespace is what "
                    f"keeps a route out of the `p*`/`ap*`/`r*` a resolution head and "
                    f"`:L findings`' `tests` column resolve against, so a route spelled `p1` "
                    f"collides with the hypothesis prediction of that name at both sites"
                )
            for key, column, cost in _LEAD_PRED_CELLS:
                if not _cell(lp, key):
                    errors.append(f"{where}: empty `{column}` — {cost}")
            dest = _cell(lp, "advance_to")
            if dest and dest not in destinations:
                errors.append(
                    f"{where}: `advance_to` names {dest!r}, which is neither a lead NAME this "
                    f"document declares ({_known_ids(names)}) nor one of "
                    f"{', '.join(_ROUTE_SENTINELS)} — the cell carries the lead's `name`, not "
                    f"its `l-*` id, and a route nobody can follow is not a plan"
                )
    return errors


_IMPACT_PRED_ID_RE = re.compile(r"ip\d+")

#: `:L l-NNN.impact_preds`' six required cells, spelled as the CANONICAL key the projector
#: emits — the same choice `_IMPACT_RESOLUTION_REQUIRED` makes and for the same reason: `dim`
#: projects as `dimension` (`_impact_pred_row`), and naming the column alias sends a reader
#: looking up a name the spec does not use. Grouped rather than spelled out one branch apiece
#: because they fail the same way and for the same reason: the row is a PREDICATE, and a
#: predicate missing its axis or one of its outcomes cannot be graded on that outcome.
_IMPACT_PRED_CELLS: tuple[str, ...] = (
    "dimension", "claim", "on_match", "on_mismatch", "on_indeterminate", "escalation_on",
)


def _check_impact_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:L l-NNN.impact_preds` rows — the impact predicate a lead registers at PREDICT, checked
    for the cells that make it gradeable.

    Impact is the third axis: an authorized, uncompromised action can still be
    escalation-worthy if its consequence exceeds a threshold. What makes that checkable rather
    than a post-hoc judgment is that the threshold and BOTH of its outcomes are written down
    before the measurement lands — so a row with a `claim` and no `on_mismatch` has registered
    a number without registering what exceeding it means, and ANALYZE grades it whichever way
    the answer came out.

    `_impact_pred_row` `_require`s only `id`, so every cell below is present-and-empty rather
    than missing: `ip1|confidentiality|||||` parses clean today.

    `dimension` is closed (`vocab.IMPACT_DIMENSION`) because `:R impact` rows must MATCH it —
    `_check_impact_resolution_refs` compares the two, and a free-text dimension makes that
    comparison a string coincidence.

    NOT checked: the one-observable-per-entry clause. "Compound `AND` / `OR` / semicolon
    predicates must be split across entries" is a judgment about what a sentence asserts, not a
    property of the row, and a lexical test would refuse "session bytes and connection count
    stay within baseline" written about one measurement. Rule #33 leaves the identical clause
    to the author on `attribute_predictions[]`, and
    `_check_attribute_prediction_structure` records why.
    """
    errors: list[str] = []
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for ip in lead.get("impact_predictions") or []:
            if not isinstance(ip, dict):
                continue
            ipid = ip.get("id") or "?"
            where = f"`:L {lid}.impact_preds` row {ipid!r}"
            if not _IMPACT_PRED_ID_RE.fullmatch(ipid):
                errors.append(
                    f"{where}: an impact prediction is numbered `ip<n>` — a `:R impact` row's "
                    f"`pred_ref` resolves in that namespace, both bare and as the "
                    f"cross-lead `{lid}.ip<n>`, so an id outside it can be graded by nothing"
                )
            # Through `_cell`, like every neighbouring read: `_impact_pred_row` unquotes `dim`
            # but does not re-strip it, so a uniformly quoted `" confidentiality "` reaches
            # here with its padding and a raw membership test refuses the row for naming an
            # axis it names correctly. Reading it twice — raw for the enum, stripped for the
            # blank test — also drew TWO refusals for one whitespace-only cell.
            dimension = _cell(ip, "dimension")
            errors += _check_vocab(
                dimension, vocab.IMPACT_DIMENSION,
                f"{where}: dimension {dimension!r} is not one of "
                f"{', '.join(vocab.IMPACT_DIMENSION)} — the cell says which axis the "
                f"consequence is measured on, and `:R impact` grades against it",
            )
            # ONE error per ROW, not per column, for the reason
            # `_check_impact_resolution_refs` gives on the grading side: an under-filled row
            # is one defect, and seven near-identical refusals for one row bury every other
            # check. `dim` rides with them — the columns differ only in what each is for, and
            # the sentence below says that once.
            blank = [c for c in _IMPACT_PRED_CELLS if not _cell(ip, c)]
            if blank:
                errors.append(
                    f"{where}: empty {', '.join(f'`{c}`' for c in blank)} — an impact "
                    f"predicate registers its axis, its threshold AND every outcome before "
                    f"the measurement lands, so all of {', '.join(_IMPACT_PRED_CELLS)} are "
                    f"required; a blank cell lets ANALYZE decide that outcome after seeing "
                    f"the answer"
                )
    return errors


#: The `:R impact` cells rule #30 requires, spelled as the CANONICAL key the projector emits
#: — which is also the name the rule uses. `_RESOLUTION_KEY_CANONICAL` renames four of them
#: on the way in (`pred_ref` → `prediction_ref`, `dim` → `dimension`, `grounding` →
#: `grounding_kind`, `authority` → `authority_for_question`), and the refusal names the
#: FIELD rather than the column: the header spelling is the author's choice, so a message
#: naming the alias sends a reader looking up a name the spec does not use.
_IMPACT_RESOLUTION_REQUIRED: tuple[str, ...] = (
    "prediction_ref",
    "dimension",
    "verdict",
    "grounding_kind",
    "authority_for_question",
    "as_of",
    "reasoning",
)


def _qualify(lid: str, ref: str) -> str:
    """A `pred_ref` under its CROSS-LEAD identity: a bare `ip<n>` is scoped to the lead the row
    landed on, a qualified `l-NNN.ip<n>` already names its own.

    ONE owner, because rules #30 and #31 both resolve this cell and a document in which they
    resolve it differently is reported as graded by one and abandoned by the other — with a
    deferral row for a predicate the run did grade as the only exit.
    """
    return ref if "." in ref else f"{lid}.{ref}"


def _declared_impact_predictions(
    companion: CompanionBody,
) -> dict[str, ImpactPrediction]:
    """Every `ip*` in the document under its CROSS-LEAD identity `l-{id}.ip{n}` — the one
    spelling both reference forms resolve to."""
    out: dict[str, ImpactPrediction] = {}
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for ip in lead.get("impact_predictions") or []:
            if isinstance(ip, dict) and isinstance(ip.get("id"), str) and ip["id"]:
                out.setdefault(f"{lid}.{ip['id']}", ip)
    return out


def _check_impact_resolution_refs(companion: CompanionBody) -> list[str]:
    """`:R impact` rows — what each grades, how it graded it, and on what authority.

    The impact analog of `_check_prediction_refs`, and it exists for the same reason: nothing
    joins a `:R impact` row back to the `:L l-NNN.impact_preds` row it claims to grade. The
    projector canonicalizes `pred_ref` into a string and stops, so a typo, a forward reference
    and ANOTHER lead's `ip1` all land identically — and a verdict attached to no predicate is a
    consequence claim with no pre-registered threshold behind it, which is the one thing the
    impact axis exists to prevent.

    `dimension` is compared against the predicate's, not merely checked for membership. A row
    that grades an availability predicate under `confidentiality` has answered a question
    nobody asked, and the roll-up into `conclude.impact_verdict` cannot tell that from a real
    answer.

    `past-case` is refused by name rather than left to the enum's silence, because the omission
    is a judgment and not an oversight: impact is per-instance reasoning about what THIS event
    did, and a past case establishes what a CATEGORY of event was permitted to do. Rule #11
    excludes it from consultations for the neighbouring reason.

    NOT checked: whether the observation supports the verdict. `observed` is free text — "180GB
    (3σ above 60GB μ)" — and reading it against `claim` is the judgment ANALYZE is for. This
    checks that the row is ANSWERABLE, not that the answer is right.
    """
    declared = _declared_impact_predictions(companion)
    errors: list[str] = []
    #: Every verdict each `ip*` was graded to, to catch the predicate graded TWICE with
    #: different answers. `_check_impact_closure` asks only whether SOME row names the ref, so
    #: without this a run can register one threshold, grade it `exceeds` AND `within`, and roll
    #: up to whichever it prefers — the after-the-fact choice the whole pre-registration axis
    #: exists to prevent. The authz axis already refuses the analogous disagreement
    #: (`_authz_contract_error`: `bad = [v for v in rows if v != "authorized"]`).
    verdicts_by_ref: dict[str, set[str]] = {}
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for row in (lead.get("outcome") or {}).get("impact_resolutions") or []:
            if not isinstance(row, dict):
                continue
            # Every cell read through `_cell`, which unquotes: `_impact_pred_row` unquotes the
            # cells on the DECLARING side and `_canonicalize_resolution_row` unquotes nothing,
            # so reading these raw refuses a uniformly quoted row three times over for values
            # it spells correctly.
            raw_ref = _cell(row, "prediction_ref")
            where = f"lead {lid}: `:R impact` row for {raw_ref or '<no prediction_ref>'}"
            # ONE error per ROW, not per column: an under-filled row is one defect, and seven
            # near-identical refusals for one row would bury the six other checks below.
            blank = [key for key in _IMPACT_RESOLUTION_REQUIRED if not _cell(row, key)]
            if blank:
                errors.append(
                    f"{where}: empty {', '.join(f'`{c}`' for c in blank)} — an impact "
                    f"resolution carries a consequence verdict AND the provenance that makes "
                    f"it checkable, so all of "
                    f"{', '.join(_IMPACT_RESOLUTION_REQUIRED)} are required; a "
                    f"blank cell records the verdict without what it rests on"
                )
            verdict = _cell(row, "verdict")
            errors += _check_vocab(
                verdict, vocab.IMPACT_VERDICT,
                f"{where}: verdict {verdict!r} is not one of "
                f"{', '.join(vocab.IMPACT_VERDICT)} — the cell says whether the measurement "
                f"landed inside the registered threshold, not what was measured",
            )
            grounding = _cell(row, "grounding_kind")
            if grounding == "past-case":
                errors.append(
                    f"{where}: `grounding past-case` — impact is per-instance reasoning about "
                    f"what THIS event did, and a past case establishes only what a CATEGORY "
                    f"of event was permitted to do. Re-send this row grounded on "
                    f"{', '.join(vocab.IMPACT_GROUNDING)}. Deferring the predicate in "
                    f"`:T conclude.deferred_impact` does NOT clear this: the refusal is on the "
                    f"`:R impact` row, and append-only leaves it on disk"
                )
            else:
                errors += _check_vocab(
                    grounding, vocab.IMPACT_GROUNDING,
                    f"{where}: grounding {grounding!r} is not one of "
                    f"{', '.join(vocab.IMPACT_GROUNDING)}",
                )
            if not raw_ref:
                continue
            # Bare `ip{n}` is scoped to the lead the row landed on — the one the `resolved_by`
            # column named, which is the only lead that could have measured it.
            ref = _qualify(lid, raw_ref)
            pred = declared.get(ref)
            if pred is None:
                errors.append(
                    f"{where}: `prediction_ref` resolves to {ref!r}, which no "
                    f"`:L l-NNN.impact_preds` row declares (declared: "
                    f"{_known_ids(set(declared))}) — a bare `ip<n>` resolves within {lid} and "
                    f"a qualified `l-NNN.ip<n>` across leads; register the predicate before "
                    f"grading it"
                )
                continue
            if verdict:
                verdicts_by_ref.setdefault(ref, set()).add(verdict)
            # BOTH sides through `_cell`. `_impact_pred_row` unquotes `dim` but does not
            # re-strip it, so a declaring cell written `" confidentiality "` keeps its
            # padding — and a correct `:R impact` row grading `confidentiality` is then
            # refused for an axis it names correctly, on a committed `:L l-NNN.impact_preds`
            # row the author cannot rewrite. The blank test one screen up already reads the
            # predicate this way (`_check_impact_prediction_structure`); this is the same
            # read.
            dim, pred_dim = _cell(row, "dimension"), _cell(pred, "dimension")
            if dim and pred_dim and dim != pred_dim:
                errors.append(
                    f"{where}: `dimension {dim}` but {ref} was registered on {pred_dim!r} — a "
                    f"resolution grades the predicate it names, so the two axes have to be "
                    f"the same one; fix the column, or point `pred_ref` at the predicate this "
                    f"row actually measured"
                )
    errors += [
        f"impact prediction {ref}: graded {', '.join(sorted(seen))} by different "
        f"`:R impact` rows — a predicate registers ONE threshold and the measurement lands "
        f"inside it or outside it, so two verdicts on one `ip<n>` let the close pick which of "
        f"its own answers to be measured against. Keep the grading that measured the "
        f"registered claim, or register a second predicate for the second measurement"
        for ref, seen in sorted(verdicts_by_ref.items())
        if len(seen) > 1
    ]
    return errors


def _check_vocab_vertices(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for v in _walkers.all_vertices(companion):
        t = v.get("type")
        errors += _check_vocab(
            t, vocab.TYPES,
            f"vertex {v.get('id', '?')}: type {t!r} is not a known vertex "
            f"type (`enum types`)",
        )
    return errors


def _check_vocab_edges(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for e in _walkers.all_edges(companion):
        rel = e.get("relation")
        errors += _check_vocab(
            rel, vocab.RELATIONS,
            f"edge {e.get('id', '?')}: rel {rel!r} is not a known relation "
            f"(`enum relations`)",
        )
        kind = auth_kind_of(e)
        errors += _check_vocab(
            kind, vocab.AUTH_KINDS,
            f"edge {e.get('id', '?')}: auth_kind {kind!r} is not a known "
            f"observational authority (`enum auth-kinds`)",
        )
    return errors


def _check_vocab_hypotheses(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for h in _walkers.all_hypotheses(companion).values():
        pv = (h.get("proposed_edge") or {}).get("parent_vertex") or {}
        pt = pv.get("type")
        errors += _check_vocab(
            pt, vocab.TYPES,
            f"hypothesis {h.get('id', '?')}: parent_type {pt!r} is not a "
            f"known vertex type (`enum types`)",
        )
        rel = (h.get("proposed_edge") or {}).get("relation")
        errors += _check_vocab(
            rel, vocab.RELATIONS,
            f"hypothesis {h.get('id', '?')}: rel {rel!r} is not a known "
            f"relation (`enum relations`)",
        )
    return errors


def _check_vocab_weights(companion: CompanionBody) -> list[str]:
    """The two cells that carry a weight, against the bucket list plus `null`.

    The one enum in the language that had no arm here, and the gap was not inert: every
    weight-keyed gate reads one of these two cells and every one of them is a membership test,
    so an off-vocabulary token skips all of them at once. `h-001 null → confirmed` cleared the
    strong-move provenance gate (which fires on `STRONG_WEIGHTS`), the `++` coverage gate
    (which fires on `CONFIRMED_WEIGHT`) and the refutation-citation gate, where the honest
    `++` is refused for the predictions it leaves open — while `_walkers.final_weights`
    propagated the token verbatim and reported the hypothesis live. One typo was strictly
    better for the author than telling the truth.

    `:H`'s cell is checked as well as the resolution's: `_hypothesis_record` maps `null` to
    `None` and stores anything else verbatim, so a weight declared at birth is the same
    unvalidated token by another route.
    """
    errors: list[str] = []
    for hid, h in _walkers.all_hypotheses(companion).items():
        errors += _check_vocab(
            h.get("weight"), vocab.WEIGHT_CELL_VALUES,
            f"hypothesis {hid}: weight {h.get('weight')!r} is not a weight — a `:H` row's "
            f"cell is one of {', '.join(vocab.WEIGHT_CELL_VALUES)}",
        )
    for lid, res in _walkers.iter_resolutions(companion):
        for cell in ("before", "after"):
            errors += _check_vocab(
                res.get(cell), vocab.WEIGHT_CELL_VALUES,
                f"lead {lid}: resolution of {res.get('hypothesis', '?')} has "
                f"{cell} {res.get(cell)!r}, which is not a weight — the cells either side of "
                f"the arrow are one of {', '.join(vocab.WEIGHT_CELL_VALUES)}; a token outside "
                f"the list moves nothing and skips every gate that reads the grade",
            )
    return errors


def _check_vocab_anchor_kinds(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for h in _walkers.all_hypotheses(companion).values():
        for c in h.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            ak = c.get("anchor_kind")
            errors += _check_vocab(
                ak, vocab.ANCHOR_KINDS,
                f"hypothesis {h.get('id', '?')} contract "
                f"{c.get('id', '?')}: anchor_kind {ak!r} is not known "
                f"(`enum anchor-kinds`)",
            )
    for row in _walkers.iter_authz_resolutions(companion):
        row_ak = row.get("anchor_kind")
        errors += _check_vocab(
            row_ak, vocab.ANCHOR_KINDS,
            f"authz resolution for contract {row.get('fulfills_contract', '?')}: "
            f"anchor_kind {row_ak!r} is not known (`enum anchor-kinds`)",
        )
    return errors


def _swap_cell(cells: list[str], at: int, replacement: str) -> str:
    """One cell replaced, every other left exactly where the author put it."""
    swapped = list(cells)
    swapped[at] = replacement
    return "|".join(swapped)


#: The refinement keys `:R attr_updates` accepts. `class` sharpens the classification,
#: `attrs.<name>` an attribute, and `ident` the vertex's effective IDENTIFIER. `ident` lands in
#: a distinct top-level `identifier` slot, never in `attributes`: `_check_benign_open_slots`
#: refuses a benign close on any `??`-valued ATTRIBUTE, so routing it there would make
#: `ident=??` block a benign disposition.
#:
#: These three ARE the slot vocabulary `iter_vertex_cells` reports, and the one this module
#: uses to decide a refinement key is legal — one literal for both, so the spelling that CLOSES
#: a slot and the spelling that NAMES one in a `VertexCell` cannot drift apart INSIDE this file.
#:
#: They stop there. A lesson's `slot:` selector is free-form YAML compared by `!=`
#: (`lessons_frontier._node_match_score`), so nothing holds an AUTHOR to these spellings; the
#: prompt says so and `learning/author/lessons/prompt.md` warns that a typo matches nothing
#: forever. A corpus lint over `vocab` is what would close that, not another constant —
#: `frontier.py` deliberately does not re-export these (see its `__all__` note).
SLOT_CLASS = "class"
IDENT_REFINEMENT_KEY = "ident"
SLOT_IDENT = IDENT_REFINEMENT_KEY
ATTR_PREFIX = "attrs."


def _is_legal_refinement_key(key: str) -> bool:
    return key in (SLOT_CLASS, SLOT_IDENT) or key.startswith(ATTR_PREFIX)


def _unquoted(cell: str) -> str:
    """The cell with ONE wrapping pair of double quotes removed, or the cell unchanged.

    NOT a decoding step, and this file does not use it as one. In invlang a quote PROTECTS a
    delimiter and is KEPT: `_split_quoted` hands back `"v-001|v-002"` with its quotes, and the
    `:V` row declaring that vertex carries them too, so both sides of a target comparison see
    the same bytes. A key cell is read the same way as every other cell — which is why
    `"class"` is not the key `class`, and why `_is_legal_refinement_key` is not taught to
    accept it (#963). Making the key cell the one place quotes fall away would put this check
    at odds with every other reader of the format, including the target match one column left.

    What it is for is the REPAIR. An author who wrote `"class"` meant `class`, and the useful
    suggestion is the key they meant — not `attrs."class"`, which is what prefixing text the
    check has already refused produces: a legal-SHAPED key naming an attribute whose name
    contains quote characters, which nobody wants and which `_candidate_refusal` then rejects
    anyway, withholding the whole suggestion and leaving the author with no repair at all.
    """
    if len(cell) >= 2 and cell.startswith('"') and cell.endswith('"'):
        return cell[1:-1]
    return cell


def _candidate_refusal(
    block: Block, cols: list[str], parsed: list[str], at: int, candidate: str
) -> str | None:
    """Why this rebuilt row cannot be OFFERED, or `None` when it can.

    FOUR questions, because "does the parser accept it" answers only one of them and the rest
    are how a rebuild corrupts a row, or earns a refusal, while re-splitting to a legal width:

      * could it stand inside the fence at all — a cell carrying ``` closes the block early,
        and the row reader, handed one row, has no notion of the fence;
      * does it read back at all — `_row_cells`, the parser's own reader, which also catches
        a `"` the splice opened inside a token (`attrs."class"`);
      * does it split to the DECLARED width — asked separately because `_row_cells` PADS a row
        between `required_cells` and the declared width and returns normally, while
        `runtime.tools._new_row_shape_reason` (the guard the model's `fix_row` actually meets)
        demands equality. Under a header with a trailing `?` column, the padded rejoin
        `…|c:\\path\\` + `|` turns the author's closing backslash into an escaped delimiter,
        the candidate comes back one cell SHORT, `_row_cells` pads it back and says nothing —
        and the paste earns exactly the second refusal F-47 exists to prevent;
      * do the author's OTHER cells survive — the one failure worse than a refusal. `key` is
        spliced in from the PARSED record, where `\\|` has already been unescaped, so a key
        cell carrying an escaped pipe rebuilds as `attrs.a|a\\` and the joining `|` pairs with
        the trailing backslash: `l-001|v-001|a\\|a\\ |hello` re-splits to four cells, passes
        both width gates, pastes with ZERO diagnostics, and leaves the document claiming key
        `attrs.a` / value `a|hello` where the author wrote value `hello`.

    Compared cell-by-cell against the row as the PARSER reads it, not against the raw spans:
    a candidate is allowed to normalise padding the tokenizer would have stripped anyway, and
    is not allowed to move a byte across a boundary.
    """
    if "```" in candidate:
        # An invlang FACT, not a runtime one: rows live inside a ```invlang fence, so a row
        # carrying the delimiter would close its own block early. `_row_cells` has no notion
        # of the fence — it is handed one row — so the offer gate has to say it, or it hands
        # the model a `use:` line `fix_row` refuses for a reason the row reader never checks.
        return (
            "it carries a fence delimiter (```), which would close the block early — the row "
            "cannot be repaired in place at all"
        )
    try:
        _row_cells(block, candidate, len(cols))
    except RowError as e:
        return str(e)
    back = _split_cells(candidate)
    if len(back) != len(cols):
        return (
            f"it splits to {len(back)} cells but the block declares {len(cols)} — "
            f"the rejoined row lost a delimiter"
        )
    moved = [cols[i] for i in range(len(cols)) if i != at and back[i] != parsed[i]]
    if moved:
        return (
            f"it would rewrite the {', '.join(repr(c) for c in moved)} cell(s), which the "
            f"repair must leave exactly as written"
        )
    return None


def _illegal_key_diagnostic(
    block: Block, row: str, cols: list[str], rec: dict[str, str], key: str,
) -> Diagnostic:
    """The warn-severity diagnostic for one `:R attr_updates` row whose `key` cell names
    neither `class`, `ident` nor an `attrs.<name>`. Split out of `_check_attr_update_keys`
    only to keep that loop under the mccabe cap; see its docstring for the raw-text rebuild
    this builds `fix` from.
    """
    # The LAST `key` column, because that is the cell `key` came from: `_row_dict` zips the
    # header onto the cells and a repeated column name lets the later cell win, so a header
    # spelling `key` twice makes `cols.index` point at a cell the record never read. The
    # suggestion then rewrites an innocent cell and leaves the offending one standing — a
    # repair that re-earns its own warning, forever, since the row still parses.
    at = len(cols) - 1 - cols[::-1].index("key")
    raw_cells = _split_cells_raw(row)
    if len(raw_cells) < len(cols):
        # A legal SHORT row under a header marking its trailing column(s) optional — pad out
        # to the declared width, same as `_row_cells` pads the parsed record, so the pasted
        # candidate is full-width rather than re-opening the same gap.
        raw_cells = raw_cells + [""] * (len(cols) - len(raw_cells))
    # The repair is built from the key with its wrapping quotes removed, never from the raw
    # cell: `attrs.{key}` over a quoted cell splices text the check has ALREADY judged
    # malformed behind a legal prefix (#963). When the unquoted text is itself a legal key the
    # author simply quoted, that key IS the repair and there is no second route to offer —
    # `class` and `attrs.class` are not two readings of `"class"`, and offering the pair would
    # invite the author to pick the wrong one.
    basis = _unquoted(key)
    quoted_legal = basis != key and _is_legal_refinement_key(basis)
    candidates: tuple[str, ...]
    if quoted_legal:
        candidates = (_swap_cell(raw_cells, at, basis),)
    else:
        # The `attrs.` route needs a NAME to prefix. With the quotes stripped off `""` there
        # is none, and `attrs.` is legal-SHAPED — `_is_legal_refinement_key` accepts anything
        # starting with the prefix — so offering it would land an attribute whose name is the
        # empty string. That is the same "repair worse than the row" #963 is about, reachable
        # here only because the unquoting made the prefix splice succeed where `attrs.""`
        # used to be caught by the offer guard. The `class` route is unaffected and is offered
        # alone; nothing is silently dropped, because for an empty name there is no second
        # route to drop.
        routes = [_swap_cell(raw_cells, at, "class")]
        if basis:
            routes.append(_swap_cell(raw_cells, at, f"attrs.{basis}"))
        candidates = tuple(routes)
    # ALL-OR-NOTHING (F-M half one): put each candidate through `_candidate_refusal` — which
    # wraps the parser's OWN row reader rather than substituting it, since that reader RAISES
    # where this check returns a value — and withhold the whole suggestion the moment either
    # candidate would not come back as the author's row with one cell changed. One
    # complete-looking suggestion with the other route silently missing would be worse than
    # none.
    #
    # The refusal is CARRIED, not paraphrased: the three grounds it distinguishes are three
    # different things for the author to fix, and naming only the width sends someone counting
    # pipes on a row whose pipes are already right.
    #
    # `parsed` cannot raise here, and is not wrapped for it: `_check_attr_update_keys` reached
    # this row only by `_row_dict(block, row)` returning, and that is this same call — the
    # `default_cols` arm it resolves collapses to `block.columns or []`, which is `cols`.
    parsed = _row_cells(block, row, len(cols))
    refusal: str | None = None
    rejected = ""
    for candidate in candidates:
        refusal = _candidate_refusal(block, cols, parsed, at, candidate)
        if refusal is not None:
            rejected = candidate
            break
    # `or`, not `.get`'s default: `rec` is keyed on the block's DECLARED columns, so a header
    # that names `target` puts the key there whatever the cell holds — the default fires only
    # for a header that omits the column entirely, and a blank cell renders "on : key ...",
    # naming no object at all. Blank and absent are the same thing to a reader here.
    message = (
        f":R attr_updates on {rec.get('target') or '?'}: key {key!r} is not a "
        f"valid refinement key — use `class` (class refinement), `ident` "
        f"(identifier refinement) or `attrs.<name>` (attribute); a bare key "
        f"is dropped silently"
    )
    if quoted_legal:
        # Says WHY a word the author knows is legal was refused. Without it the message reads
        # as the validator not recognising `class`, and the author's next move is to argue
        # with it rather than to drop two characters.
        message += (
            f" — a quote is part of the cell in this format, never stripped from it, so "
            f"{key} names a different key than {basis}"
        )
    if refusal is not None:
        message += (
            # QUOTES THE REBUILT ROW the refusal is ABOUT. The carried reason is the row
            # reader's verdict on a MACHINE-BUILT candidate, and it sits two lines above
            # `render_diagnostic`'s `row: <the author's line>` — so unattributed it reads as a
            # verdict on the author's row and prescribes an edit to bytes they never wrote
            # ("row has 5 cells but 4 expected", printed beside a 4-cell row).
            #
            # NO VERB INSTRUCTION HERE. `runtime.tools` already appends "Repair each flagged
            # row with `fix_row(old_row, new_row)` — or delete it with `fix_row(old_row, "")`"
            # under every rendered warn diagnostic, and it owns that vocabulary; a second copy
            # is a third place to keep in step.
            f" — the suggested repair is withheld: rebuilding this row as {rejected!r} "
            f"would not read back as a row of this block ({refusal})"
        )
    return Diagnostic(
        message=message,
        locus=Locus(block=":R attr_updates", row_text=row),
        fix=() if refusal is not None else candidates,
        # THE one warn-severity family. The row is INERT — it changes no effective vertex
        # state — so the block it rides in is worth keeping, and the model repairs the row
        # with `fix_row` instead of re-emitting the whole block. Every other family stays a
        # refusal: nothing is written and the model re-sends.
        severity="warning",
    )


def _check_attr_update_keys(proposed_text: str) -> list[Diagnostic]:
    """`:R attr_updates` refinement rows — the KEY, and the value that key promises to carry
    — checked over the ROWS rather than the folded records.

    Reads blocks straight from the document because this is the one check that quotes a row
    back and offers a corrected one. The fold keeps `{key: value}` per target and drops the
    header, so rebuilding a row from it means assuming the conventional
    `resolved_by|target|key|value` order — a convention `_row_dict` does not enforce, since it
    zips whatever header the block declares. Against `[…|value|key]` that yields a correction
    with its columns transposed: a "fix" that earns a second refusal.

    Here the `key` CELL is replaced in place and every other cell stays where the author put
    it. A block whose header names no `key` column has no cell to substitute and no row this
    can honestly point at, so it yields nothing — the row is not a refinement at all.

    The VALUE cell is the second family, and a REFUSAL rather than a warning. A present-but-
    blank value is not inert: `_apply_attr_updates` would assign it, and since neither
    `has_open_slot("")` nor `is_unresolved("")` reads `""` as open, the empty cell reads as a
    RESOLUTION — `l-001|v-001|class|` makes a benign-blocking error vanish. The truncated
    3-cell row is already refused by the cell-count rule, so the hole is exactly the cell that
    is present and says nothing. No `fix` is offered: the missing value is the one thing this
    check cannot supply."""
    out: list[Diagnostic] = []
    for block in iter_blocks(proposed_text):
        cols = block.columns or []
        if block.name != "attr_updates":
            continue
        for row in block.rows:
            try:
                rec = _row_dict(block, row)
            except RowError:
                continue  # already a parse warning; not this check's business
            key = rec.get("key")
            if not key:
                continue
            if _is_legal_refinement_key(key):
                value = rec.get("value")
                if "value" in cols and not (value or "").strip():
                    out.append(Diagnostic(
                        message=(
                            f":R attr_updates on {rec.get('target') or '?'}: the `value` cell "
                            f"for key {key!r} is empty — a refinement settles a slot by "
                            f"naming the value the lead obtained, and an empty cell settles "
                            f"nothing. Write that value, or leave the `??` standing and "
                            f"escalate"
                        ),
                        locus=Locus(block=":R attr_updates", row_text=row),
                    ))
                continue
            # `rec`'s keys are the block's DECLARED columns, so a non-empty `key` is proof
            # the header names a `key` column to substitute into. Built from the row's RAW
            # text, not from `rec` — see `_illegal_key_diagnostic`.
            out.append(_illegal_key_diagnostic(block, row, cols, rec, key))
    return out


def _check_attr_update_targets(companion: CompanionBody) -> list[str]:
    """A `:R attr_updates` row must name a graph object the document DECLARES.

    Otherwise an undeclared target lands with zero diagnostics and `effective_vertex_state`
    fabricates the object out of the refinement alone — and since `ident` is writable, the
    fabricated vertex's identifier carries a value that flows from alert content.

    EDGES count as declared targets, not only vertices. `:R attr_updates` is the surface for
    recording facts learned about ANY existing graph object, and refining an edge is ordinary
    practice (`l-001|e-001|attrs.auth_method|password` appears in the checked-in goldens)."""
    declared = {
        r.get("id")
        for records in (_walkers.all_vertices(companion), _walkers.all_edges(companion))
        for r in records
        if isinstance(r.get("id"), str)
    }
    errors: list[str] = []
    for upd in _walkers.iter_attr_updates(companion):
        tgt = upd.get("target")
        if not isinstance(tgt, str) or not tgt or tgt in declared:
            continue
        errors.append(
            f":R attr_updates refines {tgt!r}, which no `:V` or `:E` block declares — declare "
            f"it before refining it (declared: {sorted(d for d in declared if d)})"
        )
    return errors


def _check_closed_vocab(companion: CompanionBody, proposed_text: str) -> list[Diagnostic]:
    out: list[Diagnostic] = []
    out += _plain(_check_vocab_vertices(companion))
    out += _plain(_check_vocab_edges(companion))
    out += _plain(_check_vocab_hypotheses(companion))
    out += _plain(_check_conclude_vocab(companion))
    out += _plain(_check_vocab_anchor_kinds(companion))
    out += _plain(_check_vocab_weights(companion))
    out += _check_attr_update_keys(proposed_text)
    return out




#: The whole-cell open marker, named once so the two predicates below and every reader of
#: theirs look for the same token rather than for a literal each spells for itself.
OPEN_MARKER = "??"


def is_unresolved(value: Any) -> bool:
    """Does this cell say "not settled yet" — the WHOLE of it, not a substring.

    The two markers SKILL.md §Open questions defines, and the three-state progression it
    documents (`??` → `{a, b, c}` → concrete) is why both count: a candidate set is an upgrade
    from `??`, not a resolution of it. No comma is required — `{internal}` is a one-member set
    that still has not picked.

    Anchored to the whole value on purpose: a "contains braces" test would refuse a benign
    close over a legitimate `attrs.cmdline` that happens to carry `{...}`.

    An OPENING brace with no close counts as open — otherwise a single dropped `}` reads as
    CONCRETE and closes benign over the class it was still enumerating (`role={internal, dmz`
    satisfies neither of the other two tests).

    That `count("{") > count("}")` test is load-bearing ON TOP of the whole-value anchor, not a
    replacement for it. The anchor alone reads any value that merely BEGINS with a brace as
    open, closed or not — `attrs.cmdline={ cd /x && ls; } >out` and a JSON-shaped attribute
    both start with `{` and carry their close. The anchor still narrows: a shell command
    carrying an unclosed `{` does not START with one, so it stays clean.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if v == OPEN_MARKER:
        return True
    return v.startswith("{") and (v.endswith("}") or v.count("{") > v.count("}"))


def is_ident_open(value: Any) -> bool:
    """Does this `ident` cell still carry an open question — WHOLE-cell or EMBEDDED.

    Unlike a class slot or an attribute value, an identifier is routinely named IN PART, and
    the committed investigations do exactly that: `bash[pid=??]` and `??[pid=??]` for a process
    whose binary is known and whose pid is not, `dev-ws-??` for a host whose prefix is known
    and whose index is not.

    `is_unresolved` is anchored to the whole cell and calls every one of those SETTLED,
    which is the wrong answer for BOTH halves of the retrieval key (#919): a
    `frontier_nodes: {slot: ident}` lesson — "pin the pid before you attribute the process" —
    could never fire on the document that needs it, and an `observed_nodes: {slot: ident}`
    lesson fires instead, asserting the run HOLDS an identifier that literally reads `??`.

    SUBSTRING, deliberately, and only here. `is_unresolved` stays whole-cell anchored because
    an `attrs.cmdline` may legitimately carry braces or a literal `?`; an ident cell is a name
    the document CHOSE, and `??` inside one is the marker rather than data. Scope is retrieval
    only — `_check_benign_open_slots` passes `include_ident=False`, so widening this cannot
    move a disposition gate.

    A SUPERSET of `is_unresolved`, never a replacement for it. The embedded test alone loses
    the OTHER marker: SKILL.md's progression is `??` → `{a, b}` → concrete, so an ident cell
    reading `{dev-ws-1, dev-ws-2}` has not picked a name — and a substring test for `??` calls
    it SETTLED, which is the exact inversion this predicate exists to prevent for `??`. The
    class and attribute arms already read a candidate set as open; the ident arm has to agree.
    """
    return is_unresolved(value) or (isinstance(value, str) and OPEN_MARKER in value)


def class_slots(classification: str) -> list[str]:
    """A class cell's slots — the slash-tuple, minus an optional leading `<type>:` prefix.

    Brace-aware, because the primary candidate-set form enumerates whole triples
    (`{monitoring-agent/internal/known-corp, ip-only/internet/novel}`) and a plain
    `split("/")` would shred it into slots that are neither open nor concrete. Splitting at
    depth 0 only reads that cell as the ONE unresolved slot it is, and still reads the
    per-slot form (`role/{internal, dmz}/prov`) as three.

    The type prefix is stripped rather than tolerated: SKILL.md says the class cell carries
    the slash-tuple only, but `compute:{...}` is a spelling models reach for, and the prefix
    alone would otherwise hide the candidate set behind it.

    PUBLIC for the same reason `effective_vertex_state` below is: `has_open_slot` uses this
    split to decide a class cell is OPEN, and `scripts/lessons/lessons_frontier.py` re-splits
    the same cell to decide which selector matches it. A second, plainer `split("/")` there
    read the whole-triple candidate set as five fragments and kept the `compute:` prefix, so
    the two halves of one join disagreed about what a slot even is (#919).
    """
    c = classification.strip()
    head, sep, rest = c.partition(":")
    if sep and "{" not in head and "/" not in head:
        c = rest.strip()
    slots: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in c:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        elif ch == "/" and depth == 0:
            slots.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    slots.append("".join(cur))
    return [s.strip() for s in slots]


def is_open_slot(slot: str) -> bool:
    """Is this ONE ALREADY-SPLIT class slot unresolved.

    PUBLIC and separate from `has_open_slot` because `scripts/lessons/lessons_frontier.py`
    needs exactly this half: it has already run `class_slots` and holds the slots, and calling
    `has_open_slot` on one of them re-splits it and strips a leading `<head>:` prefix — so the
    cell that decided a slot was OPEN and the cell that wildcards it disagreed about the values
    the two exist to agree on (#919). One definition, two readers, rather than a copy per
    reader.

    A `{` the author never closed is an UNTERMINATED candidate set and counts as open: the
    depth-aware split in `class_slots` folds every slot after it into one cell that is neither
    `??` nor a closed `{...}`, so a single dropped `}` would read as CONCRETE. A stray `}` with
    no `{` is left alone — it splits like any other character and hides nothing.
    """
    return is_unresolved(slot) or slot.count("{") > slot.count("}")


def has_open_slot(classification: Any) -> bool:
    if not isinstance(classification, str):
        return False
    return any(is_open_slot(slot) for slot in class_slots(classification))


def _seed_vertex_state(
    companion: CompanionBody, state: dict[str, dict[str, Any]]
) -> None:
    for v in _walkers.all_vertices(companion):
        vid = v.get("id")
        if not isinstance(vid, str):
            continue
        cls = v.get("classification", "")
        cur = state.setdefault(
            vid,
            {
                "classification": cls,
                # Seeded from the DECLARED `:V` identifier. Both construction sites carry the
                # slot — one present at only one of them is a KeyError for the consumer on
                # every document that does not happen to exercise the other.
                "identifier": v.get("identifier", ""),
                "attributes": dict(v.get("attributes") or {}),
            },
        )
        # BLANK counts as unsettled here, exactly as it does on the ident arm below.
        # `classification` is not a required `:V` column, so `v-001|compute|||attrs` is
        # diagnostic-clean, and the pre-#919 test — `has_open_slot(cur["classification"])` —
        # is False for `""`, so the concrete class a later `observations.vertices` row
        # supplies was dropped. That only mattered once `iter_vertex_cells` stamped the class
        # tuple onto EVERY cell: a latched `""` makes `_class_pins` refuse every class-bearing
        # selector against the vertex's ident and attrs cells too, not just its class cell.
        #
        # Still one direction, and still never blank→OPEN: taking an unresolved class over an
        # empty one would newly BLOCK a benign close on a document the gate accepts today.
        held_cls = cur["classification"]
        if cls and not has_open_slot(cls) and (
            not (isinstance(held_cls, str) and held_cls.strip()) or has_open_slot(held_cls)
        ):
            cur["classification"] = cls
        # The IDENT half of the same rule, and it only started mattering when
        # `iter_vertex_cells(include_ident=True)` gave the slot a reader (#919). Re-observing a
        # vertex is how an append-only document NAMES the entity it opened with `ident=??`
        # (SKILL.md §Open questions now recommends that spelling over a guessed identifier), so
        # without this the frontier reports `ident=??` open on a vertex the run already named,
        # re-pushes the "name this entity" lesson forever, and withholds every
        # `observed_nodes: {slot: ident}` selector from the resolved value.
        #
        # UNSETTLED, not just `??`, and BLANK is one of the unsettled states: an empty ident
        # column is neither open nor held and no open predicate reads `""` (see
        # `_apply_attr_updates` on why none may), so without this arm a vertex declared with
        # an empty ident and later named in a lead's `observations.vertices` folds to `""`
        # and the run's answer to "which host is this IP" reaches NO lane at all.
        #
        # The INCOMING value is not required to be settled, only non-blank. `bash[pid=??]` is
        # the shape this arm was written for — a process whose binary the run has and whose
        # pid it has not — and demanding a settled value dropped it, leaving the cell `""`:
        # not an `OpenSlot` either, so the "pin the pid before you attribute the process"
        # lesson could not fire on the document that needs it.
        #
        # One direction only, like the class arm: the guard is on what is HELD, so a later row
        # can supersede a blank or still-open cell and can never re-open a settled name.
        ident = v.get("identifier", "")
        held = cur["identifier"]
        if isinstance(ident, str) and ident.strip() and (
            not (isinstance(held, str) and held.strip()) or is_ident_open(held)
        ):
            cur["identifier"] = ident
        if v.get("attributes"):
            cur["attributes"].update(v["attributes"])


def _apply_attr_updates(
    companion: CompanionBody, state: dict[str, dict[str, Any]]
) -> None:
    for upd in _walkers.iter_attr_updates(companion):
        tgt = upd.get("target")
        updates = upd.get("updates") or {}
        if not isinstance(tgt, str) or not isinstance(updates, dict):
            continue
        st = state.setdefault(
            tgt, {"classification": "", "identifier": "", "attributes": {}}
        )
        for key, val in updates.items():
            # A refinement with nothing in its value cell resolves nothing. The parser defaults
            # an absent value to `""`, and `has_open_slot("")` / `is_unresolved("")` are both
            # False — so assigning it would read not as a downgrade but as a RESOLUTION, and
            # `l-001|v-001|class|` would clear the very `??` the row was meant to settle.
            # `_check_attr_update_keys` refuses the row outright; this keeps the read side
            # honest on a document that never went through the gate.
            if not isinstance(val, str) or not val.strip():
                continue
            if key == SLOT_CLASS:
                st["classification"] = val
            elif key == IDENT_REFINEMENT_KEY:
                # A DISTINCT top-level slot, never `attributes["ident"]` — see
                # IDENT_REFINEMENT_KEY. Last row in document order wins; the fold retains
                # no history, so a superseded value survives only as the rows on disk.
                st["identifier"] = val
            elif isinstance(key, str) and key.startswith(ATTR_PREFIX):
                st["attributes"][key[len(ATTR_PREFIX):]] = val


def effective_vertex_state(
    companion: CompanionBody,
) -> dict[str, dict[str, Any]]:
    """Every vertex as it stands NOW — declared `:V` state with every `:R attr_updates` row
    applied, last row winning.

    PUBLIC because it is the read-side answer to "what does the document currently say",
    which two independent consumers need: the benign-disposition gate below, and the
    frontier derivation `frontier.py` keys lesson retrieval on (#919). Both must see one
    fold of the document, not two that can drift.
    """
    state: dict[str, dict[str, Any]] = {}
    _seed_vertex_state(companion, state)
    _apply_attr_updates(companion, state)
    return state


#: The three states a vertex cell can be in. NOT a bool: open and held are not complements —
#: an absent cell is neither, and collapsing it into `held` would report every attribute a
#: vertex never carried as something the run KNOWS (`frontier.HeldFact`).
CELL_OPEN = "open"
CELL_HELD = "held"
CELL_EMPTY = "empty"


@dataclass(frozen=True)
class VertexCell:
    """One `(vertex, slot)` cell of the folded document, classified open / held / empty.

    THE node-axis walk. Two consumers read it, and they disagree about what to DO with a cell,
    never about what the cell IS: the benign-disposition gate (`_check_benign_open_slots`)
    blocks on the open ones, and `frontier._node_state` keys lesson retrieval on both populated
    halves (#919, PR-930). Before this they were two walks that agreed by inspection.
    """

    vertex_id: str
    #: The vertex's effective class tuple, carried on EVERY cell rather than only the `class`
    #: one, because a lesson selector matches `{type, class, slot}` as a triple — an
    #: `attrs.loginuid` cell still has to say what kind of vertex it sits on.
    classification: str
    slot: str
    value: str
    state: str

    @property
    def is_open(self) -> bool:
        return self.state == CELL_OPEN

    @property
    def is_held(self) -> bool:
        return self.state == CELL_HELD


def _cell_text(value: Any) -> str:
    """A cell as text. A non-`str` is read as ABSENT rather than crashing the walk.

    Both open tests already guard their input and answer False for a non-`str`, so this only
    restates their tolerance for the emptiness test below — which reaches for `.strip()` and
    would otherwise take down a whole document's frontier over one malformed attribute."""
    return value if isinstance(value, str) else ""


def _cell_state(value: str, *, open_test: Callable[[Any], bool]) -> str:
    """Classify one already-folded cell.

    `open_test` varies by slot and the variation is load-bearing: a class cell is open when ANY
    of its slash-slots is (`has_open_slot`), while `ident` and `attrs` cells are single values
    that `is_unresolved` reads whole. Running `is_unresolved` across a class tuple would read
    `a/??/c` as concrete — it is the WHOLE cell that is neither `??` nor a candidate set.

    Emptiness is tested FIRST and independently, because neither predicate reads `""` as open —
    see `_apply_attr_updates` on why a blank value must never read as a resolution."""
    if not value.strip():
        return CELL_EMPTY
    return CELL_OPEN if open_test(value) else CELL_HELD


def iter_vertex_cells(
    companion: CompanionBody, *, include_ident: bool
) -> Iterator[VertexCell]:
    """Every vertex cell the folded document holds, in document order, class → ident → attrs.

    `include_ident` is the first of the two divergences `frontier.py`'s module docstring
    records, hoisted out of a comment and into the signature. The gate passes False — an
    unresolved identifier must not block a benign close, which is the whole reason
    `IDENT_REFINEMENT_KEY` routes `ident` to its own top-level slot instead of into
    `attributes`. Retrieval passes True, because an unresolved identifier is the single most
    retrieval-worthy open slot there is.

    The second divergence is deliberately NOT a parameter. `effective_vertex_state` fabricates
    an entry for any `:R attr_updates` TARGET and the validator admits an `e-*` there, so some
    ids yielded here have no `:V` row at all. This walk reports them: the gate blocks on them
    today and must keep doing so, and dropping them here would narrow it silently. It is the
    CONSUMER that needs a vertex type to match a selector against, so that filter — and the
    limitation it creates — belongs in `frontier._node_state`, where it is recorded.
    """
    for vid, st in effective_vertex_state(companion).items():
        cls = _cell_text(st.get("classification"))
        yield VertexCell(
            vid, cls, SLOT_CLASS, cls, _cell_state(cls, open_test=has_open_slot)
        )
        if include_ident:
            ident = _cell_text(st.get("identifier"))
            yield VertexCell(
                vid, cls, SLOT_IDENT, ident, _cell_state(ident, open_test=is_ident_open)
            )
        for name, raw in (st.get("attributes") or {}).items():
            val = _cell_text(raw)
            yield VertexCell(
                vid,
                cls,
                f"{ATTR_PREFIX}{name}",
                val,
                _cell_state(val, open_test=is_unresolved),
            )


def _check_benign_open_slots(companion: CompanionBody) -> list[str]:
    """The open cells that block a benign close, over the one shared walk.

    `include_ident=False`: see `IDENT_REFINEMENT_KEY`. An unresolved identifier does not block —
    routing `ident` where this check can see it is the exact mistake that key exists to prevent.
    """
    errors: list[str] = []
    for cell in iter_vertex_cells(companion, include_ident=False):
        if not cell.is_open:
            continue
        if cell.slot == SLOT_CLASS:
            errors.append(
                f"disposition benign blocked: vertex {cell.vertex_id} still has an "
                f"unresolved class ({cell.value!r}) — resolve via "
                f":R attr_updates or escalate"
            )
        elif cell.slot.startswith(ATTR_PREFIX):
            errors.append(
                f"disposition benign blocked: vertex {cell.vertex_id} attribute "
                f"{cell.slot[len(ATTR_PREFIX):]!r} is still unresolved ({cell.value!r}) — "
                f"resolve via :R attr_updates or escalate"
            )
        # No `else`. The two arms above are the two slot kinds `include_ident=False` yields
        # today, but the walk is SHARED and takes a knob — a bare `else` would render an
        # `ident` cell as `attribute ''` (`"ident"[len("attrs."):]` is `""`), a nonsense refusal
        # naming an attribute that does not exist, and one that contradicts the whole reason
        # `IDENT_REFINEMENT_KEY` routes `ident` out of `attributes`. A fourth slot kind reaching
        # here should be a visible gap, not a mislabelled attribute.
    return errors


def _anchor_kind(record: Any) -> str:
    """The anchor kind a `:H h-NNN.authz` contract or a `:R authz` row carries, normalized.

    Through `_cell`, because this is the only column the two sides of the shared-`ac<n>`
    discrimination both carry — `_hyp_sub_authz_row` copies it verbatim and
    `_canonicalize_resolution_row` copies it verbatim, so an author who quotes uniformly makes
    the two halves of one comparison disagree about a kind they spell identically, and no row
    can then be attributed to its contract.
    """
    return _cell(record, "anchor_kind") if isinstance(record, dict) else ""


def _declarers_by_contract_id(
    companion: CompanionBody,
) -> dict[str, list[tuple[str, str]]]:
    """Every `(hypothesis, anchor kind)` that declares each `ac*` id — LIVE OR NOT.

    A different question from the one `_check_authz_contract_ids` indexes, which is why the
    live filter is not shared. That check asks "is this collision still repairable"; this one
    asks "which contract does a `:R authz` row naming this id answer", and a refuted declarer
    competes for the row exactly as a live one does — the row carries no hypothesis column.
    """
    declared_by: dict[str, list[tuple[str, str]]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            # `_cell`, which unquotes: `_hyp_sub_authz_row` copies `id` verbatim while every
            # reader matches it against a `fulfills` cell read through `_cell`, so a quoted
            # declaring id is a contract no row can ever discharge — and rule #26's refusal
            # then advises a `fulfills="ac1"` cell that unquotes straight back to `ac1`.
            cid = _cell(c, "id")
            if cid:
                declared_by.setdefault(cid, []).append((hid, _anchor_kind(c)))
    return declared_by


def _authz_contract_error(
    hid: str,
    contract: AuthorizationContract,
    declarers: dict[str, list[tuple[str, str]]],
    verdicts: dict[str, list[tuple[str, str]]],
) -> str | None:
    """Why this ONE contract on this LIVE hypothesis does not close benign — or `None`."""
    cid = _cell(contract, "id") or "?"
    anchor = _anchor_kind(contract)
    competing = [(h, a) for h, a in declarers.get(cid, []) if h != hid]
    candidates = verdicts.get(cid) or []

    if competing:
        # The anchor kind is always present: `_hyp_sub_authz_row` `_require`s it, so a
        # `:H <h>.authz` row without one is a parse error and the contract never reaches the
        # companion. That is what makes the kind a usable discriminator here.
        twins = sorted(h for h, a in competing if a == anchor)
        if twins:
            return (
                f"disposition benign blocked: authz contract {cid} on live hypothesis "
                f"{hid} shares BOTH its id and its anchor kind {anchor!r} with a contract "
                f"on {', '.join(twins)} — a `:R authz` row names only the contract it "
                f"fulfills, so no row can be attributed to this one and none discharges "
                f"it; number `ac*` across the document, not per hypothesis"
            )
        rows = [v for v, a in candidates if a == anchor]
        if not rows:
            return (
                f"disposition benign blocked: authz contract {cid} on live hypothesis "
                f"{hid} asks an {anchor!r} question, and {cid} is also declared by "
                f"{', '.join(sorted(h for h, _a in competing))} — so only a `:R authz` row "
                f"carrying anchor kind {anchor!r} discharges it, and the document has none"
            )
    else:
        rows = [v for v, _a in candidates]

    if not rows:
        return (
            f"disposition benign blocked: authz contract {cid} on "
            f"live hypothesis {hid} resolved 'no fulfilling :R authz "
            f"row', not 'authorized' — benign requires every contract "
            f"authorized"
        )
    # The LIST, not `next(..., None)`: `None` is a verdict a row can carry, so the sentinel
    # and the value would be the same object and a `None` verdict would discharge the contract
    # it is the strongest evidence against. Emptiness is the only test that cannot collide.
    bad = [v for v in rows if v != "authorized"]
    if bad:
        return (
            f"disposition benign blocked: authz contract {cid} on "
            f"live hypothesis {hid} resolved {bad[0]!r}, not 'authorized' "
            f"— benign requires every contract authorized"
        )
    return None


def outstanding_authz_contracts(
    companion: CompanionBody,
) -> list[tuple[str, AuthorizationContract, str]]:
    """Every `(hypothesis, contract, why)` on a LIVE hypothesis that no `:R authz` row
    discharges — THE definition of "this authorization question is still open".

    PUBLIC, and published for the same reason `effective_vertex_state` is: two consumers need
    one answer. `_check_benign_authz` below turns each `why` into a benign-close refusal, and
    `frontier._open_contracts` puts each contract on the retrieval frontier (#919). A second
    reading of "discharged" — a bare `fulfills_contract` id set, say — silently disagrees with
    this one on every shared id, and disagrees in the harmful direction: the frontier drops
    the contract that is actually wedging the close, so the lessons about what that anchor can
    conclude are withheld exactly when the run is stuck on it.

    See `_authz_contract_error` for why a shared id is scoped by anchor kind.
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    hyps = _walkers.all_hypotheses(companion)
    declarers = _declarers_by_contract_id(companion)

    verdicts: dict[str, list[tuple[str, str]]] = {}
    for row in _walkers.iter_authz_resolutions(companion):
        # `_cell`, matching `_check_authz_contract_closure`. Read raw, a uniformly quoted
        # `fulfills` keys `'"ac1"'` here and `ac1` there, so the closure gate calls the contract
        # discharged while this — the definition `_check_benign_authz` AND `frontier`
        # `_open_contracts` both read — calls it outstanding. Two answers about one row, and the
        # frontier drops the contract that is actually wedging the close.
        cid = _cell(row, "fulfills_contract")
        if cid:
            verdicts.setdefault(cid, []).append(
                (row.get("verdict", "indeterminate"), _anchor_kind(row))
            )

    out: list[tuple[str, AuthorizationContract, str]] = []
    for hid in sorted(live):
        hyp = hyps.get(hid)
        if hyp is None:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            found = _authz_contract_error(hid, c, declarers, verdicts)
            if found is not None:
                out.append((hid, c, found))
    return out


def _check_benign_authz(companion: CompanionBody) -> list[str]:
    """Every authz contract on a LIVE hypothesis is discharged by an `authorized` row.

    The row that discharges it has to be attributable to it, and a bare `fulfills_contract` id
    is not always enough. `_check_authz_contract_ids` exempts a collision whose other side is
    REFUTED, because on an append-only document refuting is the only repair left once the rows
    are on disk. That exemption is sound about the CONTRACT and false about the ROW: a
    `:R authz` row written against the refuted declarer's `ac1` would discharge the LIVE
    declarer's `ac1` too, landing a benign close over a question nobody ever asked.

    So a shared id is scoped by ANCHOR KIND — the one column both sides carry, and the one that
    says which question the row answers. Scoping rather than refusing outright keeps the rule
    repairable: `:H` rows are immutable, so a live contract holding a shared `ac1` can never be
    renumbered, and "an ambiguous id discharges nothing" would make `disposition: benign`
    unreachable for the rest of that document's life. Writing the `:R authz` row that carries
    THIS contract's anchor kind is an ordinary append, and it discharges it.

    Two declarers sharing an id AND an anchor kind has no honest reading left and is refused:
    no row can be attributed, so none discharges.

    The scoping applies only where the id is shared. A contract nobody competes for is
    discharged by its id alone; making the anchor kind load-bearing document-wide would refuse
    every document that left the cell empty.
    """
    return [why for _hid, _c, why in outstanding_authz_contracts(companion)]


def _check_conclude_vocab(companion: CompanionBody) -> list[str]:
    """`conclude`'s disposition is the run's headline, so it carries a vocabulary check like
    every other conclude field: an out-of-enum value silently skips the benign gating below,
    and a typo would buy a document past the checks a `benign` conclusion has to pass."""
    disposition = (companion.get("conclude") or {}).get("disposition")
    return _check_vocab(
        disposition, vocab.DISPOSITION,
        f"conclude: disposition {disposition!r} is not a known disposition "
        f"(`enum disposition`)",
    )


def _row_states_something(value: Any) -> bool:
    """A `:T conclude` scalar that actually SAYS something — present, non-blank, and not the
    format's own "nothing to say" marker, which only the parser gets to define."""
    return (
        isinstance(value, str)
        and bool(value.strip())
        and not is_conclude_empty_marker(value)
    )


def _lead_returned_a_result(lead: FindingRecord) -> bool:
    """Did this lead come back with a RESULT — not merely with a record that it ran.

    Deliberately stricter than `_check_loop_close`'s committed test, which counts ANY outcome:
    `:L findings`' `fail_reason` column projects into `outcome` as `failure_reason`, so a lead
    whose only recorded outcome is "the query errored" reads as committed there. For closing a
    loop that is right — the loop was worked. Here it is the shape the gate exists to reject:
    a failed query tested the alerted entity for nothing.
    """
    if lead.get("resolutions"):
        return True
    outcome = lead.get("outcome")
    if not isinstance(outcome, dict):
        return False
    return bool(set(outcome) - {"failure_reason"})


def _check_false_positive_gating(companion: CompanionBody) -> list[str]:
    """`false-positive` is the one disposition that closes a case on a claim about the RULE, so
    it is the one that has to prove it also looked at the entity.

    Three things are checked, each a way the exit could otherwise be faked:

      * `detection_notes` — an FP close with no stated defect is a close with no reason, and
        `none` is not a defect: the format's empty marker is rejected here, not read as prose;
      * `entity_check` names a lead that EXISTS and RETURNED A RESULT — a planned-but-never-
        dispatched lead is the shape of an investigation that stopped at the plan, and a lead
        carrying only a `fail_reason` is the shape of one whose query never landed;
      * that lead targets a vertex the PROLOGUE carried — an entity the ALERT named, not one
        the refutation introduced.

    TWO things it does NOT check, both about the QUESTION the named lead asked:

      * whether it was a good one. Distinguishing "read authorized_keys for the service account"
        from "…for root" is a question about query parameters, which never reach this layer;
      * whether it was INDEPENDENT of the alert's claim. Nothing here separates the lead that
        tested the host for its own suspicion from the lead that refuted the correlation, so a
        run can satisfy this gate with work it had already done before the refutation landed.

    Closing either gap means a fixed indicator set the runtime executes rather than the model
    choosing; this gate is the structural half, and its limits are recorded here so the next
    author does not read a passing gate as a swept host.
    """
    conclude = companion.get("conclude") or {}
    errors: list[str] = []

    notes = conclude.get("detection_notes")
    if not _row_states_something(notes):
        errors.append(
            "disposition false-positive blocked: no `detection_notes` row — the "
            "close rests on a claim about the rule, so the defect has to be stated"
        )

    lead_id = conclude.get("entity_check")
    if not (isinstance(lead_id, str) and lead_id.strip()):
        return errors + [
            "disposition false-positive blocked: no `entity_check` row — name the "
            "`:L findings` lead that tested the alerted entity for suspicion "
            "independent of the alert's claim, or conclude in another vocabulary"
        ]
    lead_id = lead_id.strip()

    lead = next(
        (f for f in _leads(companion) if f.get("id") == lead_id), None
    )
    if lead is None:
        return errors + [
            f"disposition false-positive blocked: `entity_check` names {lead_id!r}, "
            f"which is not a lead in `:L findings`"
        ]

    if not _lead_returned_a_result(lead):
        errors.append(
            f"disposition false-positive blocked: `entity_check` lead {lead_id} "
            f"committed no result — a lead that was planned and never resolved, or "
            f"whose only outcome is a `fail_reason`, did not test anything"
        )

    prologue_vertices = {
        v.get("id") for v in (companion.get("prologue") or {}).get("vertices") or []
    }
    target = lead.get("target")
    if target not in prologue_vertices:
        errors.append(
            f"disposition false-positive blocked: `entity_check` lead {lead_id} "
            f"targets {target!r}, which the prologue does not carry — the check has "
            f"to be against an entity the ALERT named, not one the refutation "
            f"introduced"
        )

    return errors


def _check_benign_grounding(companion: CompanionBody) -> list[str]:
    """`benign` needs a log that recorded WHAT THE ALERT WAS ABOUT.

    The other two benign checks refuse CONTRADICTIONS — an unresolved slot, an unfulfilled
    contract — which is the right shape for a log that did the work, and vacuous for one that
    did not: a document with no vertices has no slot to be open and no hypothesis to carry a
    contract, so it clears a price it never paid. Absent, empty, whitespace-only and fence-less
    `investigation.md` files all reach the close that way.

    So the prologue has to carry a vertex, and the point is what that does to the two checks
    beside it: once a vertex is guaranteed, `_check_benign_open_slots` has something to check
    on every benign close, and "the classification is resolved" stops being a claim a document
    can satisfy by staying silent. ORIENT writes this block before PLAN runs, so every real run
    clears it long before it can conclude anything.

    Deliberately NOT a demand for leads, committed or declared. How much measurement a
    disposition needs is a judgment about the case, which the review gate makes; this is the
    structural floor beneath it, and a trivially-benign alert closed off the payload alone is a
    run this must not refuse.
    """
    if not (companion.get("prologue") or {}).get("vertices"):
        return [
            "disposition benign blocked: no `:V prologue.vertices` row — benign says the "
            "alerted activity was accounted for, so the log has to name the entity the "
            "alert was about. An `investigation.md` that records no vertex records no "
            "investigation; conclude `inconclusive` instead."
        ]
    return []


def _check_benign_gating(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    errors += _check_benign_grounding(companion)
    errors += _check_benign_open_slots(companion)
    errors += _check_benign_authz(companion)
    return errors


@dataclass(frozen=True)
class _Price:
    """What a keyword costs, and why it costs it.

    Two columns because the price has two audiences. `check` answers whether THIS document has
    paid, and its strings name the blocking vertex, contract or row. `rationale` answers why
    the price exists at all — what a refused model needs in order to choose between paying it
    and concluding in another vocabulary. The rationale is a property of the KEYWORD, equally
    true at either boundary, so it belongs beside the check rather than in a second
    keyword-keyed table at whichever boundary happens to print it.
    """

    check: Callable[[CompanionBody], list[str]]
    rationale: str


#: The structural price of a keyword, keyed by the keyword. Two dispositions carry one; the
#: rest carry none. A table rather than a guard clause inside each gate, so a third priced
#: keyword is a row here and not a third copy of the "is this my disposition" preamble that
#: has to get the keyword normalization right every time.
#:
#: Two readers dispatch on it and both must, because a price owed by the document alone is not
#: owed at all: `_check_disposition_gating` on what `:T conclude` says, and
#: `disposition_entry_price` on what the close is about to commit. Adding a row arms both.
#:
#: The rationale rides in the row so a new keyword cannot be collected but left unexplained —
#: `lint_half_read_table`'s documented blind spot is a consumer that enumerates EVERY key, so
#: a second `{keyword: prose}` table elsewhere would not be caught drifting.
#:
#: Each row is BOUND TO A NAME rather than built inline, and that is load-bearing:
#: `lint_half_read_table` recognizes a keyed gate table only when every value is a
#: `Name`/`Attribute`/`Lambda`, so writing these as `_Price(...)` calls in the literal makes
#: the table invisible to the gate that watches it and drops its other findings too.
_BENIGN_PRICE = _Price(
    check=_check_benign_gating,
    rationale=(
        "`benign` says the alerted activity was accounted for, which an unresolved slot or "
        "an unfulfilled authorization contract on a live hypothesis directly contradicts, "
        "and which a log that never named the alerted entity does not support at all — so "
        "it is reachable only from an `investigation.md` that recorded the entity and "
        "settled what it left open."
    ),
)
_FALSE_POSITIVE_PRICE = _Price(
    check=_check_false_positive_gating,
    rationale=(
        "`false-positive` says the RULE misfired, which is no evidence about the alerted "
        "entity — so it is reachable only from an `investigation.md` that states the defect "
        "and names the lead that checked the entity anyway."
    ),
)

_DISPOSITION_GATES: dict[str, _Price] = {
    "benign": _BENIGN_PRICE,
    "false-positive": _FALSE_POSITIVE_PRICE,
}


@dataclass(frozen=True)
class EntryPrice:
    """What a close still owes for its keyword, and why that keyword owes anything.

    Both halves come back from ONE dispatch so a caller cannot look the second up on a
    differently-normalized value than the first — which would lose the refusal's explanation on
    exactly the zero-width-laced keyword normalization exists for.
    """

    owed: tuple[str, ...]
    rationale: str

    def __bool__(self) -> bool:
        """Truthy when something is owed, so `if price:` reads as "is anything outstanding".
        An unpriced keyword and a paid document are both falsy — the caller does not care
        which, and neither blocks a close."""
        return bool(self.owed)


def disposition_entry_price(disposition: str, companion_text: str) -> EntryPrice:
    """What `disposition` still owes, read off an `investigation.md` — nothing owed when it
    owes nothing, and nothing owed for the keywords `_DISPOSITION_GATES` prices at nothing.

    Public because a price has to be collected at BOTH boundaries. This module gates the
    `investigation.md` write; `report.md` is written by `close_investigation`, which takes its
    disposition as a tool argument and never reads the companion. Without a second reader an
    entry price is bypassable by writing `:T conclude` with a cheaper keyword — or none — and
    passing the priced one to the close, which is the artifact the learning loop, the evals and
    the ticket lane all actually read.

    The mirror of `_check_disposition_gating`, and deliberately the same table read: that one
    dispatches on the disposition the DOCUMENT wrote, this one on the disposition the CALLER is
    about to commit, so a row added to `_DISPOSITION_GATES` is collected at both.

    `disposition` is normalized through `normalized_disposition` for the same reason the
    write-side dispatch is: a keyword is judged on what it RENDERS as, so a zero-width
    character cannot turn a gate off. Typed `str` rather than `object` even though the
    normalizer accepts anything: an unrecognized value takes the unpriced branch, so this
    dispatch fails OPEN on a wrong one, and `object` would let the type checker pass a caller
    that swapped these two arguments — both are `str` — and silently waive the price. (The
    write-side dispatch reads a value off a parsed DOCUMENT and keeps the wider type honestly.)

    What each price means about an ABSENT companion is the gate's own business, and both priced
    ones answer it the same way for different reasons: `false-positive` demands stated content,
    so nothing written owes everything, and `benign` demands a prologue vertex beneath its
    contradiction checks (`_check_benign_grounding`), which are vacuous over a document with no
    vertices.
    """
    priced = normalized_disposition(disposition)
    price = _DISPOSITION_GATES.get(priced) if priced else None
    if price is None:
        return EntryPrice(owed=(), rationale="")
    companion, _ = parse_dense_companion(companion_text)
    return EntryPrice(owed=tuple(price.check(companion)), rationale=price.rationale)


def _check_disposition_gating(companion: CompanionBody) -> list[str]:
    """Run the structural checks this run's disposition is priced at, and only those.

    Dispatched on what the value RENDERS as. This is the ONE branch that decides whether a
    disposition's structural checks run at all, so a zero-width character clinging to the
    keyword would turn them all off — a gate failing open on an invisible character in
    model-authored text. `_check_conclude_vocab` denies the laced spelling separately, and the
    two rules stay independent on purpose: either alone would leave a hole.
    """
    disposition = normalized_disposition(
        (companion.get("conclude") or {}).get("disposition")
    )
    price = _DISPOSITION_GATES.get(disposition) if disposition else None
    return price.check(companion) if price is not None else []




#: `:L findings`' `mode` cell for a fast-path screen lead, and the `screen_result` that says
#: the screen HIT. The only two cell values the SCREEN rule turns on — every other mode and
#: every other result passes through it untouched.
SCREEN_MODE = "screen"
SCREEN_MATCH = "match"


def _check_screen_structure(companion: CompanionBody) -> list[str]:
    """A `screen_result` is a SCREEN lead's verdict, and two ways a document can carry one
    that decides nothing.

    On a lead with no `mode: screen` it is a verdict about a screen that never ran, written in
    the slot every reader takes for the run's fast-path answer. A `match` beside a `hypothesize`
    block is the second, and the only one with a disposition behind it — a matched screen ENDS
    the run on the fast path, so a companion that then enumerates hypotheses claims both that
    no investigation was needed and that one happened. WHICH of its two repairs is reachable
    depends on which half the document wrote first, and one of them always is — that is the
    whole of why this arm survives the strike below and the intermediate arm did not. Leads
    first (the shape the arm was written against): the `:L findings` cell is committed and "do
    not write the block" is the reachable repair. `:H hypothesize.hypotheses` first, which is
    the ORDINARY phase order: the block is committed and "record the screen as `no_match`" is
    the reachable one. Either way the trigger is the write in hand, which is what the
    intermediate arm never had.

    THE ONE ORDERING WHERE NEITHER IS: a `match` committed on an earlier screen, then a later
    screen in the same loop falling through and a `:H` block beside it. The run's answer is the
    last screen's `no_match`, so hypothesizing is right — and this arm still names the earlier
    committed `match` cell, which no write can withdraw. Recorded in the enforcement ramp as
    the wedge v2.22 leaves open; closing it wants the arm to read the loop's LAST
    `screen_result`, which is the `:L findings` document order `companion["findings"]` does not
    carry.

    THE INTERMEDIATE ARM IS GONE, and it is not coming back in this shape. The spec's third
    clause reads a `screen_result` on any screen lead that a later same-loop screen follows as
    a partial answer in the sequence's slot. The reading is defensible and the refusal is not
    reachable: whether a screen is the last one is a fact about leads not yet written, so the
    author cannot know it when writing the row, and by the time a second screen makes the first
    intermediate the first is a committed `:L findings` cell no legal write can withdraw. The
    arm named that earlier lead and offered "only its final lead carries the result", which is
    an instruction to have written a different row — and unlike the `match` arm it offered no
    second repair the proposed write could take. An earlier revision carved `match` out of this
    arm for exactly that reason, and the carve-out was the whole rule. What is lost is real —
    an early `no_match` still reads as the sequence's answer to a careless reader — and it is a
    reader-side concern that `:L findings` DOCUMENT order and the `loop` column answer for a
    human. Not for a programmatic one: `companion["findings"]` is the projector's lead buckets
    in FIRST-MENTION order, so a `:T resolutions` head naming a lead ahead of its `:L findings`
    row reorders the list and "the last `screen_result` in the loop" is not the last one
    written. Recorded in the enforcement ramp.

    Read off `findings[].screen_result`, which is where the `:L findings` column projects. The
    spec spells the field `outcome.screen_result`, from the pre-dense envelope; the projection
    has never nested it.

    NOT checked: whether the verdict is the right one, or whether the indicators it claims to
    rest on were retrieved. `screen_result` is a scalar the model writes and nothing beneath it
    is projected — the same limit `_check_false_positive_gating` records for `entity_check`.
    """
    leads = _leads(companion)
    # LOWERCASED at the read, because both cells are compared against a closed value and
    # neither is checked by any `_check_vocab_*` arm: `Screen` read raw fails CLOSED (a row
    # refused for a mode it spells correctly, with advice the author already followed) and
    # `Match` read raw fails OPEN (the fast-path arm below never fires).
    #
    # `screen_result` is the only one of the two folded across the whole document, and only to
    # buy the early return. `mode` is read PER ROW inside the loop: both surviving arms ask it
    # of the row they are judging, and the parallel-list shape the struck intermediate arm
    # needed (it scanned `modes[j]` for every `j > i`) is an invitation to reach across leads
    # again, which is the reading that arm was struck for.
    results = [_cell(lead, "screen_result").lower() for lead in leads]
    if not any(results):
        # Before the per-lead fold. No `screen_result` anywhere is every document in the tree
        # today, and every run that never takes the fast path.
        return []
    first_match = ""
    errors: list[str] = []
    for lead, result in zip(leads, results, strict=True):
        # `none` / `n/a` is the format's empty-cell spelling, not a verdict — the same reading
        # `_check_refutation_scope` takes of a `refutes` cell. Writing it in an unused trailing
        # column is the shipped convention (`defender/examples/example-b-parallel-iam-cmdb.md`
        # does it in `window`), so reading it as a screen result refuses a row that says
        # "nothing here" and offers "drop the cell" as the repair.
        if not result or is_conclude_empty_marker(result):
            continue
        lid = lead.get("id", "?")
        mode = _cell(lead, "mode").lower()
        # The matched-screen arm below speaks only for leads that ACTUALLY screened. A
        # `match` on a lead with no `mode: screen` is one defect — the mode arm's — and
        # letting it reach the fast-path arm too tells the same author, in the same pass, to
        # set the mode cell AND to delete a legitimate hypothesize block over a screen that
        # never ran.
        if mode != SCREEN_MODE:
            errors.append(
                f"lead {lid}: `screen_result: {result}` on a lead whose mode is {mode!r} — "
                f"the column records a SCREEN's verdict; set `mode: screen` on the lead that "
                f"ran the screen, or drop the cell"
            )
        elif result == SCREEN_MATCH and not first_match:
            # FIRST in `companion["findings"]` order, which is the projector's lead buckets in
            # FIRST-MENTION order rather than `:L findings` order — so with two matched screens
            # and a `:T resolutions` head naming the later one ahead of its row, the message
            # names the later-written cell. Same limit the docstring records for reading "the
            # loop's last `screen_result`", and it bites here for the same reason.
            first_match = str(lid)
    if first_match and _walkers.all_hypotheses(companion):
        errors.append(
            f"lead {first_match}: `screen_result: {SCREEN_MATCH}` closes the run on the fast "
            f"path, but {_HYPOTHESIS_DECLARING_BLOCKS} enumerates hypotheses — a matched "
            f"screen and an investigation are two different runs; drop the block, or record "
            f"the screen as `no_match` and keep investigating"
        )
    return errors


def _weight_text(weight: Any) -> str:
    """A hypothesis weight as the FORMAT spells it, for a message the author has to act on.

    `_hypothesis_record` maps the `weight null` cell to Python `None`, and an omitted cell
    leaves the key off — so `{weight!r}` renders `None` for exactly the hypothesis a
    persistence refusal is about. `null` is what the author wrote and what they can search for.
    """
    return repr(weight if isinstance(weight, str) and weight else vocab.NULL_WEIGHT)


def _check_hypothesis_persistence(companion: CompanionBody) -> list[str]:
    """A close that ENUMERATES its survivors enumerates all of them. A hypothesis the run
    neither refuted nor listed was dropped, and nothing else on disk says so.

    The failure is grading blindness papered over by silence: a hypothesis declared in loop 1,
    never moved off `null`, and left out of the close reads exactly like one that was never
    proposed. The document then concludes over a smaller mechanism set than it opened with,
    and no reader can tell which one went missing.

    Two discharges. Final effective weight `--` — the run refuted it — or a
    `:T conclude.surviving` row naming it. What was not refuted is what the run is still
    carrying, and naming it is the whole price. #933 retired the third, a `:T shelved` row:
    no investigation on record ever wrote one, and an escape hatch the injected SKILL.md never
    taught was reachable only by a run that guessed its grammar.

    A close that writes NO surviving table is out of scope, and that is a measured concession
    rather than an oversight. The table is omittable by construction — `_project_surviving_block`
    projects it "checkable, not authoritative" and benign gating computes survival from the
    resolution record precisely so a run may leave it out — so an absent table is read as the
    document deferring to that record, under which every non-refuted hypothesis IS surviving and
    nothing is dropped. Reading an absent table as an empty one instead would refuse seven of
    the eight ```invlang documents in the tree, both shipped goldens among them; making the
    table mandatory is a spec decision about what ANALYZE must write, not a validator decision
    about what this document says. The rule bites where the author made the claim: writing the
    table and leaving a live hypothesis out of it.

    NOT a claim that the table is TRUE. It is read as an ASSERTION the author made, never as
    evidence — which is what lets this demand the row without the row buying anything, and what
    keeps benign gating's independent computation of survival independent.

    v2.17: the spec's other two discharge arms are excised. `termination.rationale` is free text
    and `termination.category` an unchecked scalar, so "cited as the termination target" was
    never a projected hypothesis reference; and `matched_archetype` — "the matched archetype's
    mechanism" — is a `schema.Conclude` scalar no production code reads, resolved against an
    archetype catalog that does not exist. Neither was checkable, and an escape hatch that
    cannot be checked is one every document holds open.
    """
    conclude = companion.get("conclude") or {}
    # KEY presence, not row count. `_project_surviving_block` opens the bucket before it reads
    # a row, so an absent `:T conclude.surviving` block leaves the key off entirely while a
    # table written as the empty-array marker (`none`) leaves it present and empty — and the
    # second is a claim that NOTHING survived, which a live hypothesis contradicts.
    if "surviving_hypotheses" not in conclude:
        return []
    surviving = {
        row["hypothesis"] for row in conclude["surviving_hypotheses"]
        if isinstance(row, dict) and isinstance(row.get("hypothesis"), str)
    }
    return [
        f"conclude: hypothesis {hid} is neither refuted nor carried into the close — its "
        f"final weight is {_weight_text(weight)} and the `:T conclude.surviving` table, "
        f"which names {_known_ids(surviving)}, omits it. Resolve it to "
        f"{REFUTED_WEIGHT!r}, or add its row; a hypothesis declared and then dropped reads "
        f"like one that was never proposed"
        for hid, weight in _walkers.final_weights(companion).items()
        if weight != REFUTED_WEIGHT and hid not in surviving
    ]


#: The `termination.category` that makes rule #13 engage. A free-text scalar with NO closed
#: vocabulary anywhere in the system — `_check_vocab` has nothing to hand for it, and the
#: four-value enum the spec states (`trust-root`, `adversarial-refuted`, `severity-ceiling`,
#: `exhaustion-escalation`) is contradicted on disk by `data-ceiling` and
#: `adversarial-confirmed` in the two shipped e2e goldens. See
#: `_check_ceiling_test_scope` for what that costs the rule and why the vocabulary was not
#: closed here.
SEVERITY_CEILING = "severity-ceiling"


def _check_ceiling_test_scope(companion: CompanionBody) -> list[str]:
    """A run that terminates on a SEVERITY CEILING names the check it could not make.

    `severity-ceiling` is the strongest termination the language has that is not a refutation:
    live hypotheses remain and their critical edges cannot be tested with available tools. It
    is the one category that ends a run by declaring the question unanswerable, so it is the
    one that most needs a receipt — without `ceiling_test`, "severity ceiling" is a phrase, and
    the reader cannot tell a run that hit a real tooling boundary from one that stopped.

    The receipt is `ceiling_test`: one row per unreachable check, naming the host and the data
    source (`skills/invlang/SKILL.md` §`:T conclude`). The empty marker `none` projects as
    absence, so "wrote the row and said there was no ceiling" and "wrote no row" are the same
    document here, which is right — both claim no gap while the termination claims one.

    HALF the spec rule, deliberately. #13 also says `ceiling_test` is FORBIDDEN under any other
    termination, and that half is not implemented and should not be:

      * The field it forbids is not the field the spec was written about. The pilot spec's
        `ceiling_test` was `{kind, subject}` — THE out-of-band step that would resolve the
        ceiling, so "only under a ceiling" follows. The shipped field is the list of checks the
        run could not make, and eleven checked-in lessons instruct writing it whenever a source
        was out of reach ("name them by host and source type in `ceiling_test`"). Forbidding it
        elsewhere would refuse a run for obeying a lesson, which is the one failure
        `learning/core/persist.py` turns into a discarded run.
      * Measured: it would fire on the runs that name a telemetry gap and terminate on
        something else, which is the ordinary shape — `golden-v2sshd` names two such gaps in
        its prose and terminates `data-ceiling`.

    The TRIGGER is unbacked and this rule fails silent because of it. `termination.category` is
    free text with no vocabulary, so `severity_ceiling` or `severity-celing` disables this
    check with nothing said. That direction is the safe one — a typo costs a miss, never a
    wrongful refusal — but it is a real limit and not a rounding error. Closing the vocabulary
    would fix it and was NOT done here: the spec's four values are contradicted by both shipped
    e2e goldens (`data-ceiling`, `adversarial-confirmed`) and by three test corpora
    (`exhaustion`, `adversarial-confirmed`, `natural`), so closing it is a spec-owner decision
    with its own measurement, filed in the enforcement ramp rather than taken here.
    """
    conclude = companion.get("conclude") or {}
    category = (conclude.get("termination") or {}).get("category")
    # `_row_states_something` per row, not truthiness of the list. `ceiling_test  ""` projects
    # as a one-element list holding the empty string — truthy, and a receipt that names no
    # gap. The honest `ceiling_test  none` projects as absence and IS refused, so a bare
    # truthiness test makes the blank strictly easier to get past than the honest marker.
    if category != SEVERITY_CEILING or any(
        _row_states_something(t) for t in conclude.get("ceiling_test") or []
    ):
        return []
    return [
        f"conclude: `termination.category {SEVERITY_CEILING}` with no `ceiling_test` — the "
        f"category says live hypotheses remain and their critical edges cannot be tested, so "
        f"the close owes the specific check it could not make. Add one "
        f"`ceiling_test  \"<host> <data source> not retrieved\"` row per gap to `:T conclude` "
        f"(repeat the key; the SKILL's §`:T conclude` has the shape), naming the source "
        f"rather than the shape of the question. If you wrote a `:T conclude.ceiling_test "
        f"[kind|subject]` sub-table, that is the RETIRED spelling from "
        f"`docs/dense-investigation-format.md` — the parser recognizes it and projects "
        f"nothing, so its rows never reach this rule; re-send them as flat rows. If nothing "
        f"was actually out of reach, this run did not hit a ceiling — terminate on the "
        f"category that describes what happened."
    ]


#: Every `:T conclude.*` SUB-TABLE field — the fields a block writes without the document
#: having written `:T conclude` itself. Subtracted below so a mid-run write of one cannot read
#: as a close: `_project_deferral_block` opens its table lazily for the same reason, and
#: `_project_surviving_block` CANNOT (see `_is_closing`), which is why the subtraction is the
#: load-bearing half here rather than the belt.
#:
#: DERIVED from `parser._CONCLUDE_SUBTABLE_FIELDS`, never restated: that dict's own comment
#: invites "a fourth namespace should be a row here, not a fourth projector", and a
#: hand-written copy one module over is exactly what such a row leaves behind — after which a
#: mid-run `:T conclude.deferred_<new>` arms all three closure gates against every commitment
#: the run has not reached yet.
_NON_CLOSING_FIELDS: frozenset[str] = _CONCLUDE_SUBTABLE_FIELDS


def _is_closing(companion: CompanionBody) -> bool:
    """Did this document write a `:T conclude` block — the question the three closure gates
    actually mean by `if not conclude`.

    A truthiness test on the projected dict answers a different question and gets it wrong in
    both directions. A `:T conclude.deferred_preds` carrying a REAL row makes `conclude`
    truthy with no close in sight, so a mid-run write that defers one commitment would be
    refused for every commitment the run has not reached CONCLUDE on yet. And the
    other way, a `:T conclude` block is now guaranteed to record SOMETHING —
    `_project_conclude_scalars` warns when it recognizes no key at all — so an empty dict can
    only mean the close is not written.

    `surviving_hypotheses` does NOT count, though it is a claim ABOUT the close: being a claim
    about the close is not being the close, which is the question this asks.
    `_project_surviving_block` opens the key before it reads a row and must keep doing so —
    `_check_hypothesis_persistence` reads KEY PRESENCE to tell an absent table (defer to the
    resolution record) from one written as the `none` marker (a claim that NOTHING survived),
    so the lazy-open used for the deferral tables would silently disarm that rule. That leaves
    the subtraction as the only place to draw the line, and it costs nothing: rule #24 gates
    itself on its own key-presence test and never consults this function.

    Without the subtraction, a mid-run `:T conclude.surviving` with no `:T conclude` anywhere
    arms all three closure gates — and since append-only forbids removing the block and
    `fix_row` cannot reach it, the document is unwritable from then on.
    """
    conclude = companion.get("conclude")
    return isinstance(conclude, dict) and bool(set(conclude) - _NON_CLOSING_FIELDS)


@dataclass(frozen=True)
class _Commitment:
    """One thing the document DECLARED, which a close therefore has to account for.

    `owner` is the block that declared it — a hypothesis for a contract or a prediction, a lead
    for an impact prediction — because the local id is only unique under that owner. `ref` is
    the qualified spelling every deferral table and every error message uses.
    """

    owner: str
    local_id: str

    @property
    def ref(self) -> str:
        return f"{self.owner}.{self.local_id}"


def _deferral_index(rows: Iterable[DeferralRecord]) -> dict[str, list[str]]:
    """`:T conclude.deferred_*` rows keyed by the reference they name, EXACTLY as written.

    Never by an expanded alias. A row that writes the qualified `h-001.ac1` is registered under
    that alone, so it cannot also discharge `h-002.ac1`; a row that writes the bare `ac1`
    registers under the bare form and discharges every owner's `ac1`, which is the same
    document-wide reading `_check_benign_authz` gives a bare `fulfills_contract`. The
    asymmetry is deliberate: over-refusing a deferral leaves an author with no legal repair,
    while over-accepting one costs an orphan that a differently-spelled row would have
    excused anyway.

    A list per key, not one rationale: two rows may name the same commitment, and one of them
    carrying a reason is enough.

    EITHER spelling of the reference column. `:T conclude.deferred_authz` names its cell
    `contract_ref` and the other two `prediction_ref`; the parser keeps whichever the table
    used, because that is the name the spec gives the field, and one closure walk over three
    namespaces is a reason for ONE reader, not for one column name. A row carries exactly one
    of the two.
    """
    out: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ref = (row.get("contract_ref") or row.get("prediction_ref") or "").strip()
        if ref:
            out.setdefault(ref, []).append(row.get("rationale") or "")
    return out


def _unclosed_commitments(
    declared: Iterable[_Commitment],
    *,
    resolved: Container[str],
    deferrals: Iterable[DeferralRecord],
) -> Iterator[tuple[_Commitment, bool]]:
    """Every declared commitment a close neither resolved nor deferred WITH A RATIONALE, paired
    with which of the two it is — `True` when a deferral row names it and every rationale on it
    is blank, `False` when nothing names it at all.

    ONE walk for three rules. #26 (authorization contracts), #31 (impact predictions) and #34
    (predictions) are the same sentence over three namespaces — *every declared X is resolved,
    or deferred with a reason* — and #31's own text says it "mirrors rule #26's orphan gate".
    Written out three times they drift: the bare-vs-qualified reference reading, whether a
    blank rationale discharges, and whether a second deferral row can rescue the first are
    three judgment calls each, and nine places to disagree.

    What the callers keep is everything rule-specific: WHICH commitments are declared, what
    counts as resolved (a `:R authz` row, a `:R impact` row, a resolution head), and the prose.
    A blank rationale is a distinct outcome rather than "not deferred" because the two need
    different repairs — one needs a row, the other needs a sentence.

    "States something" rather than "is non-blank", the same test `_check_ceiling_test_scope`
    applies to `ceiling_test`. `none` / `n/a` is the format's own word for "nothing to say" and
    the SKILL teaches it two paragraphs from the deferral tables as the empty-TABLE marker, so
    a bare-truthiness test makes `h-001.p1|none` a discharge — one word that clears the only
    guard the escape hatch has, while the honest empty cell is refused.
    """
    index = _deferral_index(deferrals)
    for c in declared:
        if c.ref in resolved or c.local_id in resolved:
            continue
        rationales = index.get(c.ref, []) + index.get(c.local_id, [])
        if not rationales:
            yield c, False
        elif not any(_row_states_something(r) for r in rationales):
            yield c, True


def _closure_refusal(
    subject: str, table: str, ref: str, *, blank_rationale: bool, resolve: str
) -> str:
    """The two ways a closure rule refuses, worded once.

    `subject` names the commitment as its own rule spells it, `resolve` is that rule's
    non-deferral repair, and `table` is the sub-table that carries the deferral. The wording is
    shared because the FAILURE is shared: a commitment made and then neither kept nor withdrawn
    reads, from outside, exactly like one that was never made.
    """
    if blank_rationale:
        return (
            f"conclude: {subject} is deferred with an empty rationale — a "
            f"`:T conclude.{table}` row records WHY the commitment could not be settled, and a "
            f"blank cell records nothing while still discharging it. Write the reason, or "
            f"{resolve}."
        )
    return (
        f"conclude: {subject} is declared and then abandoned — nothing settles it and no "
        f"`:T conclude.{table}` row defers it. Either {resolve}, or add a "
        f"`:T conclude.{table}` row `{ref}|\"<why it could not be settled>\"`; a commitment "
        f"made and then dropped reads like one that was never made."
    )


def _declarer_kinds(
    c: _Commitment, declarers: dict[str, list[tuple[str, str]]]
) -> tuple[set[str], set[str]]:
    """This commitment's own anchor kinds, and the ones a COMPETING declarer of the same
    `ac<n>` carries.

    One walk for the two readers of it — `_discharged_by_row` decides the refusal and
    `_authz_closure_repair` words its repair — because they are a matched pair: a repair
    derived from a different split than the predicate advises a row the gate will reject
    again, on an append-only `:R authz` row the author cannot rewrite.
    """
    rows = declarers.get(c.local_id, [])
    return (
        {a for h, a in rows if h == c.owner},
        {a for h, a in rows if h != c.owner},
    )


def _discharged_by_row(
    c: _Commitment,
    declarers: dict[str, list[tuple[str, str]]],
    kinds_by_id: dict[str, set[str]],
) -> bool:
    """Does some `:R authz` row fulfil THIS contract — not merely one numbered the same.

    A `:R authz` row names only the contract id, so when one `ac*` has more than one declarer
    the anchor kind is the only column that says which question the row answered. Same
    discrimination `_authz_contract_error` makes, and made here rather than shared with it
    because that function's other job is to word a benign-gate refusal.

    TWINS — a competing declarer carrying the SAME anchor kind — discharge NOTHING, which is
    the arm `_authz_contract_error` states first: "a `:R authz` row names only the contract it
    fulfills, so no row can be attributed to this one and none discharges it". Reading the
    shared kind as a discharge instead makes one row answer two questions, and
    `_check_authz_contract_ids` deliberately exempts a collision whose other side is refuted —
    exactly the shape this rule covers and the benign gate does not — so the live hypothesis's
    row would silently close the refuted one's unrelated question. `outstanding_authz_contracts`
    names that second reading as the harmful one; the two now give the same answer.
    """
    kinds = kinds_by_id.get(c.local_id)
    if not kinds:
        return False
    mine, competing = _declarer_kinds(c, declarers)
    if not competing:
        return True
    if mine & competing:
        return False
    return bool(mine & kinds)


def _authz_closure_repair(
    c: _Commitment, declarers: dict[str, list[tuple[str, str]]]
) -> str:
    """The non-deferral way out of a rule #26 refusal, worded for the case at hand.

    The BARE id in `fulfills`, the qualified one in the deferral row. That is not a cosmetic
    difference: `_check_benign_authz` matches `fulfills_contract` on the bare `ac<n>` alone, so
    advising `fulfills=h-001.ac1` would name a row that clears THIS rule and leaves the benign
    gate blocked.

    When the id is SHARED, the anchor kind is named too — `_discharged_by_row` requires it, and
    a repair that omits the discriminating column reads as already done to an author who has
    written the plain row. When it is shared with a declarer carrying the SAME kind, no row can
    be attributed at all, and saying so is the only honest repair besides the deferral the
    refusal already offers.
    """
    plain = f"fulfil it with a `:R authz` row carrying `fulfills={c.local_id}`"
    mine, competing = _declarer_kinds(c, declarers)
    if not competing:
        return plain
    twins = sorted(mine & competing)
    if twins:
        # The QUALIFIED spelling, because it is the one this rule actually accepts:
        # `_check_authz_contract_closure` resolves `c.ref in qualified`, so `fulfills={c.ref}`
        # discharges a twin that no bare id could. Advising "renumber it" alone would be a
        # repair the author cannot make — `:H` rows are append-only — on the one shape where a
        # legal repair exists. `_check_benign_authz` still matches the bare form, so the bare
        # row is named too; a document that owes both writes both.
        return (
            f"fulfil it with a `:R authz` row carrying `fulfills={c.ref}` — {c.local_id} is "
            f"also declared on another hypothesis under anchor kind {twins[0]!r}, so the bare "
            f"id names no one contract and only the qualified `h-NNN.ac<n>` form says which "
            f"question the row answered (`ac<n>` numbers across the DOCUMENT, so the durable "
            f"fix is not to share one)"
        )
    # `mine` cannot be empty here: `c` came from the same `all_hypotheses` walk that built
    # `declarers`, under the same guard, so its own `(owner, kind)` pair is always in it — an
    # empty anchor kind still contributes `{""}`.
    return (
        f"{plain} AND `anchor_kind={sorted(mine)[0]}` — {c.local_id} is declared on more than "
        f"one hypothesis, so the anchor kind is what says which question the row answered"
    )


def _check_authz_contract_closure(
    companion: CompanionBody, *, gated: set[str] | None = None
) -> list[str]:
    """Every declared `:H h-NNN.authz` contract is fulfilled by a `:R authz` row, or deferred
    in `:T conclude.deferred_authz` with a reason.

    The orphan-contract gate. `_check_benign_authz` already refuses an unresolved contract, but
    only on a LIVE hypothesis and only under `disposition: benign` — so every escalation path
    accepted orphans in silence, and in the pre-v2.10 corpus 59% of declared contracts had no
    resolution at all. A contract is a question the run committed to asking; dropping it
    quietly is how a legitimacy question stops existing.

    DELIBERATELY broader than `_check_benign_authz` in two directions, and both come from the
    spec text. It runs under every disposition, and it covers contracts on REFUTED hypotheses
    too — refutation is offered as a deferral RATIONALE ("superseded by mechanism refutation at
    lead l-007"), not as an automatic discharge, because "the mechanism was refuted so its
    authorization question is moot" is a claim about the case that a reader should be able to
    see the run make.

    DEFERS to the run's own disposition gate on any contract that gate is ALREADY refusing. The
    two would otherwise report one missing `:R authz` row twice, and the second report would be
    actively misleading: this rule offers "defer it with a rationale" as a repair, and on a
    `disposition: benign` document that repair clears this rule and leaves benign blocked —
    a fix that does not fix the document. The gate's refusal names the same contract with the
    sharper consequence and the only repair that works, so it is the one that speaks.

    Matched on the gate's OUTPUT, not on the disposition keyword. `outstanding_authz_contracts`
    is the shared definition of "still open" and hands back the exact string the gate emits, so
    a price added to `_DISPOSITION_GATES` that also refuses contracts is deferred to with no
    edit here — where a `== "benign"` test would leave the next one double-reporting. The
    gate's output is HANDED IN by `diagnose`, which already ran it this pass; the `gated=None`
    default re-runs it for a direct caller and is what every test in the tree reaches.

    Fulfilment is read by id, with no verdict condition: an `unauthorized` row settles the
    question, and what that verdict then costs the document is the benign gate's business. A
    SHARED `ac*` id is scoped by ANCHOR KIND, the same discrimination `_authz_contract_error`
    applies, and `outstanding_authz_contracts`' docstring names the alternative as the harmful
    one: "a second reading of 'discharged' — a bare `fulfills_contract` id set, say — silently
    disagrees with this one on every shared id". `_check_authz_contract_ids` refuses two LIVE
    declarers of one id but deliberately exempts a collision whose other side is refuted —
    which is exactly the shape this rule covers and the benign gate does not, so a bare-id
    reading would let the live hypothesis's `:R authz` row discharge the refuted one's
    unrelated question. That is the automatic discharge the paragraph above says the rule does
    not grant.

    `resolved` is spelled QUALIFIED for the same reason. The shared walk also accepts a bare
    `local_id`, which is right for the deferral table (the SKILL teaches the bare form there)
    and wrong here: `_check_benign_authz` matches `fulfills` bare only after scoping it, and
    handing the walk a bare set would reintroduce the cross-owner discharge one layer down.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    # HANDED IN by `diagnose`, which already ran the gate this pass — re-running it here made
    # this the most expensive check in the validator, and the re-run is by far the larger half
    # of its cost on a `benign` document (`_check_benign_grounding` + `_check_benign_open_slots`
    # + `_check_benign_authz`, itself three `all_hypotheses` rebuilds). The default keeps the
    # function callable on its own, which is how every test in the tree reaches it.
    if gated is None:  # lint-default: ok — the standalone fallback; `diagnose` binds it
        gated = set(_check_disposition_gating(companion))
    # Guarded on `gated`: only a priced disposition can put a contract in it, and
    # `outstanding_authz_contracts` is three `all_hypotheses` rebuilds plus two lead walks —
    # otherwise computed in full and then filtered away by an empty set on every other close.
    spoken_for = {
        f"{hid}.{_cell(c, 'id')}"
        for hid, c, why in outstanding_authz_contracts(companion)
        if why in gated
    } if gated else set()
    declarers = _declarers_by_contract_id(companion)
    kinds_by_id: dict[str, set[str]] = {}
    #: `fulfills=h-001.ac1` — spec rule #7's QUALIFIED spelling ("`fulfills_contract` of shape
    #: `h-{id}.ac{n}` points to a hypothesis whose `authorization_contract` declares that
    #: `ac{n}`"), which `docs/dense-investigation-format.md` also calls the correct shape. The
    #: SKILL teaches the bare form and `_check_benign_authz` matches only that, so the bare one
    #: is what this rule ADVISES — but refusing the qualified one would deny a close for a
    #: contract the run answered, in the spelling the spec blesses. Kept in its own set rather
    #: than folded into `kinds_by_id`: a qualified row names its own declarer, so it discharges
    #: that contract and never another hypothesis's `ac1`.
    qualified: set[str] = set()
    for row in _walkers.iter_authz_resolutions(companion):
        # Through `_cell`, which unquotes — the read every other cell this rule compares gets.
        # `_canonicalize_resolution_row` copies the `fulfills` cell verbatim, as
        # `_hyp_sub_authz_row` does the `id` it is matched against — BOTH sides are read
        # through `_cell` for that reason. Read raw, a uniformly quoted row keys `'"ac1"'`
        # here, matches no declared `ac1`, and the refusal tells the author to write the row
        # they just wrote. Before the closure gate that only cost a `benign` close
        # (`_check_benign_authz`); now it costs every close.
        cid = _cell(row, "fulfills_contract")
        if not cid:
            continue
        owner, dot, local = cid.rpartition(".")
        if dot and local and HYPOTHESIS_ID_RE.fullmatch(owner):
            qualified.add(cid)
        else:
            kinds_by_id.setdefault(cid, set()).add(_anchor_kind(row))
    declared = [
        _Commitment(hid, _cell(c, "id"))
        for hid, hyp in _walkers.all_hypotheses(companion).items()
        for c in hyp.get("authorization_contract") or []
        if isinstance(c, dict) and _cell(c, "id")
        and f"{hid}.{_cell(c, 'id')}" not in spoken_for
    ]
    resolved = {
        c.ref
        for c in declared
        if c.ref in qualified or _discharged_by_row(c, declarers, kinds_by_id)
    }
    return [
        _closure_refusal(
            f"authz contract {c.ref}", "deferred_authz", c.ref,
            blank_rationale=blank,
            resolve=_authz_closure_repair(c, declarers),
        )
        for c, blank in _unclosed_commitments(
            declared,
            resolved=resolved,
            deferrals=conclude.get("deferred_authorizations") or [],
        )
    ]


def _check_impact_closure(companion: CompanionBody) -> list[str]:
    """Every declared `ip*` is graded by a `:R impact` row or deferred in
    `:T conclude.deferred_impact` with a reason — and the roll-up over those grades is
    internally consistent.

    Rule #26's orphan gate on the impact axis, and #31's own text says so. The failure is the
    same one: a predicate registered at PREDICT and never graded lets a run choose, after the
    fact, which of its own consequence thresholds to be measured against.

    ACROSS ALL LEADS, including a lead whose query failed. A predicate registered on a lead
    that never came back is exactly what the deferral arm is for ("the query errored before the
    measurement landed"), so the wider reading costs nothing and needs no concept the format
    does not already have — where exempting failed leads would need a rule about which
    `failure_reason` values excuse a predicate.

    The second half is the ROLL-UP PAIR, and only its PRESENCE. `impact_severity` is required
    exactly when the verdict is `exceeds` or `indeterminate` and forbidden otherwise, because
    severity is the magnitude of a consequence the run is CLAIMING: a severity beside `within`
    claims a magnitude for something that stayed inside its threshold, and a missing one beside
    `exceeds` escalates without saying how far. That is structural — it holds whatever the two
    cells say — which is why it ships while neither cell's VOCABULARY does.

    NOT checked, three times over, and all three for reasons at their sites. Neither conclude
    scalar's enum is enforced: `skills/invlang/SKILL.md` has never stated either vocabulary, so
    refusing on one refuses a run for a rule the model was never given — the failure spec rule
    #32 was struck for. And whether the roll-up is ARITHMETICALLY right — `exceeds` beside
    three `within` rows — needs the rows, and no document in the tree carries any; computing an
    aggregate from rows that do not exist yet is a check with no way to be wrong.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    resolved: set[str] = set()
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for row in (lead.get("outcome") or {}).get("impact_resolutions") or []:
            # `_cell` + `_qualify`, both shared with `_check_impact_resolution_refs`, so the
            # two rules cannot resolve one `pred_ref` to two different strings and report a
            # predicate as graded and abandoned at once.
            ref = _cell(row, "prediction_ref") if isinstance(row, dict) else ""
            if ref:
                resolved.add(_qualify(lid, ref))
    # The SAME index `_check_impact_resolution_refs` resolves against, not a second walk with
    # the same guard written out again: what counts as a declared `ip*` is one question.
    declared = [
        _Commitment(*ref.rsplit(".", 1))
        for ref in _declared_impact_predictions(companion)
    ]
    errors = [
        _closure_refusal(
            f"impact prediction {c.ref}", "deferred_impact", c.ref,
            blank_rationale=blank,
            resolve=f"grade it with a `:R impact` row carrying `pred_ref={c.ref}`",
        )
        for c, blank in _unclosed_commitments(
            declared,
            resolved=resolved,
            deferrals=conclude.get("deferred_impact_predictions") or [],
        )
    ]

    # `conclude.impact_verdict`'s ENUM is measured and NOT armed. `vocab.CONCLUDE_IMPACT_VERDICT`
    # exists so the SKILL and this comment can name it, and nothing refuses on it yet. It fires on
    # BOTH shipped e2e goldens — `golden-v2sshd` writes `none-detected` and
    # `golden-sshpivot-ab3` writes `attempted-lateral-movement`, where the spec's roll-up over
    # zero `:R impact` rows is `none` in both cases. Those two are not authored fixtures whose
    # cell can be corrected: they are RECORDED runs replayed through this very gate from
    # `tool_trace.jsonl`, so arming this refuses the recorded write and takes seven e2e tests
    # with it, and "repairing" them means rewriting a trace of what a model actually wrote.
    #
    # The cause is upstream of the fixtures. `skills/invlang/SKILL.md` writes `impact_verdict
    # none` in one worked example and states no vocabulary, so both runs filled a
    # free-text-looking slot with prose and neither disobeyed anything. The order this has to
    # land in is teach, then re-record, then arm — and the first step ships here.
    #
    # `impact_severity`'s MEMBERSHIP is unenforced for the same reason and by the same rule:
    # `vocab.IMPACT_SEVERITY` is registered so `enum conclude.impact_severity` can teach it,
    # and no check refuses on it. It measures zero fires today — no document writes the cell at
    # all — but enforcing a vocabulary the runtime prompt has never stated is the same mistake
    # whether or not it happens to bite yet, and the two conclude scalars are one decision.
    #
    # The conditional-presence clause below does NOT depend on either membership test. An
    # unrecognized verdict is simply not in `_SEVERITY_OWING`, so a severity beside it is
    # forbidden and a missing one is not demanded — which is the correct reading of a run that
    # rolled up to something the enum does not name.
    verdict = conclude.get("impact_verdict")
    severity = conclude.get("impact_severity")
    # BOTH cells normalized the same way, and the verdict is the half that used to be read raw.
    # `_project_conclude_scalars` `_unquote`s a scalar without re-stripping, so
    # `impact_verdict "exceeds "` reaches here with its padding and `Exceeds` reaches here with
    # its case — and a raw membership test then reads either as a verdict claiming nothing,
    # refusing the run for the `impact_severity` the SKILL just told it to write. One reading
    # for the pair, because the pair is one clause.
    verdict_key = _cell(conclude, "impact_verdict").lower()
    # `null` is the format's own word for "no severity", so it is an ABSENT severity here and
    # not a present one — the same reading `_project_conclude_scalars` gives the bare token.
    # Case-FOLDED, like `is_conclude_empty_marker` beside it: a case-sensitive test makes
    # `impact_severity NULL` a present severity that satisfies `exceeds` while saying there is
    # none, so the one spelling that should be refused hardest is the one that validates clean.
    stated = (
        _row_states_something(severity)
        and _cell(conclude, "impact_severity").lower() != "null"
    )
    owed = verdict_key in _SEVERITY_OWING
    if owed and not stated:
        errors.append(
            f"conclude: `impact_verdict {verdict}` with no `impact_severity` — the verdict "
            f"says a registered threshold was crossed or could not be shown not to be, and "
            f"the severity is how far. Add `impact_severity` "
            f"({', '.join(v for v in vocab.IMPACT_SEVERITY if v != 'null')}), or roll up to "
            f"`within` if nothing was actually exceeded"
        )
    if stated and not owed:
        errors.append(
            f"conclude: `impact_severity {severity}` beside `impact_verdict "
            f"{verdict if verdict is not None else 'null'}` — severity is the magnitude of a "
            f"consequence the run is CLAIMING, and this verdict claims none. Write "
            f"`impact_severity null`, or say which predicate was exceeded and roll the "
            f"verdict up to match"
        )
    return errors


#: The `conclude.impact_verdict` values that OWE an `impact_severity` — the ones where the run
#: is CLAIMING a consequence, so the severity says how large. Subtracted from the row-level
#: verdict enum rather than restated: `within` is the one member that claims none, and the
#: conclude-only `none` is not in that enum at all, so both fall out for the right reason
#: instead of by being left off a hand-written pair.
_SEVERITY_OWING: frozenset[str] = frozenset(vocab.IMPACT_VERDICT) - {"within"}


def _check_prediction_closure(companion: CompanionBody) -> list[str]:
    """Every `p*`/`ap*` on a hypothesis the run is still carrying was settled by some
    resolution, or deferred in `:T conclude.deferred_preds` with a reason.

    The contract ANALYZE owes PREDICT. PREDICT pre-commits a prediction set precisely so the
    grading cannot be chosen after the evidence lands; without a closure gate, ANALYZE cites
    the two predictions that came in and the other three are never heard from again, and no
    reader of the finished document can tell they existed.

    The late half of a pair. `_check_prediction_completeness` (spec #6) asks the same question
    at WRITE time and only of a hypothesis STANDING at `++` (`_confirmed_and_standing`, the one
    predicate that partitions the two), and offers no deferral — a standing `++` claims every
    prediction came in, so there is nothing outstanding to defer. This asks it of every weight, at
    CONCLUDE, and offers the deferral because at that point "the tool was never available" is a
    true and final answer.

    The discharge besides citation is read off the RESOLUTION RECORD rather than the `status`
    column the spec's wording names. `status` is a `:H` cell fixed at declaration time and
    append-only forbids updating it, so it can never carry a FINAL status; the run says
    "refuted" by moving the weight to `--`. That is the same translation
    `_check_hypothesis_persistence` applies to spec #24 — and since #933 retired `:T shelved`,
    the two rules read one word, not two.

    A citation only counts from a resolution with a non-null `after`. A row that cites `p1` and
    moves nowhere has recorded that the lead looked, not that the prediction settled — and
    `_walkers.final_weights` would read that row as the hypothesis's final position anyway.

    Scoped to the hypothesis that declared the prediction, never document-wide: a sibling's
    `p1` discharges nothing here, which is the cross-citation rule #25 refuses one level down
    and `_check_prediction_refs` enforces on the citing row.
    """
    conclude = companion.get("conclude") or {}
    if not _is_closing(companion):
        return []
    # ONE DEFINITION with rule #6's (`_settled_predictions`), so the write gate and the closure
    # gate cannot disagree about which citations count — a disagreement leaves the author
    # DEFERRING a prediction on a `++` that claims none is outstanding. Not one WALK: the two
    # rules run in separate passes and each folds it.
    resolved = {
        f"{hid}.{pid}"
        for hid, pids in _settled_predictions(companion).items()
        for pid in pids
    }
    weights = _walkers.final_weights(companion)
    # DEFERS to rule #6 on any hypothesis STANDING at `++`, the way
    # `_check_authz_contract_closure` defers to the disposition gate — and for the identical
    # reason. `_check_prediction_completeness` already refuses every uncited prediction on a
    # `++`, and offers no deferral because, as the docstring above says, "a `++` claims every
    # prediction came in, so there is nothing outstanding to defer". Reporting it here too
    # hands the author a repair (`:T conclude.deferred_preds`) that clears THIS rule and leaves
    # #6 refusing — a fix that does not fix the document, and one that then sits on disk as a
    # deferral contradicting the run's own `++`.
    #
    # TWO DIFFERENT READINGS, and the difference is a known gap rather than a design.
    # `weights` is `_walkers.final_weights`, last-move-wins by LEAD-DECLARATION order over the
    # raw `after` cell; the predicate counts `++` entries against exits per row and is
    # order-free. They agree on any document whose `:T resolutions` blocks follow their leads,
    # and disagree on one that does not — where this rule can call a hypothesis the document
    # refuted a "live" one, or skip as refuted one the document still carries. Fixing it wants
    # `final_weights` itself to fold in append order, which is eight readers wide; see the note
    # on `_walkers.final_weights`.
    confirmed = _confirmed_and_standing(companion)
    declared = [
        _Commitment(hid, pid)
        for hid, hyp in _walkers.all_hypotheses(companion).items()
        if weights.get(hid) != REFUTED_WEIGHT and hid not in confirmed
        for pid in sorted(_declared_prediction_ids(hyp))
    ]
    return [
        _closure_refusal(
            f"prediction {c.ref} on live hypothesis {c.owner}", "deferred_preds", c.ref,
            blank_rationale=blank,
            resolve=(
                f"cite {c.local_id} in a `:T resolutions` head that moves {c.owner}"
            ),
        )
        for c, blank in _unclosed_commitments(
            declared,
            resolved=resolved,
            deferrals=conclude.get("deferred_predictions") or [],
        )
    ]


def _check_loop_close(companion: CompanionBody) -> list[str]:
    closed = companion.get("closed_loops") or []
    if not closed:
        return []
    resolved_by_loop: dict[int, bool] = {}
    for f in companion.get("findings", []):
        loop = f.get("loop")
        if isinstance(loop, int):
            committed = bool(f.get("resolutions")) or bool(f.get("outcome"))
            resolved_by_loop[loop] = resolved_by_loop.get(loop, False) or committed
    errors: list[str] = []
    seen: set[int] = set()
    for n in closed:
        if n in seen:
            errors.append(f":T close blocked: loop {n} closed more than once")
        seen.add(n)
        if not resolved_by_loop.get(n, False):
            errors.append(
                f":T close blocked: loop {n} has no committed finding "
                f"— cannot close an empty/drafted loop"
            )
    return errors




def diagnose(
    proposed_text: str, current_text: str | None = None
) -> list[Diagnostic]:
    """The validator proper. Failures arrive as `Diagnostic`s so a caller that wants to point
    at the offending row can. `validate_companion` is the string surface over this and is what
    nearly everything calls."""
    proposed_text = _normalize_newlines(proposed_text)
    if current_text is not None:
        current_text = _normalize_newlines(current_text)

    found: list[Diagnostic] = []
    found.extend(_plain(_check_surface(proposed_text, current_text)))

    companion, warnings = parse_dense_companion(proposed_text)
    current_companion: CompanionBody | None = None
    if current_text is not None:
        current_companion, _ = parse_dense_companion(current_text)

    found.extend(_plain(
        _check_append_only(proposed_text, current_text, companion, current_companion)
    ))

    found.extend(_parse_diagnostic(w) for w in warnings)

    if not companion:
        return found

    found.extend(_plain(_check_lead_refs(companion)))
    found.extend(_plain(_check_attr_update_targets(companion)))
    found.extend(_plain(_check_hypothesis_refs(
        companion, deferred=deferred_hypothesis_ids(warnings),
    )))
    found.extend(_plain(_check_prediction_refs(companion)))
    found.extend(_plain(_check_fork_distinctness(companion)))
    found.extend(_plain(_check_refutation_scope(companion)))
    found.extend(_plain(_check_authz_contract_ids(companion)))
    found.extend(_plain(_check_tested_commitment_refs(companion)))
    found.extend(_plain(_check_tested_id_namespaces(companion)))
    found.extend(_plain(_check_strong_move_provenance(companion)))
    found.extend(_plain(_check_prediction_completeness(companion)))
    found.extend(_plain(_check_attribute_prediction_structure(companion)))
    found.extend(_plain(_check_prediction_id_namespace(companion)))
    found.extend(_plain(_check_lead_prediction_structure(companion)))
    found.extend(_plain(_check_impact_prediction_structure(companion)))
    found.extend(_plain(_check_impact_resolution_refs(companion)))
    found.extend(_check_closed_vocab(companion, proposed_text))
    found.extend(_plain(_check_screen_structure(companion)))
    # Bound, not recomputed: `_check_authz_contract_closure` defers to this gate's OUTPUT on
    # any contract it is already refusing, and running it twice per write is the single most
    # expensive thing in the pass.
    gated = _check_disposition_gating(companion)
    found.extend(_plain(gated))
    found.extend(_plain(_check_ceiling_test_scope(companion)))
    found.extend(_plain(_check_hypothesis_persistence(companion)))
    # The three closure gates, together and last: they are one sentence over three namespaces
    # (`_unclosed_commitments`), and each is only safe to run because its `deferred_*` table is
    # now projected.
    found.extend(_plain(_check_authz_contract_closure(companion, gated=set(gated))))
    found.extend(_plain(_check_impact_closure(companion)))
    found.extend(_plain(_check_prediction_closure(companion)))
    found.extend(_plain(_check_loop_close(companion)))
    return found


def warn_diagnostics(text: str) -> tuple[Diagnostic, ...]:
    """The REPAIR WINDOW, derived from a document's current bytes and stored nowhere.

    Not state anything records: it is `diagnose`'s warn-severity findings over whatever is on
    disk right now, so it cannot go stale, cannot disagree with the file, and survives a
    freshly constructed deps object. Each finding's `locus.row_text` is how `fix_row` addresses
    the row — the row as PARSED (the tokenizer strips it), which is also the text the warning
    prints, so the model's copy-paste round trip closes.

    No baseline: append-only is judged against history, but a warning is a property of the
    document as it stands."""
    return tuple(d for d in diagnose(text) if d.severity == "warning")


def validate_companion(
    proposed_text: str, current_text: str | None = None
) -> list[str]:
    """The string surface over `diagnose`, which is what the validator's callers are written
    against. `_artifact_schema` is the one caller that wants the structure and calls `diagnose`
    directly.

    ERROR severity only. Its production caller reads this list as "reasons to refuse the
    document" — persist dead-letters a run on any element — and a warn-family row is explicitly
    not that: the run reaches the learning loop with it."""
    return [
        d.message for d in diagnose(proposed_text, current_text) if d.severity != "warning"
    ]
